//! Session validity checking and silent refresh (Phase 2).
//!
//! Group-claim re-validation against freshly refreshed claims (mentioned
//! in the plan's refinement pass) lands in Phase 4, once per-host
//! authorization config exists to check against — this module only
//! refreshes and re-validates the token itself.

use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::{Nonce, OAuth2TokenResponse, RefreshToken, TokenResponse};

use crate::db::{self, Session};
use crate::state::AppState;

// Boxing `Session` would trade a small amount of enum size for a heap
// allocation on every successful verification — the overwhelmingly common
// case for a running deployment — which isn't the right tradeoff here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VerifyOutcome {
    /// Authenticated (and, if it had expired, freshly refreshed). Carries
    /// the session so callers can run the per-host group-membership check
    /// (Phase 4) against its `claims_json` without a second DB read.
    Valid(Session),
    Invalid,
}

/// Checks whether `session_id` names a currently-valid session *for
/// `expected_base_domain`*, silently refreshing it first if its access/ID
/// token has expired but its refresh token might still work. Never
/// surfaces refresh failure as anything other than `Invalid` — per the
/// plan's locked-in decision, a failed refresh just clears the session,
/// no error shown to the user.
///
/// The base-domain check matters once more than one base domain is
/// configured (Phase 3): the session cookie's `Domain` attribute keeps a
/// real browser from ever presenting a `.example.com` session to a
/// `.other.com` app, but nothing stops a forged `Cookie` header from
/// trying exactly that, so it's re-checked server-side rather than
/// trusted implicitly.
pub async fn verify_session(
    state: &AppState,
    session_id: &str,
    expected_base_domain: &str,
) -> VerifyOutcome {
    let session = match db::get_session(&state.db, session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return VerifyOutcome::Invalid,
        Err(err) => {
            tracing::error!(%err, "session lookup failed");
            return VerifyOutcome::Invalid;
        }
    };
    if session.base_domain != expected_base_domain {
        tracing::warn!(session_id, session_base_domain = %session.base_domain, expected_base_domain, "session presented against the wrong base domain");
        return VerifyOutcome::Invalid;
    }

    if !session.is_expired() {
        return VerifyOutcome::Valid(session);
    }

    // Expired: refresh under this session's lock. Concurrent requests for
    // the same session serialize here, so exactly one of them talks to
    // the IdP — important with strict IdPs that invalidate the old
    // refresh token the moment a new one is issued.
    state
        .session_locks
        .with_lock(session_id, || async move {
            // Re-check: a concurrent waiter (or the reaper) may have
            // already refreshed or deleted this row while we waited.
            let session = match db::get_session(&state.db, session_id).await {
                Ok(Some(session)) => session,
                Ok(None) => return VerifyOutcome::Invalid,
                Err(err) => {
                    tracing::error!(%err, "session lookup failed");
                    return VerifyOutcome::Invalid;
                }
            };
            if session.base_domain != expected_base_domain {
                return VerifyOutcome::Invalid;
            }
            if !session.is_expired() {
                return VerifyOutcome::Valid(session);
            }
            refresh(state, session).await
        })
        .await
}

async fn refresh(state: &AppState, mut session: Session) -> VerifyOutcome {
    let Some(oidc_client) = state.oidc_clients.get(&session.base_domain) else {
        tracing::warn!(session_id = %session.id, base_domain = %session.base_domain, "no OIDC client for session's base domain; clearing session");
        clear(state, &session.id).await;
        return VerifyOutcome::Invalid;
    };

    let refresh_token = match session.decrypt_refresh_token(&state.refresh_cipher) {
        Ok(Some(token)) => token,
        Ok(None) => {
            // No refresh token was ever issued for this session — nothing
            // to silently refresh with, so the session simply ends here.
            clear(state, &session.id).await;
            return VerifyOutcome::Invalid;
        }
        Err(err) => {
            tracing::error!(session_id = %session.id, %err, "failed to decrypt stored refresh token");
            clear(state, &session.id).await;
            return VerifyOutcome::Invalid;
        }
    };

    let refresh_token_value = RefreshToken::new(refresh_token.clone());
    let token_request = match oidc_client.exchange_refresh_token(&refresh_token_value) {
        Ok(req) => req,
        Err(err) => {
            tracing::error!(session_id = %session.id, %err, "failed to build refresh request");
            clear(state, &session.id).await;
            return VerifyOutcome::Invalid;
        }
    };

    let token_response = match token_request.request_async(&state.http_client).await {
        Ok(response) => response,
        Err(err) => {
            // Covers both "IdP unreachable" and "IdP rejected the refresh
            // token" (revoked, rotated out from under us, expired) — both
            // end the session the same way, silently.
            tracing::info!(session_id = %session.id, %err, "refresh failed; clearing session");
            clear(state, &session.id).await;
            return VerifyOutcome::Invalid;
        }
    };

    // A fresh ID token is still subject to the same checks as at login
    // (signature, issuer, audience, expiry/clock-skew). Not every provider
    // returns one on refresh; when present, a failure here means treating
    // the whole refresh as untrustworthy rather than keeping stale claims.
    // When one *is* present and valid, its claims replace the session's
    // stored snapshot — this is what lets a group-membership change at
    // the IdP take effect on next refresh rather than only at next login
    // (the plan's group-recheck-on-refresh design).
    let mut fresh_claims_json = None;
    if let Some(id_token) = token_response.id_token() {
        let verifier = oidc_client
            .id_token_verifier()
            .set_time_fn(|| {
                Utc::now() - ChronoDuration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS)
            })
            .set_issue_time_verifier_fn(|iat| {
                if iat > Utc::now() + ChronoDuration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS) {
                    Err(
                        "id_token issued too far in the future (clock skew beyond allowed leeway)"
                            .to_string(),
                    )
                } else {
                    Ok(())
                }
            });
        // Refresh responses aren't bound to a login-time nonce.
        if let Err(err) = id_token.claims(&verifier, |_: Option<&Nonce>| Ok(())) {
            tracing::warn!(session_id = %session.id, ?err, "refreshed id_token failed verification; clearing session");
            clear(state, &session.id).await;
            return VerifyOutcome::Invalid;
        }
        match crate::oidc::decode_claims_json(&id_token.to_string()) {
            Ok(json) => fresh_claims_json = Some(json),
            Err(err) => {
                tracing::warn!(session_id = %session.id, %err, "failed to decode refreshed id_token claims; keeping stale claims")
            }
        }
    }

    // Providers vary on whether they rotate the refresh token; keep the
    // one we just used if a new one wasn't issued.
    let new_refresh_token = token_response
        .refresh_token()
        .map(|t| t.secret().clone())
        .unwrap_or(refresh_token);
    let encrypted = state.refresh_cipher.encrypt(&new_refresh_token);

    let ttl = token_response
        .expires_in()
        .unwrap_or(state.config.global.session_ttl_fallback);
    let expires_at = Utc::now()
        + ChronoDuration::from_std(ttl).unwrap_or_else(|_| {
            ChronoDuration::seconds(state.config.global.session_ttl_fallback.as_secs() as i64)
        });

    if let Err(err) = db::update_session_after_refresh(
        &state.db,
        &session.id,
        Some(encrypted),
        expires_at,
        fresh_claims_json.as_ref(),
    )
    .await
    {
        tracing::error!(session_id = %session.id, %err, "failed to persist refreshed session");
        return VerifyOutcome::Invalid;
    }

    tracing::debug!(session_id = %session.id, "session silently refreshed");
    session.expires_at = expires_at;
    if let Some(claims_json) = fresh_claims_json {
        session.claims_json = claims_json;
    }
    VerifyOutcome::Valid(session)
}

async fn clear(state: &AppState, session_id: &str) {
    if let Err(err) = db::delete_session(&state.db, session_id).await {
        tracing::error!(%session_id, %err, "failed to delete session");
    }
}

/// One sweep of the expired-session reaper (Phase 2): for every session
/// whose access/ID token expired before `now`, re-checks it under its
/// per-session lock (so it can't race an in-flight refresh — a
/// concurrent refresh either finishes first, in which case the re-check
/// here sees the pushed-forward expiry and skips it, or starts after,
/// in which case it waits for the reaper to finish with that row first)
/// and deletes it if it's genuinely still expired.
pub async fn reap_expired_sessions(state: &AppState) {
    let now = Utc::now();
    let candidates = match db::list_expired_session_ids(&state.db, now).await {
        Ok(ids) => ids,
        Err(err) => {
            tracing::error!(%err, "reaper: failed to list expired sessions");
            return;
        }
    };

    let mut reaped = 0usize;
    for id in candidates {
        let did_reap = state
            .session_locks
            .with_lock(&id, || async {
                match db::get_session(&state.db, &id).await {
                    Ok(Some(session)) if session.is_expired() => {
                        clear(state, &id).await;
                        true
                    }
                    Ok(_) => false, // gone, or refreshed out from under us
                    Err(err) => {
                        tracing::error!(session_id = %id, %err, "reaper: session lookup failed");
                        false
                    }
                }
            })
            .await;
        if did_reap {
            reaped += 1;
        }
    }

    if reaped > 0 {
        tracing::info!(reaped, "reaper: swept expired sessions");
    }
}

/// Spawns the background reaper loop. Returns the task handle so callers
/// can hold/abort it if needed; dropping the handle does not stop the task.
pub fn spawn_reaper(state: AppState, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so we don't sweep on startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            reap_expired_sessions(&state).await;
        }
    })
}
