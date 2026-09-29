//! SQLite-backed session store. Single instance, no HA requirement (see
//! the plan's locked-in persistence decision).

use std::path::Path;

use chrono::{DateTime, Utc};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{AssertSqlSafe, Row, SqlSafeStr, SqlitePool};

use crate::crypto::RefreshTokenCipher;

/// Migrations are embedded at compile time (`include_str!`) rather than
/// resolved from a `./migrations` directory at runtime, so the compiled
/// binary doesn't depend on that directory existing next to it wherever
/// it's deployed.
fn migrator() -> Migrator {
    Migrator::with_migrations(vec![
        migration(
            1,
            "sessions",
            include_str!("../migrations/0001_sessions.sql"),
        ),
        migration(
            2,
            "session_claims",
            include_str!("../migrations/0002_session_claims.sql"),
        ),
        migration(
            3,
            "session_provider",
            include_str!("../migrations/0003_session_provider.sql"),
        ),
    ])
}

/// sqlx records a checksum of each migration's exact SQL text and refuses
/// to start ("migration N was previously applied but has been modified")
/// if it differs later. A checkout with `core.autocrlf` turns these files'
/// line endings into CRLF, so the same migration built on another machine
/// would checksum differently; normalizing to LF first keeps the checksum
/// a property of the SQL, not of the checkout. `.gitattributes` pins the
/// files to LF as well.
fn migration(version: i64, description: &'static str, sql: &'static str) -> Migration {
    Migration::new(
        version,
        description.into(),
        MigrationType::ReversibleUp,
        AssertSqlSafe(sql.replace("\r\n", "\n")).into_sql_str(),
        false,
    )
}

pub async fn connect(path: &Path) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new().connect_with(options).await?;
    migrator().run(&pool).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    Ok(pool)
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub base_domain: String,
    /// The provider that authenticated this session (see
    /// `config::ResolvedHost::provider_key`); a host using a different
    /// provider must not accept it.
    pub provider_key: String,
    pub subject: String,
    pub email: Option<String>,
    pub refresh_token: Option<(Vec<u8>, Vec<u8>)>, // (nonce, ciphertext)
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    /// Raw ID token claims as of the last login or refresh — the source
    /// for the per-host group-membership check (Phase 4), since the
    /// configurable `group_claim_name` isn't known at compile time.
    pub claims_json: serde_json::Value,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Past the absolute lifetime cap (`session_max_age`), which no number
    /// of successful refreshes extends.
    pub fn is_past_max_age(&self, max_age: std::time::Duration) -> bool {
        let max_age = chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::MAX);
        Utc::now() >= self.created_at + max_age
    }

    /// Decrypts the stored refresh token, if this session has one.
    pub fn decrypt_refresh_token(
        &self,
        cipher: &RefreshTokenCipher,
    ) -> anyhow::Result<Option<String>> {
        match &self.refresh_token {
            Some((nonce, ciphertext)) => Ok(Some(cipher.decrypt(nonce, ciphertext)?)),
            None => Ok(None),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &SqlitePool,
    id: &str,
    base_domain: &str,
    provider_key: &str,
    subject: &str,
    email: Option<&str>,
    refresh_token: Option<(Vec<u8>, Vec<u8>)>,
    expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
    claims_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let (nonce, ciphertext) = match refresh_token {
        Some((n, c)) => (Some(n), Some(c)),
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO sessions \
         (id, base_domain, provider_key, subject, email, refresh_token_nonce, \
          refresh_token_ciphertext, expires_at, created_at, user_agent, claims_json) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(base_domain)
    .bind(provider_key)
    .bind(subject)
    .bind(email)
    .bind(nonce)
    .bind(ciphertext)
    .bind(expires_at.timestamp())
    .bind(Utc::now().timestamp())
    .bind(user_agent)
    .bind(claims_json.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

const SESSION_COLUMNS: &str = "id, base_domain, provider_key, subject, email, refresh_token_nonce, \
     refresh_token_ciphertext, expires_at, created_at, user_agent, claims_json";

fn session_from_row(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<Session> {
    let nonce: Option<Vec<u8>> = row.try_get("refresh_token_nonce")?;
    let ciphertext: Option<Vec<u8>> = row.try_get("refresh_token_ciphertext")?;
    let refresh_token = match (nonce, ciphertext) {
        (Some(n), Some(c)) => Some((n, c)),
        _ => None,
    };
    let claims_json: String = row.try_get("claims_json")?;
    let base_domain: String = row.try_get("base_domain")?;
    // Rows from before migration 3 have no provider recorded; they could
    // only have come from the base domain's default provider.
    let provider_key: String = row.try_get("provider_key")?;
    let provider_key = if provider_key.is_empty() {
        base_domain.clone()
    } else {
        provider_key
    };

    Ok(Session {
        id: row.try_get("id")?,
        base_domain,
        provider_key,
        subject: row.try_get("subject")?,
        email: row.try_get("email")?,
        refresh_token,
        expires_at: DateTime::from_timestamp(row.try_get::<i64, _>("expires_at")?, 0)
            .unwrap_or_default(),
        created_at: DateTime::from_timestamp(row.try_get::<i64, _>("created_at")?, 0)
            .unwrap_or_default(),
        user_agent: row.try_get("user_agent")?,
        claims_json: serde_json::from_str(&claims_json).unwrap_or(serde_json::Value::Null),
    })
}

pub async fn get_session(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<Session>> {
    // Safe: the only dynamic part is the compile-time-constant column
    // list, never user input.
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(session_from_row).transpose()
}

/// Every session belonging to `subject` at `provider_key` on
/// `base_domain`, newest first — the overview page's device list (Phase
/// 6). Deliberately scoped to one base domain *and* one provider: the
/// same subject string at a different provider is a different person as
/// far as anyone can tell, and must never see or revoke these.
pub async fn list_sessions_for_subject(
    pool: &SqlitePool,
    base_domain: &str,
    provider_key: &str,
    subject: &str,
) -> anyhow::Result<Vec<Session>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SESSION_COLUMNS} FROM sessions \
         WHERE base_domain = ? AND (provider_key = ? OR (provider_key = '' AND ? = base_domain)) \
           AND subject = ? \
         ORDER BY created_at DESC"
    )))
    .bind(base_domain)
    .bind(provider_key)
    .bind(provider_key)
    .bind(subject)
    .fetch_all(pool)
    .await?;

    rows.iter().map(session_from_row).collect()
}

pub async fn delete_session(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Updates a session's refresh token, expiry, and (when the IdP returned a
/// fresh ID token on refresh) claims, after a successful silent refresh
/// (Phase 2). `refresh_token` is `None` when the IdP didn't rotate it and
/// the caller chose to keep serving requests without persisting a new
/// value (callers should generally pass the existing token back through
/// here rather than omit it, so this stays a simple overwrite).
/// `claims_json` is `None` when the refresh response carried no ID token
/// (not every provider returns one on refresh) — the stored claims are
/// left as-is rather than wiped, per the plan's group-recheck-on-refresh
/// design: best-effort freshness, not a hard requirement per refresh.
pub async fn update_session_after_refresh(
    pool: &SqlitePool,
    id: &str,
    refresh_token: Option<(Vec<u8>, Vec<u8>)>,
    expires_at: DateTime<Utc>,
    claims_json: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let (nonce, ciphertext) = match refresh_token {
        Some((n, c)) => (Some(n), Some(c)),
        None => (None, None),
    };
    sqlx::query(
        "UPDATE sessions \
         SET refresh_token_nonce = ?, refresh_token_ciphertext = ?, expires_at = ?, \
             claims_json = COALESCE(?, claims_json) \
         WHERE id = ?",
    )
    .bind(nonce)
    .bind(ciphertext)
    .bind(expires_at.timestamp())
    .bind(claims_json.map(|v| v.to_string()))
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Session IDs that can never become valid again: created before
/// `max_age_cutoff`, or with an access/ID token expired as of `now` *and*
/// no refresh token to renew it with — candidates for the reaper (Phase
/// 2). An expired session that still holds a refresh token is left alone:
/// the next request for it triggers a silent refresh, and only the IdP
/// can say whether that refresh token is still good. Deleting such rows
/// here would end every session after one access-token lifetime of
/// inactivity, well short of the documented `session_max_age`.
///
/// The reaper still has to re-check each candidate under its per-session
/// lock before deleting, since one may be mid-refresh (see
/// `locks::SessionLocks`). That re-check is also what makes the
/// comparisons here safely inclusive: timestamps are stored as whole
/// seconds, so a strict `<` could miss a row for up to a second after
/// `Session::is_expired` / `is_past_max_age` already say it's dead.
pub async fn list_expired_session_ids(
    pool: &SqlitePool,
    now: DateTime<Utc>,
    max_age_cutoff: DateTime<Utc>,
) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT id FROM sessions \
         WHERE (expires_at <= ? AND refresh_token_ciphertext IS NULL) OR created_at <= ?",
    )
    .bind(now.timestamp())
    .bind(max_age_cutoff.timestamp())
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| row.try_get::<String, _>("id").map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_checksum_ignores_line_endings() {
        let lf = migration(1, "t", "CREATE TABLE t (a);\nSELECT 1;\n");
        let crlf = migration(1, "t", "CREATE TABLE t (a);\r\nSELECT 1;\r\n");
        assert_eq!(lf.checksum, crlf.checksum);
    }
}
