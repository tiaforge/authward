//! SQLite-backed session store. Single instance, no HA requirement (see
//! the plan's locked-in persistence decision).

use std::path::Path;

use chrono::{DateTime, Utc};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlSafeStr, SqlitePool};

use crate::crypto::RefreshTokenCipher;

/// Migrations are embedded at compile time (`include_str!`) rather than
/// resolved from a `./migrations` directory at runtime, so the compiled
/// binary doesn't depend on that directory existing next to it wherever
/// it's deployed.
fn migrator() -> Migrator {
    let migrations = vec![
        Migration::new(
            1,
            "sessions".into(),
            MigrationType::ReversibleUp,
            include_str!("../migrations/0001_sessions.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            2,
            "session_claims".into(),
            MigrationType::ReversibleUp,
            include_str!("../migrations/0002_session_claims.sql").into_sql_str(),
            false,
        ),
    ];
    Migrator::with_migrations(migrations)
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
         (id, base_domain, subject, email, refresh_token_nonce, refresh_token_ciphertext, \
          expires_at, created_at, user_agent, claims_json) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(base_domain)
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

pub async fn get_session(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<Session>> {
    let row = sqlx::query(
        "SELECT id, base_domain, subject, email, refresh_token_nonce, refresh_token_ciphertext, \
                expires_at, created_at, user_agent, claims_json \
         FROM sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let nonce: Option<Vec<u8>> = row.try_get("refresh_token_nonce")?;
    let ciphertext: Option<Vec<u8>> = row.try_get("refresh_token_ciphertext")?;
    let refresh_token = match (nonce, ciphertext) {
        (Some(n), Some(c)) => Some((n, c)),
        _ => None,
    };
    let claims_json: String = row.try_get("claims_json")?;

    Ok(Some(Session {
        id: row.try_get("id")?,
        base_domain: row.try_get("base_domain")?,
        subject: row.try_get("subject")?,
        email: row.try_get("email")?,
        refresh_token,
        expires_at: DateTime::from_timestamp(row.try_get::<i64, _>("expires_at")?, 0)
            .unwrap_or_default(),
        created_at: DateTime::from_timestamp(row.try_get::<i64, _>("created_at")?, 0)
            .unwrap_or_default(),
        user_agent: row.try_get("user_agent")?,
        claims_json: serde_json::from_str(&claims_json).unwrap_or(serde_json::Value::Null),
    }))
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

/// Session IDs whose access/ID token portion has already expired, as of
/// `now` — candidates for the reaper (Phase 2). The reaper still has to
/// re-check each one under its per-session lock before deleting, since a
/// candidate may be mid-refresh (see `locks::SessionLocks`).
pub async fn list_expired_session_ids(
    pool: &SqlitePool,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query("SELECT id FROM sessions WHERE expires_at < ?")
        .bind(now.timestamp())
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|row| row.try_get::<String, _>("id").map_err(Into::into))
        .collect()
}
