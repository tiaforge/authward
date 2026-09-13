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
    let sql = include_str!("../migrations/0001_sessions.sql");
    let migration = Migration::new(
        1,
        "sessions".into(),
        MigrationType::ReversibleUp,
        sql.into_sql_str(),
        false,
    );
    Migrator::with_migrations(vec![migration])
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

pub struct Session {
    pub id: String,
    pub base_domain: String,
    pub subject: String,
    pub email: Option<String>,
    pub refresh_token: Option<(Vec<u8>, Vec<u8>)>, // (nonce, ciphertext)
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_agent: Option<String>,
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
) -> anyhow::Result<()> {
    let (nonce, ciphertext) = match refresh_token {
        Some((n, c)) => (Some(n), Some(c)),
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO sessions \
         (id, base_domain, subject, email, refresh_token_nonce, refresh_token_ciphertext, \
          expires_at, created_at, user_agent) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_session(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<Session>> {
    let row = sqlx::query(
        "SELECT id, base_domain, subject, email, refresh_token_nonce, refresh_token_ciphertext, \
                expires_at, created_at, user_agent \
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
    }))
}

pub async fn delete_session(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
