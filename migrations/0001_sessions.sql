CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    base_domain TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    refresh_token_nonce BLOB,
    refresh_token_ciphertext BLOB,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    user_agent TEXT
);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
