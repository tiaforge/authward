//! Key derivation and refresh-token-at-rest encryption.
//!
//! The two secrets in `[global]` (cookie-signing key, refresh-token
//! encryption key) are operator-supplied strings of arbitrary length —
//! typically 32 random bytes hex-encoded by `authward init`, but not
//! guaranteed to be. Both are run through a KDF before use as raw key
//! material, rather than assuming a particular length/encoding.

use chacha20poly1305::aead::{Aead, Generate, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngExt;

/// Generates `n` cryptographically random bytes, hex-encoded.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rng().fill(bytes.as_mut_slice());
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Derives a 32-byte symmetric key from arbitrary-length secret material.
/// Not a password-stretching KDF (no reason to be — our inputs are already
/// high-entropy random secrets, not human-memorized passwords).
pub fn derive_key(secret: &str) -> [u8; 32] {
    *blake3::hash(secret.as_bytes()).as_bytes()
}

/// Encrypts/decrypts refresh tokens for storage in SQLite, keyed by
/// `refresh_token_encryption_key` — a key deliberately separate from the
/// cookie-signing key, for defense-in-depth (see the plan's locked-in
/// session model decision).
pub struct RefreshTokenCipher {
    cipher: XChaCha20Poly1305,
}

impl RefreshTokenCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(&Key::from(*key)),
        }
    }

    /// Returns `(nonce, ciphertext)` to store as separate columns.
    pub fn encrypt(&self, plaintext: &str) -> (Vec<u8>, Vec<u8>) {
        let nonce = XNonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("XChaCha20Poly1305 encryption of a well-formed plaintext cannot fail");
        (nonce.to_vec(), ciphertext)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<String> {
        let nonce = XNonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("stored refresh-token nonce has the wrong length"))?;
        let plaintext = self.cipher.decrypt(&nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("refresh token decryption failed (wrong key or corrupted row)")
        })?;
        Ok(String::from_utf8(plaintext)?)
    }
}
