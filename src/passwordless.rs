//! Passwordless Authentication
//!
//! Provides magic link and WebAuthn passwordless authentication.
//!
//! # Features
//!
//! - Magic link generation and verification
//! - Email-based passwordless login
//! - WebAuthn registration and authentication
//! - Time-limited tokens
//!
//! # Usage
//!
//! Only a SHA-256 hash of a magic-link token is ever stored. The plaintext
//! exists once, in the [`IssuedMagicLink`] returned by
//! [`MagicLinkToken::generate`], to be put in the e-mailed URL. Redemption
//! goes through [`redeem_magic_link`], which consumes the record atomically
//! via [`MagicLinkStore::consume`], so a link can be used at most once even
//! under concurrent clicks.
//!
//! ```
//! use armature_auth::passwordless::*;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), PasswordlessError> {
//! let store = InMemoryMagicLinkStore::new();
//!
//! // Issue the link and store the (hashed) record.
//! let issued = MagicLinkToken::generate("user@example.com", std::time::Duration::from_secs(900))?;
//! store.save(&issued.record).await?;
//! let link = issued.to_url("https://myapp.com/auth/verify");
//!
//! // Send link via email...
//! # let presented = issued.secret().to_string();
//!
//! // In the callback: verify and consume in one step.
//! let record = redeem_magic_link(&store, &presented).await?;
//! assert_eq!(record.identifier, "user@example.com");
//!
//! // Replaying the same link fails.
//! assert!(redeem_magic_link(&store, &presented).await.is_err());
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

#[cfg(feature = "webauthn")]
use webauthn_rs::prelude::*;

/// Passwordless authentication errors
#[derive(Debug, Error)]
pub enum PasswordlessError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token already used")]
    TokenUsed,

    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(&'static str),

    #[error("Magic link storage error: {0}")]
    Storage(String),
}

/// A stored magic-link record.
///
/// Holds only [`token_hash`](Self::token_hash) (hex SHA-256 of the token),
/// never the token, so a leaked record table cannot be replayed. The tokens
/// are 256-bit random values, so an unkeyed hash is not brute-forceable.
#[derive(Clone, Serialize, Deserialize)]
pub struct MagicLinkToken {
    /// Hex SHA-256 of the token; the store's lookup key.
    pub token_hash: String,

    /// User identifier (email, user ID, etc.)
    pub identifier: String,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// Whether token has been used
    pub used: bool,
}

impl fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkToken")
            .field("token_hash", &"<redacted>")
            .field("identifier", &self.identifier)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("used", &self.used)
            .finish()
    }
}

/// A freshly issued magic link: the record to store plus the plaintext token,
/// which exists only here.
///
/// The token is redacted from `Debug` and this type is not `Serialize`.
#[derive(Clone)]
pub struct IssuedMagicLink {
    /// The record to persist (hash only).
    pub record: MagicLinkToken,
    token: String,
}

impl IssuedMagicLink {
    /// The plaintext token to embed in the link.
    pub fn secret(&self) -> &str {
        &self.token
    }

    /// Create the verification URL (`{base_url}?token={token}`).
    pub fn to_url(&self, base_url: &str) -> String {
        format!("{}?token={}", base_url, self.token)
    }
}

impl fmt::Debug for IssuedMagicLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedMagicLink")
            .field("record", &self.record)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl MagicLinkToken {
    /// Generate a new magic link token
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::passwordless::*;
    ///
    /// # fn example() -> Result<(), PasswordlessError> {
    /// let issued = MagicLinkToken::generate(
    ///     "user@example.com",
    ///     std::time::Duration::from_secs(3600) // 1 hour
    /// )?;
    ///
    /// // Store `issued.record`; e-mail `issued.to_url(..)`.
    /// assert_ne!(issued.record.token_hash, issued.secret());
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate(
        identifier: impl Into<String>,
        ttl: std::time::Duration,
    ) -> Result<IssuedMagicLink, PasswordlessError> {
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        let token = hex::encode(bytes);

        let now = Utc::now();
        let expires_at =
            now + Duration::from_std(ttl).map_err(|_| PasswordlessError::InvalidToken)?;

        Ok(IssuedMagicLink {
            record: Self {
                token_hash: Self::hash_token(&token),
                identifier: identifier.into(),
                created_at: now,
                expires_at,
                used: false,
            },
            token,
        })
    }

    /// The stored form of a token: hex SHA-256.
    pub fn hash_token(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    /// Check that this token is still redeemable — **not** that the caller
    /// presented it.
    ///
    /// Checks:
    /// - Not already used
    /// - Not expired
    ///
    /// This answers a question about the stored record only; it authorises
    /// nothing. Use [`redeem_magic_link`] (or [`Self::consume`]) to log in.
    pub fn is_usable(&self) -> Result<bool, PasswordlessError> {
        if self.used {
            return Err(PasswordlessError::TokenUsed);
        }

        if Utc::now() > self.expires_at {
            return Err(PasswordlessError::TokenExpired);
        }

        Ok(true)
    }

    /// Verify `candidate` against this record and mark it used, in one step.
    ///
    /// Compares the candidate's hash in constant time and enforces the
    /// single-use and expiry rules. On `Ok(())` the record is marked used;
    /// the caller must persist that before completing the login. When the
    /// record lives in shared storage, prefer [`redeem_magic_link`], whose
    /// [`MagicLinkStore::consume`] makes check-and-mark atomic across
    /// concurrent requests.
    pub fn consume(&mut self, candidate: &str) -> Result<(), PasswordlessError> {
        // Compare first and unconditionally, so a mismatched candidate is not
        // distinguishable from a used/expired one by which check ran.
        let matches = armature_core::crypto::constant_time_eq(
            Self::hash_token(candidate).as_bytes(),
            self.token_hash.as_bytes(),
        );

        if !matches {
            return Err(PasswordlessError::InvalidToken);
        }
        self.is_usable()?;
        self.used = true;
        Ok(())
    }
}

/// Storage for magic-link records.
#[async_trait]
pub trait MagicLinkStore: Send + Sync {
    /// Persist a newly issued record.
    async fn save(&self, record: &MagicLinkToken) -> Result<(), PasswordlessError>;

    /// **Atomically** claim the record with this `token_hash`: return it and
    /// make sure no later `consume` for the same hash returns it unused
    /// (delete it, or mark it used, in the same operation — e.g.
    /// `DELETE … RETURNING`, Redis `GETDEL`, or a compare-and-set on `used`).
    ///
    /// Returns `None` if no such record exists. Returning a record whose
    /// `used` flag is set (e.g. a marked-not-deleted design) is allowed; the
    /// caller rejects it.
    async fn consume(&self, token_hash: &str) -> Result<Option<MagicLinkToken>, PasswordlessError>;
}

/// In-process [`MagicLinkStore`]. Records are per-process; use a shared store
/// for multi-instance deployments.
#[derive(Default)]
pub struct InMemoryMagicLinkStore {
    records: DashMap<String, MagicLinkToken>,
}

impl InMemoryMagicLinkStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop expired records.
    pub fn prune_expired(&self) {
        let now = Utc::now();
        self.records.retain(|_, r| r.expires_at >= now);
    }
}

#[async_trait]
impl MagicLinkStore for InMemoryMagicLinkStore {
    async fn save(&self, record: &MagicLinkToken) -> Result<(), PasswordlessError> {
        self.records
            .insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    async fn consume(&self, token_hash: &str) -> Result<Option<MagicLinkToken>, PasswordlessError> {
        // `remove` is atomic per shard: exactly one concurrent caller gets it.
        Ok(self.records.remove(token_hash).map(|(_, record)| record))
    }
}

/// Redeem a presented magic-link token: look it up by hash, atomically
/// consume it, and check it is unused and unexpired.
///
/// Returns the consumed record (with `used == true`) on success. Every
/// failure — unknown token, already used, expired — consumes nothing further
/// and returns an error.
pub async fn redeem_magic_link(
    store: &dyn MagicLinkStore,
    presented: &str,
) -> Result<MagicLinkToken, PasswordlessError> {
    let hash = MagicLinkToken::hash_token(presented);
    let mut record = store
        .consume(&hash)
        .await?
        .ok_or(PasswordlessError::InvalidToken)?;
    record.consume(presented)?;
    Ok(record)
}

/// WebAuthn Configuration
#[cfg(feature = "webauthn")]
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying party ID (your domain)
    pub rp_id: String,

    /// Relying party name
    pub rp_name: String,

    /// Origin URL
    pub origin: Url,
}

#[cfg(feature = "webauthn")]
impl WebAuthnConfig {
    pub fn new(
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        origin: impl Into<String>,
    ) -> Result<Self, PasswordlessError> {
        Ok(Self {
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin: Url::parse(&origin.into())
                .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))?,
        })
    }
}

/// WebAuthn Manager
#[cfg(feature = "webauthn")]
pub struct WebAuthnManager {
    webauthn: Webauthn,
}

#[cfg(feature = "webauthn")]
impl WebAuthnManager {
    /// Create new WebAuthn manager
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_auth::passwordless::*;
    ///
    /// # #[cfg(feature = "webauthn")]
    /// # fn example() -> Result<(), PasswordlessError> {
    /// let config = WebAuthnConfig::new(
    ///     "example.com",
    ///     "Example App",
    ///     "https://example.com"
    /// )?;
    ///
    /// let manager = WebAuthnManager::new(config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: WebAuthnConfig) -> Result<Self, PasswordlessError> {
        let rp_origin = config.origin.clone();
        let builder = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))?;

        let builder = builder.rp_name(&config.rp_name);

        let webauthn = builder
            .build()
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))?;

        Ok(Self { webauthn })
    }

    /// Start registration (credential creation)
    ///
    /// Returns challenge that should be sent to client.
    pub fn start_registration(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PasswordlessError> {
        // webauthn-rs 0.5 uses a Uuid for the user handle.
        let user_unique_id = Uuid::from_slice(user_id)
            .map_err(|e| PasswordlessError::WebAuthn(format!("user_id must be 16 bytes: {e}")))?;

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_unique_id, username, display_name, None)
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))?;

        Ok((ccr, reg_state))
    }

    /// Finish registration
    ///
    /// Verifies client response and returns credential.
    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, PasswordlessError> {
        self.webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))
    }

    /// Start authentication
    ///
    /// Returns challenge that should be sent to client.
    pub fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), PasswordlessError> {
        self.webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))
    }

    /// Finish authentication
    ///
    /// Verifies client response.
    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, PasswordlessError> {
        self.webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|e| PasswordlessError::WebAuthn(e.to_string()))
    }
}

#[cfg(not(feature = "webauthn"))]
pub struct WebAuthnManager;

#[cfg(not(feature = "webauthn"))]
impl WebAuthnManager {
    pub fn new(_config: ()) -> Result<Self, PasswordlessError> {
        Err(PasswordlessError::FeatureNotEnabled("webauthn"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(ttl_secs: u64) -> IssuedMagicLink {
        MagicLinkToken::generate("user@example.com", std::time::Duration::from_secs(ttl_secs))
            .unwrap()
    }

    #[test]
    fn test_generate_magic_link() {
        let issued = issue(3600);
        assert_eq!(issued.secret().len(), 64);
        assert_eq!(issued.record.identifier, "user@example.com");
        assert!(!issued.record.used);
    }

    #[test]
    fn record_stores_only_a_hash() {
        let issued = issue(3600);
        let json = serde_json::to_string(&issued.record).unwrap();
        assert!(!json.contains(issued.secret()), "{json}");
        assert_eq!(
            issued.record.token_hash,
            MagicLinkToken::hash_token(issued.secret())
        );
        let debug = format!("{issued:?}");
        assert!(!debug.contains(issued.secret()), "{debug}");
        assert!(!debug.contains(&issued.record.token_hash), "{debug}");
    }

    #[test]
    fn consume_requires_the_presented_secret() {
        let issued = issue(3600);
        let mut record = issued.record.clone();
        assert!(matches!(
            record.consume("not-the-token"),
            Err(PasswordlessError::InvalidToken)
        ));
        // The stored hash itself is not a valid token.
        let hash = record.token_hash.clone();
        assert!(matches!(
            record.consume(&hash),
            Err(PasswordlessError::InvalidToken)
        ));
        assert!(!record.used);
        record.consume(issued.secret()).unwrap();
        assert!(record.used);
        assert!(matches!(
            record.consume(issued.secret()),
            Err(PasswordlessError::TokenUsed)
        ));
    }

    #[test]
    fn consume_rejects_expired() {
        let issued = issue(0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut record = issued.record.clone();
        assert!(matches!(
            record.consume(issued.secret()),
            Err(PasswordlessError::TokenExpired)
        ));
    }

    #[tokio::test]
    async fn redeem_is_single_use() {
        let store = InMemoryMagicLinkStore::new();
        let issued = issue(3600);
        store.save(&issued.record).await.unwrap();

        let record = redeem_magic_link(&store, issued.secret()).await.unwrap();
        assert!(record.used);
        assert!(matches!(
            redeem_magic_link(&store, issued.secret()).await,
            Err(PasswordlessError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn concurrent_redeem_succeeds_exactly_once() {
        let store = std::sync::Arc::new(InMemoryMagicLinkStore::new());
        let issued = issue(3600);
        store.save(&issued.record).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let token = issued.secret().to_string();
            handles.push(tokio::spawn(async move {
                redeem_magic_link(store.as_ref(), &token).await.is_ok()
            }));
        }
        let mut successes = 0;
        for h in handles {
            if h.await.unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
    }

    #[tokio::test]
    async fn redeem_rejects_expired() {
        let store = InMemoryMagicLinkStore::new();
        let issued = issue(0);
        store.save(&issued.record).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(matches!(
            redeem_magic_link(&store, issued.secret()).await,
            Err(PasswordlessError::TokenExpired)
        ));
    }

    #[test]
    fn test_magic_link_url() {
        let issued = issue(3600);
        let url = issued.to_url("https://example.com/auth/verify");
        assert_eq!(
            url,
            format!("https://example.com/auth/verify?token={}", issued.secret())
        );
    }

    #[test]
    fn test_is_usable() {
        let issued = issue(3600);
        assert!(issued.record.is_usable().is_ok());
        let mut used = issued.record.clone();
        used.used = true;
        assert!(matches!(
            used.is_usable(),
            Err(PasswordlessError::TokenUsed)
        ));
    }
}
