//! API Key Management
//!
//! Provides API key generation, validation, and rotation with database injection.
//!
//! # Features
//!
//! - API key generation with secure random (256-bit)
//! - Keys are never stored: the store only ever sees
//!   `HMAC-SHA256(pepper, key)` ([`ApiKey::key_hash`]). The plaintext is
//!   returned exactly once, in the [`GeneratedApiKey`] from
//!   [`ApiKeyManager::generate`], for you to hand to the client.
//! - Key validation and verification
//! - Key rotation and expiration
//! - Rate limiting per key
//! - Scopes/permissions per key
//! - Database-agnostic with DI
//!
//! # Usage
//!
//! ```no_run
//! use armature_auth::api_key::*;
//! use chrono::{DateTime, Utc};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Implement your database storage
//! struct MyApiKeyStore;
//!
//! #[async_trait::async_trait]
//! impl ApiKeyStore for MyApiKeyStore {
//!     async fn save(&self, key: &ApiKey) -> Result<(), ApiKeyError> { Ok(()) }
//!     async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, ApiKeyError> { Ok(None) }
//!     async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, ApiKeyError> { Ok(None) }
//!     async fn list_by_user(&self, user_id: &str) -> Result<Vec<ApiKey>, ApiKeyError> { Ok(vec![]) }
//!     async fn revoke(&self, key_id: &str) -> Result<(), ApiKeyError> { Ok(()) }
//!     async fn update_last_used(&self, key_id: &str, timestamp: DateTime<Utc>) -> Result<(), ApiKeyError> { Ok(()) }
//! }
//!
//! // Inject store via DI container. The pepper is a server-side secret
//! // (>= 32 bytes) kept outside the database, e.g. in a secret manager.
//! let store: Arc<dyn ApiKeyStore> = Arc::new(MyApiKeyStore);
//! let pepper = std::env::var("API_KEY_PEPPER")?;
//! let manager = ApiKeyManager::new(store, pepper.into_bytes())?;
//!
//! // Generate API key: the plaintext is available only here.
//! let generated = manager.generate("user_123", vec!["read".to_string(), "write".to_string()]).await?;
//! let plaintext = generated.secret().to_string(); // show to the user once
//!
//! // Validate API key
//! if let Some(key) = manager.validate(&plaintext).await? {
//!     println!("Valid key for user: {}", key.user_id);
//! }
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// API Key errors
#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("Invalid API key")]
    Invalid,

    #[error("API key expired")]
    Expired,

    #[error("API key revoked")]
    Revoked,

    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("API key configuration error: {0}")]
    Configuration(String),
}

/// Minimum length of the [`ApiKeyManager`] pepper.
pub const MIN_PEPPER_LEN: usize = 32;

/// Below this many tracked keys the counter map is small enough that expired
/// windows are not worth sweeping; above it, a sweep runs at most once per
/// rate-limit window (see [`ApiKeyManager::check_rate_limit`]).
const RATE_COUNTER_SWEEP_THRESHOLD: usize = 1024;

/// A stored API key record.
///
/// Holds no secret: the key itself is represented only by
/// [`key_hash`](Self::key_hash), a keyed hash that cannot be reversed or
/// brute-forced without the manager's pepper. This is what an
/// [`ApiKeyStore`] persists.
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique key ID
    pub id: String,

    /// Hex `HMAC-SHA256(pepper, key)` of the plaintext key; the store's
    /// lookup index. See [`ApiKeyManager::hash_key`].
    pub key_hash: String,

    /// User/account ID this key belongs to
    pub user_id: String,

    /// Key name/description
    pub name: Option<String>,

    /// Scopes/permissions
    pub scopes: Vec<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,

    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,

    /// Whether key is revoked
    pub revoked: bool,

    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("key_hash", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .field("revoked", &self.revoked)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

/// A freshly generated API key: the stored [`ApiKey`] record plus the
/// plaintext key, which exists only in this value.
///
/// Return [`secret`](Self::secret) to the client once; it cannot be recovered
/// later. The plaintext is redacted from `Debug` and the type is not
/// `Serialize`, so it cannot leak into logs or be persisted by accident.
#[derive(Clone)]
pub struct GeneratedApiKey {
    /// The stored record (no secret material).
    pub api_key: ApiKey,
    plaintext: String,
}

impl GeneratedApiKey {
    /// The plaintext API key, to hand to the client exactly once.
    pub fn secret(&self) -> &str {
        &self.plaintext
    }

    /// Consume this value, returning the plaintext key.
    pub fn into_secret(self) -> String {
        self.plaintext
    }
}

impl fmt::Debug for GeneratedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedApiKey")
            .field("api_key", &self.api_key)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl std::ops::Deref for GeneratedApiKey {
    type Target = ApiKey;

    fn deref(&self) -> &ApiKey {
        &self.api_key
    }
}

/// API Key storage trait (implement with your database)
///
/// Users must provide their own implementation using their database of choice.
/// The store never receives a plaintext key — only [`ApiKey::key_hash`].
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Save or update an API key
    async fn save(&self, key: &ApiKey) -> Result<(), ApiKeyError>;

    /// Find an API key by its [`ApiKey::key_hash`] (an exact, indexed match).
    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, ApiKeyError>;

    /// Find API key by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, ApiKeyError>;

    /// List all keys for a user
    async fn list_by_user(&self, user_id: &str) -> Result<Vec<ApiKey>, ApiKeyError>;

    /// Revoke an API key
    async fn revoke(&self, key_id: &str) -> Result<(), ApiKeyError>;

    /// Update last used timestamp
    async fn update_last_used(
        &self,
        key_id: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<(), ApiKeyError>;
}

/// API Key Manager
///
/// Manages API key lifecycle with injected storage.
pub struct ApiKeyManager {
    store: Arc<dyn ApiKeyStore>,
    /// Server-side secret keying the stored key hashes.
    pepper: Vec<u8>,
    key_prefix: String,
    default_expiration: Option<Duration>,
    /// Rolling window used to enforce each key's `rate_limit` (requests per
    /// window). Defaults to one minute, matching the "requests per minute"
    /// documented on [`ApiKey::rate_limit`].
    rate_limit_window: Duration,
    /// Per-key request counters: `(window_start, count_in_window)`.
    ///
    /// Sharded rather than a single `Mutex<HashMap<..>>`: every validated
    /// request with a rate limit touches this map, and one process-wide lock
    /// covering *all* keys made unrelated keys contend with each other — the
    /// map became a serialization point on the request path for the whole
    /// application.
    rate_counters: DashMap<String, (DateTime<Utc>, u32)>,
    /// Unix seconds at which expired windows were last swept, so the O(n) sweep
    /// runs at most once per window instead of on the request that happens to
    /// miss the map.
    last_sweep_unix: AtomicI64,
}

impl ApiKeyManager {
    /// Create new API key manager with injected store
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_auth::api_key::*;
    /// use chrono::{DateTime, Utc};
    /// use std::sync::Arc;
    ///
    /// # struct MyStore;
    /// # #[async_trait::async_trait]
    /// # impl ApiKeyStore for MyStore {
    /// #     async fn save(&self, key: &ApiKey) -> Result<(), ApiKeyError> { Ok(()) }
    /// #     async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, ApiKeyError> { Ok(None) }
    /// #     async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, ApiKeyError> { Ok(None) }
    /// #     async fn list_by_user(&self, user_id: &str) -> Result<Vec<ApiKey>, ApiKeyError> { Ok(vec![]) }
    /// #     async fn revoke(&self, key_id: &str) -> Result<(), ApiKeyError> { Ok(()) }
    /// #     async fn update_last_used(&self, key_id: &str, timestamp: DateTime<Utc>) -> Result<(), ApiKeyError> { Ok(()) }
    /// # }
    /// let store: Arc<dyn ApiKeyStore> = Arc::new(MyStore);
    /// let pepper = std::env::var("API_KEY_PEPPER").unwrap().into_bytes();
    /// let manager = ApiKeyManager::new(store, pepper).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// [`ApiKeyError::Configuration`] if `pepper` is shorter than
    /// [`MIN_PEPPER_LEN`] bytes. The pepper must be a random server-side
    /// secret stored apart from the key database; rotating it invalidates
    /// every issued key.
    pub fn new(
        store: Arc<dyn ApiKeyStore>,
        pepper: impl Into<Vec<u8>>,
    ) -> Result<Self, ApiKeyError> {
        let pepper = pepper.into();
        if pepper.len() < MIN_PEPPER_LEN {
            return Err(ApiKeyError::Configuration(format!(
                "API key pepper must be at least {MIN_PEPPER_LEN} bytes (got {})",
                pepper.len()
            )));
        }
        Ok(Self {
            store,
            pepper,
            key_prefix: "ak".to_string(),
            default_expiration: Some(Duration::days(365)),
            rate_limit_window: Duration::minutes(1),
            rate_counters: DashMap::new(),
            last_sweep_unix: AtomicI64::new(0),
        })
    }

    /// Set key prefix (default: "ak")
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Set default expiration duration
    pub fn with_expiration(mut self, duration: Option<Duration>) -> Self {
        self.default_expiration = duration;
        self
    }

    /// Override the rolling window used to enforce each key's `rate_limit`
    /// (default: 1 minute). Mainly useful for tests that need a short window.
    pub fn with_rate_limit_window(mut self, window: Duration) -> Self {
        self.rate_limit_window = window;
        self
    }

    /// Record a request against `key_id`'s rate limit window and check it
    /// against `limit` (requests per window). Returns
    /// [`ApiKeyError::RateLimitExceeded`] once the count exceeds `limit`.
    ///
    /// Only the shard holding `key_id` is locked, and only for the duration of
    /// the counter update — no clock call or map-wide scan happens under it.
    /// Reclaiming expired windows is handled by [`Self::sweep_expired_windows`],
    /// which is rate-limited to once per window.
    fn check_rate_limit(&self, key_id: &str, limit: u32) -> Result<(), ApiKeyError> {
        let now = Utc::now();
        let window = self.rate_limit_window;

        // Borrowing lookup first: avoids allocating `key_id.to_string()` on the
        // common hot path where the key is already tracked. The guard is scoped
        // so it is released before anything else touches the map.
        let mut count = None;
        if let Some(mut entry) = self.rate_counters.get_mut(key_id) {
            if now - entry.0 > window {
                *entry = (now, 0);
            }
            entry.1 += 1;
            count = Some(entry.1);
        }

        let count = match count {
            Some(count) => count,
            None => {
                self.rate_counters
                    .entry(key_id.to_string())
                    .and_modify(|entry| {
                        // Another caller may have inserted between the lookup
                        // and here; fold into their window rather than resetting.
                        if now - entry.0 > window {
                            *entry = (now, 0);
                        }
                        entry.1 += 1;
                    })
                    .or_insert((now, 1))
                    .1
            }
        };

        self.sweep_expired_windows(now);

        if count > limit {
            Err(ApiKeyError::RateLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Drop counters whose window has fully elapsed, at most once per window.
    ///
    /// Those entries are exactly the ones `check_rate_limit` would reset to
    /// `(now, 0)` on next access, so evicting them cannot change a limit
    /// decision; the sweep exists only to stop key rotation from growing the
    /// map without bound. The compare-exchange means one caller pays for it and
    /// concurrent callers return immediately instead of queueing behind it.
    fn sweep_expired_windows(&self, now: DateTime<Utc>) {
        if self.rate_counters.len() < RATE_COUNTER_SWEEP_THRESHOLD {
            return;
        }

        let window_secs = self.rate_limit_window.num_seconds().max(1);
        let now_secs = now.timestamp();
        let last = self.last_sweep_unix.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) < window_secs {
            return;
        }
        if self
            .last_sweep_unix
            .compare_exchange(last, now_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let window = self.rate_limit_window;
        self.rate_counters
            .retain(|_, entry| now - entry.0 <= window);
    }

    /// Generate a new API key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use armature_auth::api_key::*;
    /// # use std::sync::Arc;
    /// # async fn example(manager: ApiKeyManager) -> Result<(), ApiKeyError> {
    /// let key = manager.generate(
    ///     "user_123",
    ///     vec!["read".to_string(), "write".to_string()]
    /// ).await?;
    ///
    /// let plaintext = key.secret(); // return to the client once
    /// println!("Key ID: {}", key.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate(
        &self,
        user_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<GeneratedApiKey, ApiKeyError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let raw_key = self.generate_random_key();
        let key_string = format!("{}_{}", self.key_prefix, raw_key);

        let expires_at = self.default_expiration.map(|d| Utc::now() + d);

        let api_key = ApiKey {
            id: key_id,
            key_hash: self.hash_key(&key_string),
            user_id: user_id.into(),
            name: None,
            scopes,
            created_at: Utc::now(),
            expires_at,
            last_used_at: None,
            revoked: false,
            rate_limit: None,
        };

        // Only the keyed hash reaches the store.
        self.store.save(&api_key).await?;

        Ok(GeneratedApiKey {
            api_key,
            plaintext: key_string,
        })
    }

    /// Validate an API key
    ///
    /// Returns the API key if valid, None if invalid, or an error.
    pub async fn validate(&self, key: &str) -> Result<Option<ApiKey>, ApiKeyError> {
        let key_hash = self.hash_key(key);
        let api_key = match self.store.find_by_key_hash(&key_hash).await? {
            Some(k) => k,
            None => return Ok(None),
        };

        // Re-check the match in constant time rather than trusting the
        // store's lookup semantics (collation, prefix or case-insensitive
        // matching in some databases).
        if !bool::from(api_key.key_hash.as_bytes().ct_eq(key_hash.as_bytes())) {
            return Ok(None);
        }

        // Check if revoked
        if api_key.revoked {
            return Err(ApiKeyError::Revoked);
        }

        // Check if expired
        if let Some(expires_at) = api_key.expires_at
            && Utc::now() > expires_at
        {
            return Err(ApiKeyError::Expired);
        }

        // Enforce per-key rate limit, if configured.
        if let Some(rate_limit) = api_key.rate_limit {
            self.check_rate_limit(&api_key.id, rate_limit)?;
        }

        // Update last used timestamp
        self.store.update_last_used(&api_key.id, Utc::now()).await?;

        Ok(Some(api_key))
    }

    /// Check if key has required scope
    pub fn has_scope(&self, api_key: &ApiKey, required_scope: &str) -> bool {
        api_key
            .scopes
            .iter()
            .any(|s| s == required_scope || s == "*")
    }

    /// Revoke an API key
    pub async fn revoke(&self, key_id: &str) -> Result<(), ApiKeyError> {
        self.store.revoke(key_id).await
    }

    /// List all keys for a user
    pub async fn list_user_keys(&self, user_id: &str) -> Result<Vec<ApiKey>, ApiKeyError> {
        self.store.list_by_user(user_id).await
    }

    /// Rotate an API key (revoke old, generate new)
    pub async fn rotate(&self, old_key_id: &str) -> Result<GeneratedApiKey, ApiKeyError> {
        // Get old key
        let old_key = self
            .store
            .find_by_id(old_key_id)
            .await?
            .ok_or(ApiKeyError::Invalid)?;

        // Revoke old key
        self.revoke(old_key_id).await?;

        // Generate new key with same scopes
        self.generate(&old_key.user_id, old_key.scopes).await
    }

    /// Generate random key string
    fn generate_random_key(&self) -> String {
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The stored form of an API key: hex `HMAC-SHA256(pepper, key)`.
    ///
    /// Keyed so that a leaked key table cannot be used to check guesses
    /// offline without also stealing the pepper.
    pub fn hash_key(&self, key: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.pepper)
            .expect("HMAC accepts any key length");
        mac.update(key.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InMemoryStore {
        keys: std::sync::Mutex<Vec<ApiKey>>,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                keys: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    const PEPPER: &[u8] = b"test-pepper-0123456789abcdefghijklmnop";

    fn manager_with(store: Arc<InMemoryStore>) -> ApiKeyManager {
        ApiKeyManager::new(store, PEPPER).unwrap()
    }

    #[async_trait]
    impl ApiKeyStore for InMemoryStore {
        async fn save(&self, key: &ApiKey) -> Result<(), ApiKeyError> {
            let mut keys = self.keys.lock().unwrap();
            if let Some(existing) = keys.iter_mut().find(|k| k.id == key.id) {
                *existing = key.clone();
            } else {
                keys.push(key.clone());
            }
            Ok(())
        }

        async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, ApiKeyError> {
            let keys = self.keys.lock().unwrap();
            Ok(keys.iter().find(|k| k.key_hash == key_hash).cloned())
        }

        async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, ApiKeyError> {
            let keys = self.keys.lock().unwrap();
            Ok(keys.iter().find(|k| k.id == id).cloned())
        }

        async fn list_by_user(&self, user_id: &str) -> Result<Vec<ApiKey>, ApiKeyError> {
            let keys = self.keys.lock().unwrap();
            Ok(keys
                .iter()
                .filter(|k| k.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn revoke(&self, key_id: &str) -> Result<(), ApiKeyError> {
            let mut keys = self.keys.lock().unwrap();
            if let Some(key) = keys.iter_mut().find(|k| k.id == key_id) {
                key.revoked = true;
            }
            Ok(())
        }

        async fn update_last_used(
            &self,
            key_id: &str,
            timestamp: DateTime<Utc>,
        ) -> Result<(), ApiKeyError> {
            let mut keys = self.keys.lock().unwrap();
            if let Some(key) = keys.iter_mut().find(|k| k.id == key_id) {
                key.last_used_at = Some(timestamp);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_generate_api_key() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();

        assert!(key.secret().starts_with("ak_"));
        assert_eq!(key.user_id, "user_123");
        assert_eq!(key.scopes, vec!["read"]);
    }

    #[tokio::test]
    async fn test_validate_api_key() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();
        let validated = manager.validate(key.secret()).await.unwrap();

        assert!(validated.is_some());
        assert_eq!(validated.unwrap().user_id, "user_123");
    }

    #[tokio::test]
    async fn validate_enforces_rate_limit_per_key() {
        let store = Arc::new(InMemoryStore::new());
        let manager = ApiKeyManager::new(store.clone(), PEPPER).unwrap();

        let mut key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();
        key.api_key.rate_limit = Some(3);
        store.save(&key.api_key).await.unwrap();

        // First 3 calls (the limit) succeed.
        for _ in 0..3 {
            let result = manager.validate(key.secret()).await;
            assert!(result.is_ok(), "expected call within limit to succeed");
        }

        // The 4th call within the same window is rejected.
        let result = manager.validate(key.secret()).await;
        assert!(matches!(result, Err(ApiKeyError::RateLimitExceeded)));
    }

    #[tokio::test]
    async fn validate_without_rate_limit_is_unbounded() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();

        for _ in 0..10 {
            assert!(manager.validate(key.secret()).await.unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();
        manager.revoke(&key.id).await.unwrap();

        let result = manager.validate(key.secret()).await;
        assert!(matches!(result, Err(ApiKeyError::Revoked)));
    }

    #[tokio::test]
    async fn rate_limit_window_resets_after_expiry() {
        let store = Arc::new(InMemoryStore::new());
        // The rate limiter reads wall-clock time via `Utc::now()` rather than
        // tokio's virtual clock, so this test can't use
        // `start_paused` + `tokio::time::advance` to fake elapsed time. Use a
        // generously wide window/sleep margin instead of a tight one to keep
        // this timing-based test from flaking under load.
        let manager = ApiKeyManager::new(store.clone(), PEPPER)
            .unwrap()
            .with_rate_limit_window(Duration::milliseconds(200));

        let mut key = manager
            .generate("user_123", vec!["read".to_string()])
            .await
            .unwrap();
        key.api_key.rate_limit = Some(2);
        store.save(&key.api_key).await.unwrap();

        // First 2 calls (the limit) succeed.
        for _ in 0..2 {
            let result = manager.validate(key.secret()).await;
            assert!(result.is_ok(), "expected call within limit to succeed");
        }

        // The 3rd call within the same window is rejected.
        let result = manager.validate(key.secret()).await;
        assert!(matches!(result, Err(ApiKeyError::RateLimitExceeded)));

        // Wait past the window and confirm the count resets.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let result = manager.validate(key.secret()).await;
        assert!(
            result.is_ok(),
            "expected count to reset after window elapsed"
        );
    }

    #[tokio::test]
    async fn rotate_revokes_old_key_and_preserves_scopes() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let old_key = manager
            .generate("user_123", vec!["read".to_string(), "write".to_string()])
            .await
            .unwrap();

        let new_key = manager.rotate(&old_key.id).await.unwrap();

        // Old key is now revoked.
        let old_result = manager.validate(old_key.secret()).await;
        assert!(matches!(old_result, Err(ApiKeyError::Revoked)));

        // New key validates and carries the same scopes.
        let validated = manager.validate(new_key.secret()).await.unwrap();
        assert!(validated.is_some());
        let validated = validated.unwrap();
        assert_eq!(validated.scopes, old_key.scopes);
        assert_ne!(validated.id, old_key.id);
        assert_eq!(validated.user_id, old_key.user_id);
    }

    #[tokio::test]
    async fn test_has_scope() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);

        let key = manager
            .generate("user_123", vec!["read".to_string(), "write".to_string()])
            .await
            .unwrap();

        assert!(manager.has_scope(&key, "read"));
        assert!(manager.has_scope(&key, "write"));
        assert!(!manager.has_scope(&key, "admin"));
    }

    #[tokio::test]
    async fn store_never_sees_plaintext_key() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store.clone());
        let generated = manager.generate("user_123", vec![]).await.unwrap();

        let stored = store.keys.lock().unwrap()[0].clone();
        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(!serialized.contains(generated.secret()), "{serialized}");
        assert_ne!(stored.key_hash, generated.secret());
        assert_eq!(stored.key_hash, manager.hash_key(generated.secret()));
    }

    #[tokio::test]
    async fn key_hash_depends_on_pepper() {
        let store = Arc::new(InMemoryStore::new());
        let a = manager_with(store.clone());
        let b = ApiKeyManager::new(
            store.clone(),
            b"another-pepper-0123456789abcdefghijk".to_vec(),
        )
        .unwrap();
        assert_ne!(a.hash_key("ak_x"), b.hash_key("ak_x"));

        // A key issued under one pepper does not validate under another.
        let generated = a.generate("u", vec![]).await.unwrap();
        assert!(b.validate(generated.secret()).await.unwrap().is_none());
        assert!(a.validate(generated.secret()).await.unwrap().is_some());
    }

    #[test]
    fn short_pepper_rejected() {
        let store = Arc::new(InMemoryStore::new());
        assert!(matches!(
            ApiKeyManager::new(store, b"short".to_vec()),
            Err(ApiKeyError::Configuration(_))
        ));
    }

    #[tokio::test]
    async fn wrong_key_does_not_validate() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);
        let generated = manager.generate("u", vec![]).await.unwrap();
        let mut wrong = generated.secret().to_string();
        wrong.push('x');
        assert!(manager.validate(&wrong).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn debug_redacts_key_material() {
        let store = Arc::new(InMemoryStore::new());
        let manager = manager_with(store);
        let generated = manager.generate("u", vec![]).await.unwrap();
        let debug = format!("{generated:?}");
        assert!(!debug.contains(generated.secret()), "{debug}");
        assert!(!debug.contains(&generated.key_hash), "{debug}");
        assert!(debug.contains("<redacted>"));
    }
}
