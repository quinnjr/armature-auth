// Password hashing and verification

use crate::{AuthError, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher as _, PasswordVerifier as _, phc::PasswordHash},
};

/// Password hashing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// Bcrypt (slower but battle-tested)
    Bcrypt,
    /// Argon2 (modern, recommended)
    Argon2,
}

/// Password hasher for secure password hashing and verification.
///
/// Supports multiple algorithms including Bcrypt and Argon2.
///
/// # Examples
///
/// Using Argon2 (recommended):
///
/// ```
/// use armature_auth::{PasswordHasher, PasswordVerifier, password::HashAlgorithm};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let hasher = PasswordHasher::new(HashAlgorithm::Argon2);
///
/// // Hash a password
/// let hash = hasher.hash("supersecret")?;
///
/// // Verify correct password
/// assert!(hasher.verify("supersecret", &hash)?);
///
/// // Verify incorrect password
/// assert!(!hasher.verify("wrongpassword", &hash)?);
/// # Ok(())
/// # }
/// ```
///
/// Using Bcrypt:
///
/// ```
/// use armature_auth::{PasswordHasher, PasswordVerifier, password::HashAlgorithm};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let hasher = PasswordHasher::new(HashAlgorithm::Bcrypt);
/// let hash = hasher.hash("mypassword")?;
/// assert!(hasher.verify("mypassword", &hash)?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PasswordHasher {
    algorithm: HashAlgorithm,
    argon2_params: argon2::Params,
    bcrypt_cost: u32,
}

/// Default Argon2id memory cost: 64 MiB (in KiB), per the RFC 9106 second
/// recommended option and OWASP's 2024 guidance.
pub const DEFAULT_ARGON2_M_COST: u32 = 64 * 1024;
/// Default Argon2id iteration count.
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const DEFAULT_ARGON2_P_COST: u32 = 1;

/// Longest password bcrypt can hash without silently truncating it.
pub const BCRYPT_MAX_PASSWORD_BYTES: usize = 72;

impl PasswordHasher {
    /// Create a new password hasher.
    ///
    /// Argon2 uses Argon2id with m = 64 MiB, t = 3, p = 1
    /// ([`DEFAULT_ARGON2_M_COST`] etc.); bcrypt uses `bcrypt::DEFAULT_COST`.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            argon2_params: argon2::Params::new(
                DEFAULT_ARGON2_M_COST,
                DEFAULT_ARGON2_T_COST,
                DEFAULT_ARGON2_P_COST,
                None,
            )
            .expect("default Argon2 parameters are valid"),
            bcrypt_cost: bcrypt::DEFAULT_COST,
        }
    }

    /// Override the Argon2id cost parameters (memory in KiB, iterations,
    /// parallelism).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Configuration`] if the parameters are outside
    /// Argon2's valid range.
    pub fn with_argon2_params(mut self, m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        self.argon2_params = argon2::Params::new(m_cost, t_cost, p_cost, None)
            .map_err(|e| AuthError::Configuration(format!("invalid Argon2 parameters: {e}")))?;
        Ok(self)
    }

    /// Override the bcrypt cost factor (4..=31).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Configuration`] for a cost outside bcrypt's range.
    pub fn with_bcrypt_cost(mut self, cost: u32) -> Result<Self> {
        if !(4..=31).contains(&cost) {
            return Err(AuthError::Configuration(format!(
                "bcrypt cost must be within 4..=31 (got {cost})"
            )));
        }
        self.bcrypt_cost = cost;
        Ok(self)
    }

    fn argon2(&self) -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            self.argon2_params.clone(),
        )
    }

    /// Hash a password.
    ///
    /// This is CPU- and (for Argon2) memory-heavy by design; from async code
    /// use [`hash_async`](Self::hash_async) so the work runs on Tokio's
    /// blocking pool instead of stalling a runtime worker.
    ///
    /// # Errors
    ///
    /// With [`HashAlgorithm::Bcrypt`], passwords longer than
    /// [`BCRYPT_MAX_PASSWORD_BYTES`] are rejected rather than silently
    /// truncated.
    pub fn hash(&self, password: &str) -> Result<String> {
        match self.algorithm {
            HashAlgorithm::Bcrypt => self.hash_bcrypt(password),
            HashAlgorithm::Argon2 => self.hash_argon2(password),
        }
    }

    /// Hash with bcrypt, refusing (instead of truncating) passwords longer
    /// than 72 bytes.
    fn hash_bcrypt(&self, password: &str) -> Result<String> {
        if password.len() > BCRYPT_MAX_PASSWORD_BYTES {
            return Err(AuthError::PasswordHashError(format!(
                "bcrypt cannot hash passwords longer than {BCRYPT_MAX_PASSWORD_BYTES} bytes; \
                 use Argon2"
            )));
        }
        // At <= 72 bytes the only thing bcrypt drops is the C-string NUL
        // terminator, so no password information is lost.
        bcrypt::hash(password, self.bcrypt_cost)
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))
    }

    /// Hash with argon2
    fn hash_argon2(&self, password: &str) -> Result<String> {
        // `hash_password` draws a 16-byte (RECOMMENDED_SALT_LEN) salt from the OS RNG via
        // getrandom.
        let password_hash = self
            .argon2()
            .hash_password(password.as_bytes())
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    /// [`hash`](Self::hash) on Tokio's blocking thread pool.
    pub async fn hash_async(&self, password: &str) -> Result<String> {
        let hasher = self.clone();
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || hasher.hash(&password))
            .await
            .map_err(|e| AuthError::PasswordHashError(format!("hashing task failed: {e}")))?
    }

    /// [`verify`](PasswordVerifier::verify) on Tokio's blocking thread pool.
    pub async fn verify_async(&self, password: &str, hash: &str) -> Result<bool> {
        let hasher = self.clone();
        let password = password.to_owned();
        let hash = hash.to_owned();
        tokio::task::spawn_blocking(move || hasher.verify(&password, &hash))
            .await
            .map_err(|e| AuthError::PasswordVerifyError(format!("verify task failed: {e}")))?
    }

    /// Whether a stored `hash` should be replaced by a fresh
    /// [`hash`](Self::hash) of the password.
    ///
    /// True when the hash uses a different algorithm than this hasher (e.g. a
    /// legacy bcrypt hash while Argon2 is configured), a non-Argon2id variant,
    /// weaker cost parameters than configured, or an unrecognised format. Call
    /// it after a *successful* verification, while the plaintext is still at
    /// hand, and store the new hash (rehash-on-login).
    ///
    /// ```
    /// use armature_auth::{PasswordHasher, PasswordVerifier, password::HashAlgorithm};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let hasher = PasswordHasher::default();
    /// let legacy = PasswordHasher::new(HashAlgorithm::Bcrypt).with_bcrypt_cost(4)?.hash("pw")?;
    /// assert!(hasher.verify("pw", &legacy)?);
    /// assert!(hasher.needs_rehash(&legacy));
    /// assert!(!hasher.needs_rehash(&hasher.hash("pw")?));
    /// # Ok(())
    /// # }
    /// ```
    pub fn needs_rehash(&self, hash: &str) -> bool {
        match self.algorithm {
            HashAlgorithm::Bcrypt => {
                if !hash.starts_with("$2") {
                    return true;
                }
                // `$2b$12$...`: the cost is the second `$`-separated field.
                hash.split('$')
                    .nth(2)
                    .and_then(|c| c.parse::<u32>().ok())
                    .is_none_or(|cost| cost < self.bcrypt_cost)
            }
            HashAlgorithm::Argon2 => {
                let Ok(parsed) = PasswordHash::new(hash) else {
                    return true;
                };
                if parsed.algorithm.as_str() != "argon2id" {
                    return true;
                }
                match argon2::Params::try_from(&parsed) {
                    Ok(params) => {
                        params.m_cost() < self.argon2_params.m_cost()
                            || params.t_cost() < self.argon2_params.t_cost()
                            || params.p_cost() != self.argon2_params.p_cost()
                    }
                    Err(_) => true,
                }
            }
        }
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new(HashAlgorithm::Argon2)
    }
}

/// Password verifier
pub trait PasswordVerifier {
    /// Verify a password against a hash
    fn verify(&self, password: &str, hash: &str) -> Result<bool>;
}

impl PasswordVerifier for PasswordHasher {
    fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        // Auto-detect algorithm from hash format
        if hash.starts_with("$2") {
            // Bcrypt format. A password longer than 72 bytes can never have
            // been hashed by `hash_bcrypt`, and the truncating verifier would
            // accept any password sharing its first 72 bytes, so reject it.
            if password.len() > BCRYPT_MAX_PASSWORD_BYTES {
                return Ok(false);
            }
            bcrypt::verify(password, hash)
                .map_err(|e| AuthError::PasswordVerifyError(e.to_string()))
        } else if hash.starts_with("$argon2") {
            // Argon2 format. The parameters (and variant) are read from the
            // PHC string itself, so hashes made with older/weaker settings
            // still verify; `needs_rehash` reports them for upgrading.
            let parsed_hash = PasswordHash::new(hash)
                .map_err(|e| AuthError::PasswordVerifyError(e.to_string()))?;

            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok())
        } else {
            Err(AuthError::PasswordVerifyError(
                "Unknown hash format".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_hashing() {
        let hasher = PasswordHasher::new(HashAlgorithm::Bcrypt);
        let password = "test-password-123";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$2"));

        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_argon2_hashing() {
        let hasher = PasswordHasher::new(HashAlgorithm::Argon2);
        let password = "test-password-456";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$argon2"));

        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    /// A PHC string produced by argon2 0.5 (`Argon2::default()`, 16-byte salt) before the
    /// upgrade to argon2 0.6. Stored hashes must keep verifying across the dependency bump.
    const ARGON2_0_5_FIXTURE: &str = "$argon2id$v=19$m=19456,t=2,p=1$nH0iQJbueCWq5JnfvSpiJw$roc61cxbzQ5B3f0VWGYnMPlFFP7YkK7C8DZnDLpbD1o";

    #[test]
    fn test_argon2_verifies_hash_from_previous_version() {
        let verifier = PasswordHasher::default();
        assert!(
            verifier
                .verify("correct horse battery staple", ARGON2_0_5_FIXTURE)
                .unwrap()
        );
        assert!(
            !verifier
                .verify("wrong-password", ARGON2_0_5_FIXTURE)
                .unwrap()
        );
    }

    #[test]
    fn test_argon2_new_hash_uses_hardened_params_and_salt_length() {
        let hash = PasswordHasher::new(HashAlgorithm::Argon2)
            .hash("test-password")
            .unwrap();
        let parsed = PasswordHash::new(&hash).unwrap();
        let fixture = PasswordHash::new(ARGON2_0_5_FIXTURE).unwrap();

        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert_eq!(parsed.algorithm, fixture.algorithm);
        assert_eq!(parsed.version, fixture.version);
        assert_eq!(
            parsed.salt.unwrap().as_ref().len(),
            fixture.salt.unwrap().as_ref().len()
        );
        assert_eq!(parsed.salt.unwrap().as_ref().len(), 16);
        assert_eq!(
            parsed.hash.unwrap().as_ref().len(),
            fixture.hash.unwrap().as_ref().len()
        );
    }

    #[test]
    fn test_argon2_rejects_tampered_hash() {
        let tampered = ARGON2_0_5_FIXTURE.replace("m=19456", "m=19457");
        assert!(
            !PasswordHasher::default()
                .verify("correct horse battery staple", &tampered)
                .unwrap()
        );
    }

    #[test]
    fn test_auto_detect_algorithm() {
        let bcrypt_hasher = PasswordHasher::new(HashAlgorithm::Bcrypt);
        let argon2_hasher = PasswordHasher::new(HashAlgorithm::Argon2);

        let password = "test-password";

        let bcrypt_hash = bcrypt_hasher.hash(password).unwrap();
        let argon2_hash = argon2_hasher.hash(password).unwrap();

        // Should work regardless of hasher algorithm
        let verifier = PasswordHasher::default();
        assert!(verifier.verify(password, &bcrypt_hash).unwrap());
        assert!(verifier.verify(password, &argon2_hash).unwrap());
    }

    #[test]
    fn previous_default_argon2_hash_needs_rehash() {
        let hasher = PasswordHasher::default();
        assert!(hasher.needs_rehash(ARGON2_0_5_FIXTURE));
        let fresh = hasher.hash("pw").unwrap();
        assert!(!hasher.needs_rehash(&fresh));
        assert!(hasher.needs_rehash("not-a-hash"));
    }

    #[test]
    fn bcrypt_hash_rejects_passwords_over_72_bytes() {
        let hasher = PasswordHasher::new(HashAlgorithm::Bcrypt)
            .with_bcrypt_cost(4)
            .unwrap();
        let long = "a".repeat(73);
        assert!(hasher.hash(&long).is_err());
        assert!(hasher.hash(&"a".repeat(72)).is_ok());
    }

    #[test]
    fn bcrypt_verify_does_not_truncate() {
        // A legacy hash of a 72-byte prefix, made by the truncating hasher.
        let prefix = "p".repeat(72);
        let legacy = bcrypt::hash(&prefix, 4).unwrap();
        let hasher = PasswordHasher::default();
        assert!(hasher.verify(&prefix, &legacy).unwrap());
        // With truncation, anything sharing the 72-byte prefix would verify.
        let longer = format!("{prefix}-attacker-suffix");
        assert!(!hasher.verify(&longer, &legacy).unwrap());
    }

    #[test]
    fn bcrypt_low_cost_needs_rehash_under_bcrypt_config() {
        let weak = PasswordHasher::new(HashAlgorithm::Bcrypt)
            .with_bcrypt_cost(4)
            .unwrap()
            .hash("pw")
            .unwrap();
        let strong = PasswordHasher::new(HashAlgorithm::Bcrypt)
            .with_bcrypt_cost(5)
            .unwrap();
        assert!(strong.needs_rehash(&weak));
    }

    #[test]
    fn invalid_cost_parameters_rejected() {
        assert!(
            PasswordHasher::default()
                .with_argon2_params(1, 0, 0)
                .is_err()
        );
        assert!(PasswordHasher::default().with_bcrypt_cost(3).is_err());
    }

    #[tokio::test]
    async fn async_hash_and_verify_roundtrip() {
        let hasher = PasswordHasher::default()
            .with_argon2_params(8 * 1024, 1, 1)
            .unwrap();
        let hash = hasher.hash_async("pw").await.unwrap();
        assert!(hasher.verify_async("pw", &hash).await.unwrap());
        assert!(!hasher.verify_async("nope", &hash).await.unwrap());
    }
}
