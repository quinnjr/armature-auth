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
}

impl PasswordHasher {
    /// Create a new password hasher
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Hash a password
    pub fn hash(&self, password: &str) -> Result<String> {
        match self.algorithm {
            HashAlgorithm::Bcrypt => self.hash_bcrypt(password),
            HashAlgorithm::Argon2 => self.hash_argon2(password),
        }
    }

    /// Hash with bcrypt
    fn hash_bcrypt(&self, password: &str) -> Result<String> {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))
    }

    /// Hash with argon2
    fn hash_argon2(&self, password: &str) -> Result<String> {
        // `hash_password` draws a 16-byte (RECOMMENDED_SALT_LEN) salt from the OS RNG via
        // getrandom, matching the salt argon2 0.5's `SaltString::generate(&mut OsRng)` produced.
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes())
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        Ok(password_hash.to_string())
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
            // Bcrypt format
            bcrypt::verify(password, hash)
                .map_err(|e| AuthError::PasswordVerifyError(e.to_string()))
        } else if hash.starts_with("$argon2") {
            // Argon2 format
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
    fn test_argon2_new_hash_keeps_algorithm_params_and_salt_length() {
        let hash = PasswordHasher::new(HashAlgorithm::Argon2)
            .hash("test-password")
            .unwrap();
        let parsed = PasswordHash::new(&hash).unwrap();
        let fixture = PasswordHash::new(ARGON2_0_5_FIXTURE).unwrap();

        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_eq!(parsed.algorithm, fixture.algorithm);
        assert_eq!(parsed.version, fixture.version);
        assert_eq!(parsed.params, fixture.params);
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
}
