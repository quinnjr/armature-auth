//! Two-Factor Authentication (2FA)
//!
//! Provides TOTP (Time-based One-Time Password, RFC 6238) support for
//! two-factor authentication, plus hashed one-time backup codes.
//!
//! # Features
//!
//! - TOTP generation and validation with replay protection
//! - QR code generation for authenticator apps
//! - Backup codes, stored only as hashes
//!
//! # Replay protection
//!
//! A TOTP code stays valid for its whole time step (plus the ±1-step skew
//! window), so a code observed once could otherwise be replayed for ~90 s.
//! [`TotpSecret::verify`] therefore takes the last time step accepted for this
//! user and returns the step it matched; persist that and pass it back next
//! time. [`TotpSecret::verify_and_record`] does both against a `&mut` field.
//!
//! # Usage
//!
//! ```no_run
//! use armature_auth::two_factor::*;
//!
//! # async fn example() -> Result<(), TwoFactorError> {
//! // Generate TOTP secret for user; persist `secret.to_base32()` encrypted.
//! let secret = TotpSecret::generate();
//!
//! // Generate QR code URL for authenticator apps
//! let qr_url = secret.to_qr_url("user@example.com", "MyApp")?;
//! println!("Scan this QR: {}", qr_url);
//!
//! // Verify TOTP code from user, tracking the last accepted step
//! let mut last_step: Option<u64> = None; // load from the user record
//! let code = "123456"; // From authenticator app
//! if secret.verify_and_record(code, 30, &mut last_step)? {
//!     // save `last_step` back to the user record
//!     println!("2FA code valid!");
//! }
//! # Ok(())
//! # }
//! ```

use data_encoding::BASE32_NOPAD;
use qrcode::{QrCode, render::svg};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use totp_lite::{Sha1, totp_custom};

/// Constant-time string comparison (prevents timing attacks on secret-derived
/// values such as TOTP codes and backup codes).
///
/// Thin wrapper over the shared [`armature_core::crypto::constant_time_eq`]
/// helper so all crates that compare secret-derived values use the same,
/// single verified implementation.
fn constant_time_eq(a: &str, b: &str) -> bool {
    armature_core::crypto::constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Two-Factor Authentication errors
#[derive(Debug, Error)]
pub enum TwoFactorError {
    #[error("Invalid TOTP code")]
    InvalidCode,

    #[error("Invalid secret")]
    InvalidSecret,

    #[error("Invalid TOTP time step: must be greater than zero")]
    InvalidTimeStep,

    #[error("QR code generation failed: {0}")]
    QrCodeError(String),

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(&'static str),
}

/// TOTP Secret.
///
/// Redacted from `Debug` and deliberately not `Serialize`/`Deserialize`:
/// persist it explicitly via [`to_base32`](Self::to_base32) (preferably
/// encrypted at rest) and restore it with [`from_base32`](Self::from_base32).
#[derive(Clone)]
pub struct TotpSecret {
    /// Base32-encoded secret
    secret: String,
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl TotpSecret {
    /// Generate a new random 160-bit TOTP secret
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::two_factor::*;
    ///
    /// let secret = TotpSecret::generate();
    /// assert_eq!(secret.to_base32().len(), 32);
    /// ```
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.random()).collect();
        Self {
            secret: BASE32_NOPAD.encode(&bytes),
        }
    }

    /// Restore a TOTP secret from its base32 form.
    ///
    /// # Errors
    ///
    /// [`TwoFactorError::InvalidSecret`] if `secret` is not valid unpadded
    /// base32 or decodes to fewer than 16 bytes (128 bits, RFC 4226's
    /// minimum).
    pub fn from_base32(secret: impl Into<String>) -> Result<Self, TwoFactorError> {
        let secret = secret.into();
        let bytes = BASE32_NOPAD
            .decode(secret.as_bytes())
            .map_err(|_| TwoFactorError::InvalidSecret)?;
        if bytes.len() < 16 {
            return Err(TwoFactorError::InvalidSecret);
        }
        Ok(Self { secret })
    }

    /// Get base32-encoded secret
    pub fn to_base32(&self) -> &str {
        &self.secret
    }

    fn secret_bytes(&self) -> Result<Vec<u8>, TwoFactorError> {
        BASE32_NOPAD
            .decode(self.secret.as_bytes())
            .map_err(|_| TwoFactorError::InvalidSecret)
    }

    /// Generate TOTP code for current time
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::two_factor::*;
    ///
    /// let secret = TotpSecret::generate();
    /// let code = secret.generate_code(30).unwrap();
    /// assert_eq!(code.len(), 6);
    /// assert!(secret.generate_code(0).is_err());
    /// ```
    pub fn generate_code(&self, time_step: u64) -> Result<String, TwoFactorError> {
        if time_step == 0 {
            return Err(TwoFactorError::InvalidTimeStep);
        }
        let secret_bytes = self.secret_bytes()?;
        // totp-lite returns the code already zero-padded to the requested digit count.
        Ok(totp_custom::<Sha1>(time_step, 6, &secret_bytes, unix_now()))
    }

    /// Verify a TOTP code, rejecting replays.
    ///
    /// Checks the code against the current time step and one step either
    /// side (clock skew). A step at or before `last_accepted_step` is never
    /// accepted, so a code (or an older one) cannot be used twice.
    ///
    /// Returns `Ok(Some(step))` with the matched time step on success —
    /// **persist it** and pass it as `last_accepted_step` on the next call —
    /// or `Ok(None)` if the code is wrong or replayed.
    ///
    /// # Errors
    ///
    /// [`TwoFactorError::InvalidTimeStep`] for `time_step == 0`,
    /// [`TwoFactorError::InvalidSecret`] for an undecodable secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::two_factor::*;
    ///
    /// # fn example() -> Result<(), TwoFactorError> {
    /// let secret = TotpSecret::generate();
    /// let code = secret.generate_code(30)?;
    ///
    /// let step = secret.verify(&code, 30, None)?.expect("valid");
    /// // The same code again is a replay.
    /// assert_eq!(secret.verify(&code, 30, Some(step))?, None);
    /// # Ok(())
    /// # }
    /// # example().unwrap();
    /// ```
    pub fn verify(
        &self,
        code: &str,
        time_step: u64,
        last_accepted_step: Option<u64>,
    ) -> Result<Option<u64>, TwoFactorError> {
        self.verify_at(code, time_step, last_accepted_step, unix_now())
    }

    fn verify_at(
        &self,
        code: &str,
        time_step: u64,
        last_accepted_step: Option<u64>,
        now: u64,
    ) -> Result<Option<u64>, TwoFactorError> {
        if time_step == 0 {
            return Err(TwoFactorError::InvalidTimeStep);
        }
        let secret_bytes = self.secret_bytes()?;
        let current = now / time_step;

        // Scan every candidate step without early exit so timing does not
        // reveal which window matched.
        let mut matched: Option<u64> = None;
        for step in [
            current.checked_sub(1),
            Some(current),
            current.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let expected = totp_custom::<Sha1>(time_step, 6, &secret_bytes, step * time_step);
            let fresh = last_accepted_step.is_none_or(|last| step > last);
            if constant_time_eq(&expected, code) && fresh && matched.is_none() {
                matched = Some(step);
            }
        }
        Ok(matched)
    }

    /// [`verify`](Self::verify) and update `last_accepted_step` in place on
    /// success. Returns whether the code was accepted. Persist
    /// `last_accepted_step` afterwards.
    pub fn verify_and_record(
        &self,
        code: &str,
        time_step: u64,
        last_accepted_step: &mut Option<u64>,
    ) -> Result<bool, TwoFactorError> {
        match self.verify(code, time_step, *last_accepted_step)? {
            Some(step) => {
                *last_accepted_step = Some(step);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Generate QR code URL for authenticator apps
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::two_factor::*;
    ///
    /// # fn example() -> Result<(), TwoFactorError> {
    /// let secret = TotpSecret::generate();
    /// let url = secret.to_qr_url("user@example.com", "MyApp")?;
    /// assert!(url.starts_with("otpauth://totp/"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_qr_url(&self, account: &str, issuer: &str) -> Result<String, TwoFactorError> {
        let url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            urlencoding::encode(issuer),
            urlencoding::encode(account),
            self.secret,
            urlencoding::encode(issuer)
        );
        Ok(url)
    }

    /// Generate QR code SVG
    ///
    /// Returns SVG string that can be rendered in HTML.
    pub fn to_qr_svg(&self, account: &str, issuer: &str) -> Result<String, TwoFactorError> {
        let url = self.to_qr_url(account, issuer)?;

        let code =
            QrCode::new(url.as_bytes()).map_err(|e| TwoFactorError::QrCodeError(e.to_string()))?;

        let svg = code.render::<svg::Color>().min_dimensions(200, 200).build();

        Ok(svg)
    }
}

/// Backup/recovery codes, stored as hashes.
///
/// [`BackupCodes::generate`] returns the plaintext codes once, in
/// [`GeneratedBackupCodes`], for display to the user; this type keeps only
/// their SHA-256 hashes and is what you persist. Each code carries 80 bits of
/// entropy, so an unkeyed hash is not brute-forceable.
#[derive(Clone, Serialize, Deserialize)]
pub struct BackupCodes {
    /// Hex SHA-256 of each unused code (normalized: hyphens removed,
    /// lower-cased).
    pub code_hashes: Vec<String>,
}

impl fmt::Debug for BackupCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupCodes")
            .field("remaining", &self.code_hashes.len())
            .finish()
    }
}

/// Freshly generated backup codes: the hashed [`BackupCodes`] to store plus
/// the plaintext codes to show the user exactly once.
///
/// Redacted from `Debug`; not `Serialize`.
#[derive(Clone)]
pub struct GeneratedBackupCodes {
    /// The hashed codes to persist.
    pub stored: BackupCodes,
    plaintext: Vec<String>,
}

impl GeneratedBackupCodes {
    /// The plaintext codes, for one-time display.
    pub fn plaintext(&self) -> &[String] {
        &self.plaintext
    }
}

impl fmt::Debug for GeneratedBackupCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedBackupCodes")
            .field("stored", &self.stored)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl BackupCodes {
    /// Number of random bytes behind each backup code. Backup codes are 2FA
    /// bypass credentials: presenting one substitutes for the second factor
    /// entirely, so the code must be as hard to guess as the factor it
    /// replaces — and, since only an unkeyed hash is stored, hard to brute
    /// force offline from a leaked hash. 10 bytes = 80 bits.
    const CODE_BYTES: usize = 10;

    /// Generate backup codes
    ///
    /// Each code carries `CODE_BYTES` bytes (80 bits) of entropy, rendered as
    /// five hyphen-separated groups of four hex digits for transcription.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_auth::two_factor::*;
    ///
    /// let generated = BackupCodes::generate(10);
    /// for code in generated.plaintext() {
    ///     println!("Backup code: {}", code); // show once
    /// }
    /// let mut stored = generated.stored.clone(); // persist this
    /// let first = generated.plaintext()[0].clone();
    /// assert!(stored.verify_and_consume(&first));
    /// assert!(!stored.verify_and_consume(&first));
    /// ```
    pub fn generate(count: usize) -> GeneratedBackupCodes {
        let mut rng = rand::rng();
        let plaintext: Vec<String> = (0..count)
            .map(|_| {
                let bytes: Vec<u8> = (0..Self::CODE_BYTES).map(|_| rng.random()).collect();
                let hex = hex::encode(bytes);
                hex.as_bytes()
                    .chunks(4)
                    .map(|c| std::str::from_utf8(c).expect("hex is ASCII"))
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .collect();

        GeneratedBackupCodes {
            stored: Self {
                code_hashes: plaintext.iter().map(|c| Self::hash_code(c)).collect(),
            },
            plaintext,
        }
    }

    /// The stored form of a code: hex SHA-256 of the code with hyphens and
    /// whitespace removed, lower-cased.
    pub fn hash_code(code: &str) -> String {
        let normalized: String = code
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        hex::encode(Sha256::digest(normalized.as_bytes()))
    }

    /// Verify and consume a backup code
    ///
    /// Returns true if code was valid and removes it from the list; persist
    /// the updated value before completing the login.
    ///
    /// Every stored hash is compared against the candidate's in constant time
    /// and the scan always runs to completion (no early exit on match).
    pub fn verify_and_consume(&mut self, code: &str) -> bool {
        let candidate = Self::hash_code(code);
        let mut found: Option<usize> = None;
        for (i, c) in self.code_hashes.iter().enumerate() {
            if constant_time_eq(c, &candidate) {
                found = found.or(Some(i));
            }
        }

        if let Some(pos) = found {
            self.code_hashes.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check remaining codes
    pub fn remaining(&self) -> usize {
        self.code_hashes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let secret = TotpSecret::generate();
        assert!(!secret.to_base32().is_empty());
        assert!(TotpSecret::from_base32(secret.to_base32()).is_ok());
    }

    #[test]
    fn from_base32_rejects_invalid_and_short_secrets() {
        assert!(TotpSecret::from_base32("not base32!").is_err());
        assert!(TotpSecret::from_base32("JBSWY3DP").is_err()); // 5 bytes
    }

    #[test]
    fn test_generate_and_verify_totp() {
        let secret = TotpSecret::generate();
        let code = secret.generate_code(30).unwrap();
        assert!(secret.verify(&code, 30, None).unwrap().is_some());
    }

    #[test]
    fn zero_time_step_is_rejected_not_a_panic() {
        let secret = TotpSecret::generate();
        assert!(matches!(
            secret.generate_code(0),
            Err(TwoFactorError::InvalidTimeStep)
        ));
        assert!(matches!(
            secret.verify("123456", 0, None),
            Err(TwoFactorError::InvalidTimeStep)
        ));
    }

    #[test]
    fn verified_code_cannot_be_replayed() {
        let secret = TotpSecret::generate();
        let code = secret.generate_code(30).unwrap();

        let mut last = None;
        assert!(secret.verify_and_record(&code, 30, &mut last).unwrap());
        assert!(last.is_some());
        assert!(!secret.verify_and_record(&code, 30, &mut last).unwrap());
    }

    #[test]
    fn older_steps_rejected_after_newer_accepted() {
        let secret = TotpSecret::generate();
        let bytes = secret.secret_bytes().unwrap();
        let now = 1_000_000_000u64; // fixed clock
        let current = now / 30;
        let previous_code = totp_custom::<Sha1>(30, 6, &bytes, (current - 1) * 30);
        let current_code = totp_custom::<Sha1>(30, 6, &bytes, current * 30);

        // The previous-step code is within the skew window...
        assert_eq!(
            secret.verify_at(&previous_code, 30, None, now).unwrap(),
            Some(current - 1)
        );
        // ...but not once the current step has been accepted.
        let step = secret
            .verify_at(&current_code, 30, None, now)
            .unwrap()
            .unwrap();
        assert_eq!(step, current);
        assert_eq!(
            secret
                .verify_at(&previous_code, 30, Some(step), now)
                .unwrap(),
            None
        );
        // Codes outside the window are rejected.
        let stale = totp_custom::<Sha1>(30, 6, &bytes, (current - 2) * 30);
        assert_eq!(secret.verify_at(&stale, 30, None, now).unwrap(), None);
    }

    #[test]
    fn test_verify_totp_rejects_wrong_code() {
        let secret = TotpSecret::generate();
        let code = secret.generate_code(30).unwrap();

        // Flip the last digit to produce a guaranteed-wrong, same-length code.
        let mut wrong = code.clone();
        let last = wrong.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        wrong.push(flipped);

        assert!(secret.verify(&wrong, 30, None).unwrap().is_none());
        // Different-length input must also be rejected without panicking.
        assert!(
            secret
                .verify(&format!("{}9", code), 30, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn secrets_are_redacted_from_debug() {
        let secret = TotpSecret::generate();
        let debug = format!("{secret:?}");
        assert!(!debug.contains(secret.to_base32()), "{debug}");
        assert!(debug.contains("<redacted>"));

        let generated = BackupCodes::generate(3);
        let debug = format!("{generated:?}");
        for code in generated.plaintext() {
            assert!(!debug.contains(code.as_str()), "{debug}");
        }
        for hash in &generated.stored.code_hashes {
            assert!(!debug.contains(hash.as_str()), "{debug}");
        }
    }

    #[test]
    fn stored_backup_codes_contain_no_plaintext() {
        let generated = BackupCodes::generate(5);
        let json = serde_json::to_string(&generated.stored).unwrap();
        for code in generated.plaintext() {
            assert!(!json.contains(code.as_str()), "{json}");
            let bare: String = code.chars().filter(|c| *c != '-').collect();
            assert!(!json.contains(&bare), "{json}");
        }
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("123456", "123456"));
        assert!(!constant_time_eq("123456", "123457"));
        assert!(!constant_time_eq("123456", "1234567"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_qr_url() {
        let secret = TotpSecret::generate();
        let url = secret.to_qr_url("user@example.com", "MyApp").unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        // The account name is percent-encoded (per RFC 3986) before being
        // embedded in the URL, so "@" becomes "%40".
        assert!(url.contains("user%40example.com"));
        assert!(url.contains("MyApp"));
    }

    #[test]
    fn test_backup_codes_use_full_entropy() {
        let generated = BackupCodes::generate(64);
        assert_eq!(generated.plaintext().len(), 64);

        for code in generated.plaintext() {
            let hex: String = code.chars().filter(|c| *c != '-').collect();
            assert_eq!(
                hex.len(),
                BackupCodes::CODE_BYTES * 2,
                "every drawn byte must reach the code: {code}"
            );
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }

        let unique: std::collections::HashSet<&String> = generated.plaintext().iter().collect();
        assert_eq!(unique.len(), 64);
    }

    #[test]
    fn test_backup_code_consumption() {
        let generated = BackupCodes::generate(5);
        let mut codes = generated.stored.clone();
        let first_code = generated.plaintext()[0].clone();

        assert_eq!(codes.remaining(), 5);
        assert!(codes.verify_and_consume(&first_code));
        assert_eq!(codes.remaining(), 4);
        assert!(!codes.verify_and_consume(&first_code)); // Already used
    }

    #[test]
    fn backup_code_accepts_transcription_variants() {
        let generated = BackupCodes::generate(1);
        let mut codes = generated.stored.clone();
        let variant: String = generated.plaintext()[0]
            .chars()
            .filter(|c| *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        assert!(codes.verify_and_consume(&variant));
    }

    #[test]
    fn test_backup_code_rejects_unknown_code() {
        let mut codes = BackupCodes::generate(5).stored;
        assert!(!codes.verify_and_consume("0000-0000"));
        assert_eq!(codes.remaining(), 5);
    }

    #[test]
    fn test_backup_code_consumes_any_matching_position() {
        let generated = BackupCodes::generate(5);
        let mut codes = generated.stored.clone();
        let last_code = generated.plaintext()[4].clone();

        assert!(codes.verify_and_consume(&last_code));
        assert_eq!(codes.remaining(), 4);
        assert!(!codes.verify_and_consume(&last_code));
    }
}
