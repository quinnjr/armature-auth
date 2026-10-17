//! Authentication and authorization for Armature.
//!
//! This crate provides comprehensive authentication and authorization
//! capabilities including JWT, OAuth2, SAML, password hashing, and guards.
//!
//! ## Features
//!
//! - 🔐 **JWT Authentication** - Token-based auth with `armature-jwt`
//! - 🌐 **OAuth2** - Google, Auth0, Microsoft, AWS Cognito, Okta
//! - 🔑 **SAML** - Enterprise SAML 2.0 authentication (requires `saml` feature)
//! - 🔒 **Password Hashing** - Argon2 (default) and bcrypt
//! - 🛡️ **Guards** - Route protection with auth and role guards
//! - 👤 **User Context** - Request-scoped user information
//!
//! ## Cargo Features
//!
//! - `default` - Core authentication (JWT, OAuth2, password hashing)
//! - `saml` - SAML 2.0 support (requires openssl/xmlsec1 system libraries)
//!
//! ### SAML System Requirements
//!
//! The `saml` feature requires system libraries for XML signature verification:
//! - **Ubuntu/Debian**: `apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl`
//! - **macOS**: `brew install libxmlsec1`
//! - **Windows**: Not recommended (complex setup)
//!
//! ## Quick Start - Password Authentication
//!
//! ```
//! use armature_auth::{AuthService, PasswordHasher, PasswordVerifier};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth_service = AuthService::new();
//!
//! // Hash a password
//! let hash = auth_service.hash_password("secret123")?;
//!
//! // Verify password
//! let is_valid = auth_service.verify_password("secret123", &hash)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## JWT Authentication
//!
//! ```no_run
//! use armature_auth::AuthService;
//! use armature_jwt::{JwtConfig, JwtManager};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create JWT manager. The HMAC secret must be >= 32 random bytes; weak or
//! // placeholder secrets are rejected.
//! let jwt_config = JwtConfig::new(std::env::var("JWT_SECRET")?)?;
//! let jwt_manager = JwtManager::new(jwt_config)?;
//!
//! // Create auth service with JWT
//! let auth_service = AuthService::with_jwt(jwt_manager);
//!
//! // JWT manager is now available
//! assert!(auth_service.jwt_manager().is_some());
//! # Ok(())
//! # }
//! ```
//!
//! ## OAuth2 - Google Example
//!
//! ```no_run
//! use armature_auth::{GoogleProvider, providers::GoogleConfig, OAuth2Provider};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = GoogleConfig::new(
//!     "client-id".to_string(),
//!     "client-secret".to_string(),
//!     "https://myapp.com/callback".to_string(),
//! );
//!
//! let provider = GoogleProvider::new(config)?;
//!
//! // Generate the authorization URL (PKCE S256 + state + OIDC nonce). Keep
//! // `pending` in the server-side session until the callback.
//! let (auth_url, pending) = provider.authorization_url()?;
//! println!("Redirect user to: {}", auth_url);
//!
//! // On the callback: pass the returned `code` and `state` with the stored
//! // `pending`. State is checked in constant time and the id_token verified.
//! # let (code, returned_state) = ("auth-code".to_string(), pending.state().to_string());
//! let token = provider.exchange_code(code, &returned_state, pending).await?;
//! let user = provider.get_user_info(&token).await?;
//! println!("Signed in: {}", user.sub);
//! # Ok(())
//! # }
//! ```
//!
//! ## Route Guards
//!
//! The guards require a **verified** identity attached by
//! [`JwtAuthMiddleware`] (register it with `Application::use_middleware`,
//! which runs before guards); a bare
//! `Authorization` header is never enough. They implement both this crate's
//! [`Guard`] and [`armature_core::Guard`].
//!
//! ```ignore
//! use armature_auth::{AuthGuard, RoleGuard};
//! use armature_core::{Controller, Get};
//!
//! #[controller("/admin")]
//! struct AdminController;
//!
//! impl AdminController {
//!     // Require authentication
//!     #[get("/dashboard")]
//!     #[guard(AuthGuard)]
//!     async fn dashboard(&self) -> Result<HttpResponse, Error> {
//!         Ok(HttpResponse::ok())
//!     }
//!
//!     // Require specific role
//!     #[get("/users")]
//!     #[guard(RoleGuard::new("admin"))]
//!     async fn users(&self) -> Result<HttpResponse, Error> {
//!         Ok(HttpResponse::ok())
//!     }
//! }
//! ```
//!
//! ## SAML Authentication
//!
//! ```ignore
//! use armature_auth::{SamlServiceProvider, SamlConfig, IdpMetadata};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SamlConfig::new(
//!     "https://myapp.com".to_string(),
//!     "https://myapp.com/callback".to_string(),
//!     // IdP metadata must be provided as XML; URL-based fetching is not yet supported.
//!     IdpMetadata::Xml("<EntityDescriptor>...</EntityDescriptor>".to_string()),
//! );
//!
//! // Multi-instance deployments: `.with_replay_cache(shared_cache)`.
//! let provider = SamlServiceProvider::new("my-sp".to_string(), config)?;
//!
//! // Generate SAML auth request; store `request_id` (and `relay_state`) in
//! // the user's session.
//! let auth_request = provider.create_auth_request()?;
//!
//! // On the ACS callback: correlated validation + replay protection.
//! # let (saml_response, received_relay) = (String::new(), None::<String>);
//! let assertion = provider
//!     .validate_response(
//!         &saml_response,
//!         &auth_request.request_id,
//!         auth_request.relay_state.as_deref(),
//!         received_relay.as_deref(),
//!     )
//!     .await?;
//! # Ok(())
//! # }
//! ```

pub mod api_key;
pub mod error;
pub mod guard;
pub mod middleware;
pub mod oauth2;
pub mod password;
pub mod passwordless;
pub mod providers;
#[cfg(feature = "saml")]
pub mod saml;
pub mod strategy;
#[cfg(feature = "two-factor")]
pub mod two_factor;
pub mod user;

pub use api_key::{ApiKey, ApiKeyError, ApiKeyManager, ApiKeyStore, GeneratedApiKey};
pub use error::{AuthError, Result};
pub use guard::{AuthGuard, Guard, PermissionGuard, RoleGuard};
pub use middleware::{JwtAuthMiddleware, RejectedCredentials};
pub use oauth2::{OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth};
pub use password::{PasswordHasher, PasswordVerifier};
pub use passwordless::{
    InMemoryMagicLinkStore, IssuedMagicLink, MagicLinkStore, MagicLinkToken, PasswordlessError,
    WebAuthnManager, redeem_magic_link,
};
#[cfg(feature = "saml")]
pub use saml::{
    AssertionReplayCache, ContactInfo, IdpMetadata, InMemoryReplayCache, SamlAssertion,
    SamlAuthRequest, SamlConfig, SamlProvider, SamlServiceProvider,
};
pub use strategy::{AuthStrategy, JwtStrategy, LocalStrategy};
#[cfg(feature = "two-factor")]
pub use two_factor::{BackupCodes, GeneratedBackupCodes, TotpSecret, TwoFactorError};
pub use user::{AuthUser, UserContext};

// Re-export providers
pub use providers::{
    Auth0Provider, AwsCognitoProvider, DiscordProvider, DiscordUser, GitHubProvider, GitHubUser,
    GitLabProvider, GitLabUser, GoogleProvider, LinkedInProvider, LinkedInUser,
    MicrosoftEntraProvider, OktaProvider,
};

use armature_jwt::JwtManager;
use armature_log::{debug, trace};
use std::sync::Arc;

/// Authentication service for managing user authentication.
///
/// Provides password hashing, verification, and optional JWT token management.
///
/// # Examples
///
/// Basic password authentication:
///
/// ```
/// use armature_auth::{AuthService, PasswordVerifier};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let service = AuthService::new();
///
/// // Hash password
/// let hash = service.hash_password("mypassword")?;
///
/// // Verify password
/// assert!(service.verify_password("mypassword", &hash)?);
/// assert!(!service.verify_password("wrongpassword", &hash)?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AuthService {
    jwt_manager: Option<Arc<JwtManager>>,
    password_hasher: PasswordHasher,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new() -> Self {
        debug!("Creating new AuthService");
        Self {
            jwt_manager: None,
            password_hasher: PasswordHasher::default(),
        }
    }

    /// Create with JWT manager
    pub fn with_jwt(jwt_manager: JwtManager) -> Self {
        debug!("Creating AuthService with JWT manager");
        Self {
            jwt_manager: Some(Arc::new(jwt_manager)),
            password_hasher: PasswordHasher::default(),
        }
    }

    /// Set password hasher
    pub fn with_password_hasher(mut self, hasher: PasswordHasher) -> Self {
        debug!("Setting password hasher");
        self.password_hasher = hasher;
        self
    }

    /// Hash a password
    pub fn hash_password(&self, password: &str) -> Result<String> {
        trace!("Hashing password");
        self.password_hasher.hash(password)
    }

    /// Verify a password
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        trace!("Verifying password");
        self.password_hasher.verify(password, hash)
    }

    /// Get JWT manager
    pub fn jwt_manager(&self) -> Option<&JwtManager> {
        self.jwt_manager.as_deref()
    }

    /// Validate authentication
    pub fn validate<T: AuthUser>(&self, user: &T) -> Result<()> {
        debug!("Validating user authentication");
        if !user.is_active() {
            debug!("User is inactive");
            return Err(AuthError::InactiveUser);
        }

        trace!("User validation successful");
        Ok(())
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}

/// Prelude for common imports.
///
/// ```
/// use armature_auth::prelude::*;
/// ```
pub mod prelude {
    pub use crate::AuthService;
    pub use crate::api_key::{ApiKey, ApiKeyManager, ApiKeyStore, GeneratedApiKey};
    pub use crate::error::{AuthError, Result};
    pub use crate::guard::{AuthGuard, Guard, PermissionGuard, RoleGuard};
    pub use crate::middleware::{JwtAuthMiddleware, RejectedCredentials};
    pub use crate::oauth2::{OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth};
    pub use crate::password::{PasswordHasher, PasswordVerifier};
    pub use crate::strategy::{AuthStrategy, JwtStrategy, LocalStrategy};
    pub use crate::user::{AuthUser, UserContext};

    // OAuth2 providers
    pub use crate::providers::{
        Auth0Provider, AwsCognitoProvider, DiscordProvider, GitHubProvider, GitLabProvider,
        GoogleProvider, LinkedInProvider, MicrosoftEntraProvider, OktaProvider,
    };

    #[cfg(feature = "saml")]
    pub use crate::saml::{
        AssertionReplayCache, InMemoryReplayCache, SamlConfig, SamlProvider, SamlServiceProvider,
    };

    #[cfg(feature = "two-factor")]
    pub use crate::two_factor::{BackupCodes, GeneratedBackupCodes, TotpSecret, TwoFactorError};
}

/// Secrets shared by this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    /// Passes `armature_jwt::config::validate_hmac_secret`.
    pub const TEST_JWT_SECRET: &str = "kV9pQ2xR7tW4yZ1bN6mC3fH8jL5sD0gA";
    /// A second, different valid secret.
    pub const OTHER_TEST_JWT_SECRET: &str = "Xw3Ee8Rr1Tt6Yy9Uu2Ii5Oo0Pp7Aa4Ss";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let service = AuthService::new();

        let password = "test-password-123";
        let hash = service.hash_password(password).unwrap();

        assert!(service.verify_password(password, &hash).unwrap());
        assert!(!service.verify_password("wrong-password", &hash).unwrap());
    }
}
