//! Token-verifying authentication middleware.
//!
//! This module ships [`JwtAuthMiddleware`], the concrete
//! [`armature_core::Middleware`] that turns a raw `Authorization: Bearer …`
//! header into verified, request-scoped identity. It is the layer the
//! fail-closed guards ([`crate::RoleGuard`], [`crate::PermissionGuard`] and
//! `armature_core::RolesGuard`) expect to run *before* them: those guards read
//! the [`UserContext`] / [`armature_core::RequestRoles`] extensions that this
//! middleware inserts, and reject any request where they are absent.
//!
//! Without this middleware (or an equivalent that populates the same
//! extensions), role- and permission-protected routes deny everyone, because
//! a bare bearer token is never treated as proof of any role.
//!
//! Register it with `armature_core::Application::use_middleware`, which runs
//! global middleware **before** module/controller/route guards, so the
//! guards see the verified identity.
//!
//! # Two modes
//!
//! The middleware supports two policies, selected by the `require_auth` flag:
//!
//! - **Required auth** (default, [`JwtAuthMiddleware::new`]): a missing or
//!   invalid/expired token is rejected immediately with `401 Unauthorized`;
//!   the downstream handler never runs. Use this to protect an entire route
//!   subtree where anonymous access is never allowed.
//! - **Optional auth** ([`JwtAuthMiddleware::optional`]): a valid token is
//!   verified and its identity attached; a missing token is passed through
//!   with **no** identity attached. An *invalid* token is never forwarded as
//!   if it were a credential: the `Authorization` header is stripped and a
//!   [`RejectedCredentials`] marker extension is inserted instead, so nothing
//!   downstream (e.g. a header-presence check) can mistake it for an
//!   authenticated request. The request still reaches the handler chain, so a
//!   per-route guard downstream makes the final allow/deny decision. Use this
//!   when some routes behind the middleware are public and others are
//!   guarded.
//!
//! In both modes a *valid* token results in a [`UserContext`] and a
//! [`RequestRoles`] extension being inserted before the next handler runs.
//! Only **access** tokens are accepted: refresh tokens minted by
//! [`JwtManager::generate_token_pair`] (identified by their `token_use` claim
//! and `typ` header) are rejected like any other invalid token, see
//! [`JwtManager::verify_access`]. A token with no subject claim is rejected
//! too, as is a request carrying more than one `Authorization` header.

use crate::UserContext;
use armature_core::{
    Error, HttpRequest, HttpResponse, Middleware, Next, RequestRoles, VerifiedIdentity,
};
use armature_jwt::JwtManager;
use armature_log::{debug, trace};
use async_trait::async_trait;

/// Marker extension inserted by [`JwtAuthMiddleware`] in optional mode when
/// the request presented a credential that failed verification (bad
/// signature, expired, refresh token, malformed or duplicated header).
///
/// The offending `Authorization` header has already been removed. Handlers on
/// public routes can use this to respond `401` with a `WWW-Authenticate`
/// challenge rather than silently serving anonymous content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectedCredentials;

/// What a request's `Authorization` header contained.
enum Credential {
    /// No `Authorization` header.
    Absent,
    /// A single `Bearer` credential.
    Bearer(String),
    /// Present but unusable: not `Bearer`, empty, non-UTF-8 or repeated.
    Malformed,
}

/// Middleware that verifies a JWT bearer token and populates request-scoped
/// identity for the authorization guards.
///
/// On a valid token it inserts two extensions into the request:
///
/// 1. A [`UserContext`] built from the configured `subject`, `roles` and
///    `permissions` claims (with the full claim set preserved in
///    [`UserContext::metadata`]). This drives [`crate::RoleGuard`] and
///    [`crate::PermissionGuard`].
/// 2. An [`armature_core::RequestRoles`] built from the same roles, so the
///    core `armature_core::RolesGuard` works too.
/// 3. An [`armature_core::VerifiedIdentity`] carrying the subject, which the
///    core `armature_core::AuthenticationGuard` requires.
///
/// # Configuration
///
/// The claim names are configurable (defaults: `sub`, `roles`, `permissions`)
/// via [`with_subject_claim`](Self::with_subject_claim),
/// [`with_roles_claim`](Self::with_roles_claim) and
/// [`with_permissions_claim`](Self::with_permissions_claim). The verification
/// key/algorithm live in the [`JwtManager`] the middleware holds.
///
/// # Example: protect a route with `RoleGuard`
///
/// A request carrying a validly-signed token with the `admin` role passes the
/// guard; a token without that role (or no token at all) is denied.
///
/// ```
/// use armature_auth::{JwtAuthMiddleware, RoleGuard, Guard};
/// use armature_core::{HttpRequest, HttpResponse, Middleware, Next};
/// use armature_jwt::{JwtConfig, JwtManager};
/// use serde_json::json;
/// use std::pin::Pin;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let rt = tokio::runtime::Runtime::new()?;
/// rt.block_on(async {
///     let manager = JwtManager::new(JwtConfig::new(
///         "kV9pQ2xR7tW4yZ1bN6mC3fH8jL5sD0gA".to_string(), // load from a secret store
///     )?)?;
///     let exp = chrono::Utc::now().timestamp() + 3600;
///
///     // Mint a token that carries the `admin` role.
///     let token = manager.sign(&json!({
///         "sub": "user123",
///         "roles": ["admin"],
///         "exp": exp,
///     }))?;
///
///     // The middleware verifies the token; the guard authorizes the role.
///     let middleware = JwtAuthMiddleware::new(manager);
///     let guard = RoleGuard::any(vec!["admin".to_string()]);
///
///     // `next` stands in for the guarded handler: it applies the guard to
///     // the (now identity-carrying) request.
///     let make_next = |guard: RoleGuard| -> Next {
///         Box::new(move |req: HttpRequest| {
///             Box::pin(async move {
///                 match Guard::can_activate(&guard, &req).await {
///                     Ok(true) => Ok(HttpResponse::ok()),
///                     _ => Ok(HttpResponse::forbidden()),
///                 }
///             }) as Pin<Box<_>>
///         })
///     };
///
///     // Authenticated request WITH the right role -> 200.
///     let mut req = HttpRequest::new("GET", "/admin".to_string());
///     req.headers
///         .insert("authorization".to_string(), format!("Bearer {token}"));
///     let resp = middleware.handle(req, make_next(guard.clone())).await.unwrap();
///     assert_eq!(resp.status, 200);
///
///     // No token, require_auth mode -> 401 before the guard even runs.
///     let req = HttpRequest::new("GET", "/admin".to_string());
///     let resp = middleware.handle(req, make_next(guard.clone())).await.unwrap();
///     assert_eq!(resp.status, 401);
///     Ok::<(), Box<dyn std::error::Error>>(())
/// })?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct JwtAuthMiddleware {
    manager: JwtManager,
    require_auth: bool,
    subject_claim: String,
    roles_claim: String,
    permissions_claim: String,
}

impl JwtAuthMiddleware {
    /// Create a middleware in **required-auth** mode.
    ///
    /// Missing or invalid tokens are rejected with `401 Unauthorized` before
    /// the downstream handler runs. Claim names default to `sub`, `roles` and
    /// `permissions`.
    pub fn new(manager: JwtManager) -> Self {
        Self {
            manager,
            require_auth: true,
            subject_claim: "sub".to_string(),
            roles_claim: "roles".to_string(),
            permissions_claim: "permissions".to_string(),
        }
    }

    /// Create a middleware in **optional-auth** mode.
    ///
    /// A valid token is verified and its identity attached; a missing or
    /// invalid token passes through with no identity attached, leaving the
    /// allow/deny decision to a downstream guard.
    pub fn optional(manager: JwtManager) -> Self {
        Self {
            require_auth: false,
            ..Self::new(manager)
        }
    }

    /// Toggle the require-auth policy.
    ///
    /// `true` (the default from [`new`](Self::new)) rejects missing/invalid
    /// tokens with `401`; `false` lets them through for a downstream guard to
    /// decide (see [`optional`](Self::optional)).
    pub fn require_auth(mut self, require_auth: bool) -> Self {
        self.require_auth = require_auth;
        self
    }

    /// Override the claim name used for the user's subject/id (default `sub`).
    pub fn with_subject_claim(mut self, claim: impl Into<String>) -> Self {
        self.subject_claim = claim.into();
        self
    }

    /// Override the claim name used for the user's roles (default `roles`).
    pub fn with_roles_claim(mut self, claim: impl Into<String>) -> Self {
        self.roles_claim = claim.into();
        self
    }

    /// Override the claim name used for the user's permissions
    /// (default `permissions`).
    pub fn with_permissions_claim(mut self, claim: impl Into<String>) -> Self {
        self.permissions_claim = claim.into();
        self
    }

    /// Classify the request's `Authorization` header.
    ///
    /// Header lookup is case-insensitive, and a repeated header is refused
    /// rather than resolved by picking one (see `HeaderMap::get_unique`).
    fn credential(req: &HttpRequest) -> Credential {
        let value = match req.headers.get_unique("authorization") {
            Ok(None) => return Credential::Absent,
            Ok(Some(value)) => value,
            Err(_) => return Credential::Malformed,
        };
        let Ok(value) = std::str::from_utf8(value) else {
            return Credential::Malformed;
        };
        let token = match value.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
            _ => return Credential::Malformed,
        };
        if token.is_empty() {
            Credential::Malformed
        } else {
            Credential::Bearer(token.to_string())
        }
    }

    /// Verify `token` as an access token and build a [`UserContext`] from
    /// its claims.
    fn context_from_token(&self, token: &str) -> Option<UserContext> {
        // `verify_access` also rejects refresh tokens, which carry the same
        // identity and roles but a much longer lifetime.
        let claims: serde_json::Value = match self.manager.verify_access(token) {
            Ok(claims) => claims,
            Err(e) => {
                debug!("JWT verification failed: {}", e);
                return None;
            }
        };

        let subject = match claims
            .get(&self.subject_claim)
            .and_then(serde_json::Value::as_str)
        {
            Some(subject) if !subject.is_empty() => subject.to_string(),
            _ => {
                debug!("JWT has no `{}` claim; rejecting", self.subject_claim);
                return None;
            }
        };

        let roles = string_list(claims.get(&self.roles_claim));
        let permissions = string_list(claims.get(&self.permissions_claim));

        trace!(
            "JWT verified for subject={subject}, {} role(s), {} permission(s)",
            roles.len(),
            permissions.len()
        );

        Some(
            UserContext::new(subject)
                .with_roles(roles)
                .with_permissions(permissions)
                .with_metadata(claims),
        )
    }

    /// Attach a verified [`UserContext`] (and matching [`RequestRoles`]) to a
    /// request's extensions.
    fn attach(req: &mut HttpRequest, context: UserContext) {
        let roles = RequestRoles::new(context.roles.clone());
        let identity = VerifiedIdentity::new(context.user_id.clone());
        req.extensions.insert(context);
        req.extensions.insert(roles);
        req.extensions.insert(identity);
    }
}

#[async_trait]
impl Middleware for JwtAuthMiddleware {
    async fn handle(&self, mut req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        let context = match Self::credential(&req) {
            Credential::Absent => {
                if self.require_auth {
                    debug!("Rejecting request with no bearer token (require_auth)");
                    return Ok(HttpResponse::unauthorized());
                }
                return next(req).await;
            }
            Credential::Bearer(token) => self.context_from_token(&token),
            Credential::Malformed => None,
        };

        match context {
            Some(context) => {
                Self::attach(&mut req, context);
                next(req).await
            }
            // Credential present but invalid/expired/refresh/malformed.
            None if self.require_auth => {
                debug!("Rejecting request with invalid credential (require_auth)");
                Ok(HttpResponse::unauthorized())
            }
            None => {
                // Optional mode: never forward a rejected credential as if it
                // were one. Strip it and flag the request instead.
                req.headers.remove_all("authorization");
                req.extensions.insert(RejectedCredentials);
                next(req).await
            }
        }
    }
}

/// Coerce a JSON claim value into a list of strings.
///
/// Accepts a JSON array of strings (`["a", "b"]`) or a single string (`"a"`),
/// producing an empty list for anything else (including absence).
fn string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OTHER_TEST_JWT_SECRET, TEST_JWT_SECRET};
    use crate::{Guard, RoleGuard};
    use armature_core::guard::{AuthenticationGuard, Guard as CoreGuard, GuardContext, RolesGuard};
    use armature_jwt::JwtConfig;
    use serde_json::json;
    use std::pin::Pin;

    fn manager() -> JwtManager {
        JwtManager::new(JwtConfig::new(TEST_JWT_SECRET.to_string()).unwrap()).unwrap()
    }

    fn token_with(manager: &JwtManager, claims: serde_json::Value) -> String {
        manager.sign(&claims).unwrap()
    }

    fn admin_token(manager: &JwtManager) -> String {
        let exp = chrono::Utc::now().timestamp() + 3600;
        token_with(
            manager,
            json!({ "sub": "user123", "roles": ["admin", "user"], "permissions": ["read"], "exp": exp }),
        )
    }

    fn bearer_request(token: &str) -> HttpRequest {
        let mut req = HttpRequest::new("GET", "/admin".to_string());
        req.headers
            .insert("authorization", format!("Bearer {token}"));
        req
    }

    /// A `next` that applies an armature-auth `RoleGuard` to the request.
    fn role_guard_next(guard: RoleGuard) -> Next {
        Box::new(move |req: HttpRequest| {
            Box::pin(async move {
                match Guard::can_activate(&guard, &req).await {
                    Ok(true) => Ok(HttpResponse::ok()),
                    _ => Ok(HttpResponse::forbidden()),
                }
            }) as Pin<Box<_>>
        })
    }

    #[tokio::test]
    async fn valid_jwt_with_matching_role_passes_role_guard() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::new(manager);
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn valid_jwt_without_role_is_denied() {
        let manager = manager();
        let exp = chrono::Utc::now().timestamp() + 3600;
        let token = token_with(
            &manager,
            json!({ "sub": "u", "roles": ["user"], "exp": exp }),
        );
        let mw = JwtAuthMiddleware::new(manager);
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        // Verified identity attached, but the role requirement is not met.
        assert_eq!(resp.status, 403);
    }

    #[tokio::test]
    async fn no_token_in_require_auth_mode_returns_401() {
        let mw = JwtAuthMiddleware::new(manager());
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let req = HttpRequest::new("GET", "/admin".to_string());
        let resp = mw.handle(req, next).await.unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn invalid_token_in_require_auth_mode_returns_401() {
        let mw = JwtAuthMiddleware::new(manager());
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw
            .handle(bearer_request("not.a.valid.token"), next)
            .await
            .unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn token_signed_with_wrong_secret_is_rejected() {
        let signer =
            JwtManager::new(JwtConfig::new(OTHER_TEST_JWT_SECRET.to_string()).unwrap()).unwrap();
        let token = admin_token(&signer);

        // Verifier uses a different secret -> signature check fails.
        let mw = JwtAuthMiddleware::new(manager());
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn no_token_in_optional_mode_passes_through_to_guard_which_denies() {
        let mw = JwtAuthMiddleware::optional(manager());
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        // No token: optional mode attaches nothing and forwards to the guard,
        // which fails closed because no verified identity is present.
        let req = HttpRequest::new("GET", "/admin".to_string());
        let resp = mw.handle(req, next).await.unwrap();
        assert_eq!(resp.status, 403);
    }

    /// A `next` that reports what reached the handler: whether an
    /// Authorization header survived and whether the request was flagged.
    fn inspecting_next() -> Next {
        Box::new(move |req: HttpRequest| {
            Box::pin(async move {
                let header = req.headers.get("authorization").is_some();
                let flagged = req.extensions.get::<RejectedCredentials>().is_some();
                let identity = req.extensions.get::<UserContext>().is_some();
                Ok(HttpResponse::ok()
                    .with_header("x-had-auth".to_string(), header.to_string())
                    .with_header("x-flagged".to_string(), flagged.to_string())
                    .with_header("x-identity".to_string(), identity.to_string()))
            }) as Pin<Box<_>>
        })
    }

    #[tokio::test]
    async fn optional_mode_strips_and_flags_invalid_token() {
        let mw = JwtAuthMiddleware::optional(manager());
        let resp = mw
            .handle(bearer_request("not.a.valid.token"), inspecting_next())
            .await
            .unwrap();
        assert_eq!(
            resp.headers.get("x-had-auth").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            resp.headers.get("x-flagged").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            resp.headers.get("x-identity").map(String::as_str),
            Some("false")
        );
    }

    #[tokio::test]
    async fn optional_mode_strips_and_flags_malformed_header() {
        let mw = JwtAuthMiddleware::optional(manager());
        let mut req = HttpRequest::new("GET", "/".to_string());
        req.headers
            .insert("authorization", "Basic YWxhZGRpbjpvcGVu".to_string());
        let resp = mw.handle(req, inspecting_next()).await.unwrap();
        assert_eq!(
            resp.headers.get("x-had-auth").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            resp.headers.get("x-flagged").map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn refresh_token_is_rejected_as_bearer() {
        let manager = manager();
        let pair = manager
            .generate_token_pair(&json!({ "sub": "user123", "roles": ["admin"] }))
            .unwrap();
        let mw = JwtAuthMiddleware::new(manager.clone());

        let resp = mw
            .handle(
                bearer_request(&pair.refresh_token),
                role_guard_next(RoleGuard::any(vec!["admin".to_string()])),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 401, "refresh token must not authenticate");

        let resp = mw
            .handle(
                bearer_request(&pair.access_token),
                role_guard_next(RoleGuard::any(vec!["admin".to_string()])),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 200);

        // Optional mode: flagged, not authenticated.
        let mw = JwtAuthMiddleware::optional(manager);
        let resp = mw
            .handle(bearer_request(&pair.refresh_token), inspecting_next())
            .await
            .unwrap();
        assert_eq!(
            resp.headers.get("x-identity").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            resp.headers.get("x-flagged").map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn token_without_subject_is_rejected() {
        let manager = manager();
        let exp = chrono::Utc::now().timestamp() + 3600;
        let token = token_with(&manager, json!({ "roles": ["admin"], "exp": exp }));
        let mw = JwtAuthMiddleware::new(manager);
        let resp = mw
            .handle(
                bearer_request(&token),
                role_guard_next(RoleGuard::any(vec!["admin".to_string()])),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn duplicate_authorization_headers_are_rejected() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::new(manager);
        let mut req = bearer_request(&token);
        req.headers
            .append("authorization", format!("Bearer {token}"));
        let resp = mw
            .handle(
                req,
                role_guard_next(RoleGuard::any(vec!["admin".to_string()])),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn bearer_scheme_is_case_insensitive() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::new(manager);
        let mut req = HttpRequest::new("GET", "/admin".to_string());
        req.headers
            .insert("Authorization", format!("bearer {token}"));
        let resp = mw
            .handle(
                req,
                role_guard_next(RoleGuard::any(vec!["admin".to_string()])),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn optional_mode_attaches_context_when_token_valid() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::optional(manager);
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn populates_core_request_roles_for_core_roles_guard() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::new(manager);

        // Downstream uses armature_core::RolesGuard, which reads RequestRoles.
        let next: Next = Box::new(move |req: HttpRequest| {
            Box::pin(async move {
                let guard = RolesGuard::new(vec!["admin".to_string()]);
                let ctx = GuardContext::new(req);
                match guard.can_activate(&ctx).await {
                    Ok(true) => Ok(HttpResponse::ok()),
                    _ => Ok(HttpResponse::forbidden()),
                }
            }) as Pin<Box<_>>
        });

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn populates_verified_identity_for_core_authentication_guard() {
        let manager = manager();
        let token = admin_token(&manager);
        let mw = JwtAuthMiddleware::new(manager);

        let next: Next = Box::new(move |req: HttpRequest| {
            Box::pin(async move {
                assert_eq!(
                    req.extensions
                        .get::<VerifiedIdentity>()
                        .map(|i| i.subject.as_str()),
                    Some("user123")
                );
                let ctx = GuardContext::new(req);
                match AuthenticationGuard.can_activate(&ctx).await {
                    Ok(true) => Ok(HttpResponse::ok()),
                    _ => Ok(HttpResponse::forbidden()),
                }
            }) as Pin<Box<_>>
        });

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn configurable_claim_names_are_honoured() {
        let manager = manager();
        let exp = chrono::Utc::now().timestamp() + 3600;
        let token = token_with(
            &manager,
            json!({ "user_id": "u1", "authorities": ["admin"], "exp": exp }),
        );
        let mw = JwtAuthMiddleware::new(manager)
            .with_subject_claim("user_id")
            .with_roles_claim("authorities");
        let next = role_guard_next(RoleGuard::any(vec!["admin".to_string()]));

        let resp = mw.handle(bearer_request(&token), next).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn string_list_accepts_array_and_scalar() {
        assert_eq!(
            string_list(Some(&json!(["a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(string_list(Some(&json!("solo"))), vec!["solo".to_string()]);
        assert!(string_list(Some(&json!(42))).is_empty());
        assert!(string_list(None).is_empty());
    }
}
