// Authentication guards

use crate::{AuthError, AuthUser, Result, UserContext};
use armature_core::guard::{Guard as CoreGuard, GuardContext};
use armature_core::{HttpRequest, RequestRoles};
use async_trait::async_trait;

/// Guard trait for protecting routes
///
/// Every guard in this crate also implements [`armature_core::Guard`], so it
/// can be registered with core routing directly. If both traits are in scope,
/// disambiguate calls with `Guard::can_activate(&guard, &req)`.
#[async_trait]
pub trait Guard: Send + Sync {
    /// Check if the request can proceed
    async fn can_activate(&self, request: &HttpRequest) -> Result<bool>;
}

/// Map an armature-auth error onto the core error the router turns into a
/// response: missing identity is `401`, everything else is `403`.
fn to_core_error(err: AuthError) -> armature_core::Error {
    match err {
        AuthError::Unauthorized
        | AuthError::InvalidToken(_)
        | AuthError::TokenExpired
        | AuthError::JwtError(_) => armature_core::Error::Unauthorized(err.to_string()),
        other => armature_core::Error::Forbidden(other.to_string()),
    }
}

/// Implement [`armature_core::Guard`] in terms of this crate's [`Guard`].
macro_rules! impl_core_guard {
    ($ty:ty) => {
        #[async_trait]
        impl CoreGuard for $ty {
            async fn can_activate(
                &self,
                context: &GuardContext,
            ) -> std::result::Result<bool, armature_core::Error> {
                Guard::can_activate(self, &context.request)
                    .await
                    .map_err(to_core_error)
            }
        }
    };
}

/// Authentication guard — requires a **verified** identity on the request.
///
/// Passes only when a [`UserContext`] extension is present, i.e. an
/// authentication layer has verified the caller's credential and attached the
/// result — in practice [`crate::JwtAuthMiddleware`], which must run before
/// this guard. The mere presence of an `Authorization` header proves nothing
/// and is not consulted: a request carrying `Authorization: Bearer x` but no
/// verified identity is rejected with [`AuthError::Unauthorized`].
#[derive(Clone)]
pub struct AuthGuard;

impl AuthGuard {
    pub fn new() -> Self {
        Self
    }

    /// Extract the verified user identity from the request.
    ///
    /// Reads the `T` extension attached by an authentication layer that has
    /// already verified the caller's token — in practice
    /// [`crate::JwtAuthMiddleware`], which inserts a [`UserContext`] built
    /// from the token's verified claims. Returns
    /// [`AuthError::Unauthorized`] if no such extension is present, e.g.
    /// because `JwtAuthMiddleware` (or an equivalent) did not run first.
    pub fn extract_user<T: AuthUser + Clone + 'static>(&self, request: &HttpRequest) -> Result<T> {
        request
            .extensions
            .get::<T>()
            .cloned()
            .ok_or(AuthError::Unauthorized)
    }
}

impl Default for AuthGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for AuthGuard {
    async fn can_activate(&self, request: &HttpRequest) -> Result<bool> {
        match request.extensions.get::<UserContext>() {
            Some(_) => Ok(true),
            None => Err(AuthError::Unauthorized),
        }
    }
}

impl_core_guard!(AuthGuard);

/// Role-based authorization guard.
///
/// Requires verified role information attached to the request by an
/// authentication layer that has already validated the caller's token. The
/// intended layer is the shipped [`crate::JwtAuthMiddleware`]: register it
/// ahead of the guarded route so it verifies the JWT and populates the
/// extensions this guard reads. The guard looks for, in order:
///
/// 1. A [`UserContext`] in [`HttpRequest::extensions`], as produced by
///    [`crate::JwtAuthMiddleware`] from the token's claims after signature
///    verification.
/// 2. An [`armature_core::RequestRoles`] extension (the same mechanism used
///    by `armature_core::RolesGuard`, also populated by
///    [`crate::JwtAuthMiddleware`]).
///
/// The guard fails closed: with neither extension present the request is
/// rejected as unauthenticated, whatever headers it carries. An **empty**
/// role list (`RoleGuard::any(vec![])`) means "any authenticated caller", not
/// "anyone": it still requires a verified identity.
#[derive(Clone)]
pub struct RoleGuard {
    required_roles: Vec<String>,
    require_all: bool,
}

impl RoleGuard {
    /// Create a guard that requires ANY of the roles
    pub fn any(roles: Vec<String>) -> Self {
        Self {
            required_roles: roles,
            require_all: false,
        }
    }

    /// Create a guard that requires ALL of the roles
    pub fn all(roles: Vec<String>) -> Self {
        Self {
            required_roles: roles,
            require_all: true,
        }
    }

    /// Check if user has required roles
    pub fn check_roles<T: AuthUser>(&self, user: &T) -> bool {
        let role_refs: Vec<&str> = self.required_roles.iter().map(|s| s.as_str()).collect();

        if self.require_all {
            user.has_all_roles(&role_refs)
        } else {
            user.has_any_role(&role_refs)
        }
    }
}

impl RoleGuard {
    /// Check the required roles against a plain role list (e.g. from a
    /// [`RequestRoles`] extension).
    fn check_role_list(&self, roles: &RequestRoles) -> bool {
        if self.require_all {
            self.required_roles.iter().all(|role| roles.contains(role))
        } else {
            self.required_roles.iter().any(|role| roles.contains(role))
        }
    }
}

#[async_trait]
impl Guard for RoleGuard {
    async fn can_activate(&self, request: &HttpRequest) -> Result<bool> {
        // Prefer the richer UserContext attached by an authentication layer
        // after it verified the caller's token.
        if let Some(user) = request.extensions.get::<UserContext>() {
            return if self.required_roles.is_empty() || self.check_roles(user) {
                Ok(true)
            } else {
                Err(AuthError::Forbidden("Insufficient role".to_string()))
            };
        }

        // Fall back to armature-core's RequestRoles extension.
        if let Some(roles) = request.extensions.get::<RequestRoles>() {
            return if self.required_roles.is_empty() || self.check_role_list(roles) {
                Ok(true)
            } else {
                Err(AuthError::Forbidden("Insufficient role".to_string()))
            };
        }

        // Fail closed: no verified identity was attached to the request.
        Err(AuthError::Unauthorized)
    }
}

impl_core_guard!(RoleGuard);

/// Permission-based authorization guard.
///
/// Requires a verified [`UserContext`] (attached by
/// [`crate::JwtAuthMiddleware`] or an equivalent layer). An **empty**
/// permission list means "any authenticated caller": it still requires the
/// verified identity.
#[derive(Clone)]
pub struct PermissionGuard {
    required_permissions: Vec<String>,
    require_all: bool,
}

impl PermissionGuard {
    /// Create a guard that requires ANY of the permissions
    pub fn any(permissions: Vec<String>) -> Self {
        Self {
            required_permissions: permissions,
            require_all: false,
        }
    }

    /// Create a guard that requires ALL of the permissions
    pub fn all(permissions: Vec<String>) -> Self {
        Self {
            required_permissions: permissions,
            require_all: true,
        }
    }

    /// Check if user has required permissions
    pub fn check_permissions<T: AuthUser>(&self, user: &T) -> bool {
        if self.require_all {
            self.required_permissions
                .iter()
                .all(|perm| user.has_permission(perm))
        } else {
            self.required_permissions
                .iter()
                .any(|perm| user.has_permission(perm))
        }
    }
}

#[async_trait]
impl Guard for PermissionGuard {
    async fn can_activate(&self, request: &HttpRequest) -> Result<bool> {
        // Permissions are only carried by the richer UserContext that an
        // authentication layer attaches after verifying the caller's token.
        // Fail closed if it is absent.
        let user = request
            .extensions
            .get::<UserContext>()
            .ok_or(AuthError::Unauthorized)?;

        if self.required_permissions.is_empty() || self.check_permissions(user) {
            Ok(true)
        } else {
            Err(AuthError::Forbidden("Insufficient permissions".to_string()))
        }
    }
}

impl_core_guard!(PermissionGuard);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserContext;

    #[test]
    fn test_role_guard() {
        let user = UserContext::new("user123".to_string())
            .with_roles(vec!["admin".to_string(), "user".to_string()]);

        // Test ANY
        let guard = RoleGuard::any(vec!["admin".to_string()]);
        assert!(guard.check_roles(&user));

        let guard = RoleGuard::any(vec!["guest".to_string()]);
        assert!(!guard.check_roles(&user));

        // Test ALL
        let guard = RoleGuard::all(vec!["admin".to_string(), "user".to_string()]);
        assert!(guard.check_roles(&user));

        let guard = RoleGuard::all(vec!["admin".to_string(), "guest".to_string()]);
        assert!(!guard.check_roles(&user));
    }

    #[test]
    fn extract_user_returns_user_context_from_extension() {
        let guard = AuthGuard::new();
        let mut request = HttpRequest::new("GET", "/me".to_string());
        request
            .extensions
            .insert(UserContext::new("user123".to_string()).with_roles(vec!["admin".to_string()]));

        let user = guard.extract_user::<UserContext>(&request).unwrap();
        assert_eq!(user.user_id, "user123");
        assert!(user.has_role("admin"));
    }

    #[test]
    fn extract_user_errors_without_extension() {
        let guard = AuthGuard::new();
        let request = HttpRequest::new("GET", "/me".to_string());

        let result = guard.extract_user::<UserContext>(&request);
        assert!(matches!(result, Err(AuthError::Unauthorized)));
    }

    /// A request carrying an (unverified) bearer header but no verified
    /// identity — exactly what an attacker can send.
    fn header_only_request() -> HttpRequest {
        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request
            .headers
            .insert("authorization", "Bearer token123".to_string());
        request
    }

    fn verified_request(user: UserContext) -> HttpRequest {
        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request.extensions.insert(user);
        request
    }

    #[tokio::test]
    async fn auth_guard_rejects_bearer_header_without_verified_identity() {
        let guard = AuthGuard::new();
        assert!(matches!(
            Guard::can_activate(&guard, &header_only_request()).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn auth_guard_accepts_verified_identity() {
        let guard = AuthGuard::new();
        let request = verified_request(UserContext::new("u".to_string()));
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_role_guard_matching_role_passes() {
        let guard = RoleGuard::any(vec!["admin".to_string()]);

        // Via UserContext extension
        let request = verified_request(
            UserContext::new("user123".to_string()).with_roles(vec!["admin".to_string()]),
        );
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));

        // Via RequestRoles extension
        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request
            .extensions
            .insert(RequestRoles::new(["user", "admin"]));
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_role_guard_missing_role_denied() {
        let guard = RoleGuard::any(vec!["admin".to_string()]);

        // UserContext without the required role
        let request = verified_request(
            UserContext::new("user123".to_string()).with_roles(vec!["user".to_string()]),
        );
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Err(AuthError::Forbidden(_))
        ));

        // RequestRoles without the required role
        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request.extensions.insert(RequestRoles::new(["user"]));
        assert!(Guard::can_activate(&guard, &request).await.is_err());
    }

    #[tokio::test]
    async fn test_role_guard_require_all_via_request_roles() {
        let guard = RoleGuard::all(vec!["admin".to_string(), "user".to_string()]);

        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request.extensions.insert(RequestRoles::new(["admin"]));
        assert!(Guard::can_activate(&guard, &request).await.is_err());

        let mut request = HttpRequest::new("GET", "/admin".to_string());
        request
            .extensions
            .insert(RequestRoles::new(["admin", "user"]));
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_role_guard_no_roles_attached_denied() {
        let guard = RoleGuard::any(vec!["admin".to_string()]);

        // Bearer header present but no verified identity: must fail closed.
        assert!(matches!(
            Guard::can_activate(&guard, &header_only_request()).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn empty_role_requirement_still_requires_authentication() {
        let guard = RoleGuard::any(vec![]);

        // Header only: not authenticated.
        assert!(matches!(
            Guard::can_activate(&guard, &header_only_request()).await,
            Err(AuthError::Unauthorized)
        ));
        // No header at all.
        let request = HttpRequest::new("GET", "/admin".to_string());
        assert!(Guard::can_activate(&guard, &request).await.is_err());

        // Verified identity with no roles: allowed.
        let request = verified_request(UserContext::new("u".to_string()));
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_role_guard_unauthenticated_denied() {
        let guard = RoleGuard::any(vec!["admin".to_string()]);

        let request = HttpRequest::new("GET", "/admin".to_string());
        assert!(Guard::can_activate(&guard, &request).await.is_err());
    }

    #[test]
    fn test_permission_guard() {
        let user = UserContext::new("user123".to_string())
            .with_permissions(vec!["read".to_string(), "write".to_string()]);

        // Test ANY
        let guard = PermissionGuard::any(vec!["read".to_string()]);
        assert!(guard.check_permissions(&user));

        let guard = PermissionGuard::any(vec!["delete".to_string()]);
        assert!(!guard.check_permissions(&user));

        // Test ALL
        let guard = PermissionGuard::all(vec!["read".to_string(), "write".to_string()]);
        assert!(guard.check_permissions(&user));

        let guard = PermissionGuard::all(vec!["read".to_string(), "delete".to_string()]);
        assert!(!guard.check_permissions(&user));
    }

    #[tokio::test]
    async fn test_permission_guard_matching_permission_passes() {
        let guard = PermissionGuard::any(vec!["write".to_string()]);
        let request = verified_request(
            UserContext::new("user123".to_string())
                .with_permissions(vec!["read".to_string(), "write".to_string()]),
        );
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_permission_guard_missing_permission_denied() {
        let guard = PermissionGuard::any(vec!["delete".to_string()]);
        let request = verified_request(
            UserContext::new("user123".to_string()).with_permissions(vec!["read".to_string()]),
        );
        assert!(Guard::can_activate(&guard, &request).await.is_err());
    }

    #[tokio::test]
    async fn test_permission_guard_no_user_attached_denied() {
        let guard = PermissionGuard::any(vec!["read".to_string()]);
        // Bearer header but no UserContext attached: must fail closed.
        assert!(
            Guard::can_activate(&guard, &header_only_request())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn empty_permission_requirement_still_requires_authentication() {
        let guard = PermissionGuard::any(vec![]);
        assert!(matches!(
            Guard::can_activate(&guard, &header_only_request()).await,
            Err(AuthError::Unauthorized)
        ));
        let request = verified_request(UserContext::new("u".to_string()));
        assert!(matches!(
            Guard::can_activate(&guard, &request).await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn guards_plug_into_core_guard_trait() {
        use armature_core::Error as CoreError;

        // Header only -> 401 via core error mapping.
        let ctx = GuardContext::new(header_only_request());
        let res = CoreGuard::can_activate(&AuthGuard::new(), &ctx).await;
        assert!(matches!(res, Err(CoreError::Unauthorized(_))), "{res:?}");

        // Verified but wrong role -> 403.
        let ctx = GuardContext::new(verified_request(
            UserContext::new("u".to_string()).with_roles(vec!["user".to_string()]),
        ));
        let res = CoreGuard::can_activate(&RoleGuard::any(vec!["admin".to_string()]), &ctx).await;
        assert!(matches!(res, Err(CoreError::Forbidden(_))), "{res:?}");

        // Verified with the permission -> allowed, usable as a trait object.
        let ctx = GuardContext::new(verified_request(
            UserContext::new("u".to_string()).with_permissions(vec!["read".to_string()]),
        ));
        let guard: Box<dyn CoreGuard> = Box::new(PermissionGuard::any(vec!["read".to_string()]));
        assert!(matches!(guard.can_activate(&ctx).await, Ok(true)));
    }
}
