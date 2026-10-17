// Microsoft Entra (Azure AD) OAuth2 provider

use crate::oauth2::{
    GenericOAuth2Provider, OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth,
};
use crate::{AuthError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

/// Shape of the Microsoft Graph `/me` response.
///
/// Graph does not use OIDC-standard claim names (`id` rather than `sub`,
/// `mail`/`userPrincipalName` rather than `email`, `displayName` rather than
/// `name`), so it is deserialized separately and mapped into
/// [`OAuth2UserInfo`].
#[derive(Debug, Clone, Deserialize)]
struct GraphUser {
    id: String,
    #[serde(default)]
    mail: Option<String>,
    #[serde(default, rename = "userPrincipalName")]
    user_principal_name: Option<String>,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(flatten)]
    additional: HashMap<String, serde_json::Value>,
}

/// Build the user identity from the verified `id_token` claims plus the
/// Graph profile.
///
/// The stable, non-reassignable identity of an Entra user is the pair
/// (`tid`, `oid`): `oid` is only unique within a tenant, and `email` /
/// Graph `mail` are mutable, tenant-administered attributes (the "nOAuth"
/// account-takeover vector). So `sub` is `"{tid}:{oid}"`, and the e-mail is
/// always reported with `email_verified: Some(false)` — never key accounts on
/// it.
fn user_info_from(claims: &serde_json::Value, graph: GraphUser) -> Result<OAuth2UserInfo> {
    let claim = |name: &str| {
        claims
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .ok_or_else(|| AuthError::InvalidToken(format!("id_token has no `{name}` claim")))
    };
    let tid = claim("tid")?;
    let oid = claim("oid")?;

    let mut additional = graph.additional;
    additional.insert("tid".to_string(), serde_json::Value::String(tid.clone()));
    additional.insert("oid".to_string(), serde_json::Value::String(oid.clone()));
    additional.insert("graph_id".to_string(), serde_json::Value::String(graph.id));

    Ok(OAuth2UserInfo {
        sub: format!("{tid}:{oid}"),
        email: graph.mail.or(graph.user_principal_name),
        name: graph.display_name,
        given_name: None,
        family_name: None,
        picture: None,
        email_verified: Some(false),
        additional,
    })
}

/// Microsoft Entra provider configuration
#[derive(Clone)]
pub struct MicrosoftEntraConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub tenant_id: String, // "common", "organizations", "consumers", or specific tenant ID
    pub scopes: Vec<String>,
}

crate::providers::debug_redacting_client_secret!(MicrosoftEntraConfig {
    client_id,
    redirect_url,
    tenant_id,
    scopes
});

impl MicrosoftEntraConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        tenant_id: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
            tenant_id,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Create config for common tenant (any Azure AD account)
    pub fn common(client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self::new(client_id, client_secret, redirect_url, "common".to_string())
    }

    /// Create config for organization accounts only
    pub fn organizations(client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self::new(
            client_id,
            client_secret,
            redirect_url,
            "organizations".to_string(),
        )
    }

    /// Create config for personal Microsoft accounts
    pub fn consumers(client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self::new(
            client_id,
            client_secret,
            redirect_url,
            "consumers".to_string(),
        )
    }
}

/// Microsoft Entra (Azure AD) provider
pub struct MicrosoftEntraProvider {
    inner: GenericOAuth2Provider,
}

impl MicrosoftEntraProvider {
    /// # Errors
    ///
    /// [`AuthError::Configuration`] if `tenant_id` is not `common`,
    /// `organizations`, `consumers`, a tenant GUID or a bare domain name.
    pub fn new(config: MicrosoftEntraConfig) -> Result<Self> {
        crate::providers::validate_hostname("Microsoft tenant id", &config.tenant_id)?;

        // Multi-tenant endpoints issue tokens whose `iss` names the user's
        // own tenant, so the issuer is checked against the token's `tid`.
        // A tenant pinned by GUID must match exactly.
        let is_guid = config.tenant_id.len() == 36
            && config
                .tenant_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-');
        let issuer = if is_guid {
            format!(
                "https://login.microsoftonline.com/{}/v2.0",
                config.tenant_id
            )
        } else {
            "https://login.microsoftonline.com/{tenantid}/v2.0".to_string()
        };
        let jwks_uri = format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            config.tenant_id
        );

        let auth_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            config.tenant_id
        );
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            config.tenant_id
        );

        let oauth2_config = OAuth2Config::new(
            config.client_id,
            config.client_secret,
            auth_url,
            token_url,
            config.redirect_url,
        )
        .with_scopes(config.scopes)
        .with_user_info_url("https://graph.microsoft.com/v1.0/me".to_string())
        .with_oidc(issuer, jwks_uri);

        let inner = GenericOAuth2Provider::new("microsoft-entra".to_string(), oauth2_config)?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl OAuth2Provider for MicrosoftEntraProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn authorization_url(&self) -> Result<(Url, PendingAuth)> {
        self.inner.authorization_url()
    }

    async fn exchange_code(
        &self,
        code: String,
        returned_state: &str,
        pending: PendingAuth,
    ) -> Result<OAuth2Token> {
        self.inner
            .exchange_code(code, returned_state, pending)
            .await
    }

    async fn get_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo> {
        // Identity comes from the verified id_token (tid + oid); without it
        // there is nothing trustworthy to key the account on.
        let claims = token.id_token_claims.as_ref().ok_or_else(|| {
            AuthError::InvalidToken(
                "Microsoft identity requires a verified id_token (request the `openid` scope)"
                    .to_string(),
            )
        })?;

        // Microsoft Graph's `/me` response doesn't use OIDC claim names (`id`
        // rather than `sub`, `mail`/`userPrincipalName` rather than `email`,
        // `displayName` rather than `name`), so it's fetched and deserialized
        // into a Graph-specific shape rather than `OAuth2UserInfo` directly.
        let user_info_url = self
            .inner
            .user_info_url()
            .ok_or_else(|| AuthError::AuthenticationFailed("No user info URL configured".into()))?;

        let response = self
            .inner
            .http()
            .get(user_info_url)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| {
                AuthError::AuthenticationFailed(format!("User info request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(AuthError::AuthenticationFailed(format!(
                "User info request failed with status: {}",
                response.status()
            )));
        }

        let graph_user: GraphUser = response.json().await.map_err(|e| {
            AuthError::AuthenticationFailed(format!("Failed to parse user info: {}", e))
        })?;

        user_info_from(claims, graph_user)
    }

    async fn refresh_token(&self, refresh_token: String) -> Result<OAuth2Token> {
        self.inner.refresh_token(refresh_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_microsoft_config() {
        let config = MicrosoftEntraConfig::common(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
        );

        assert_eq!(config.tenant_id, "common");
        assert_eq!(config.scopes.len(), 3);
    }

    #[test]
    fn test_microsoft_organizations() {
        let config = MicrosoftEntraConfig::organizations(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
        );

        assert_eq!(config.tenant_id, "organizations");
    }

    fn test_provider(user_info_url: String) -> MicrosoftEntraProvider {
        let oauth2_config = OAuth2Config::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
            "http://localhost:3000/callback".to_string(),
        )
        .with_user_info_url(user_info_url);
        let inner = GenericOAuth2Provider::new("microsoft-entra".to_string(), oauth2_config)
            .expect("provider config should be valid");
        MicrosoftEntraProvider { inner }
    }

    fn dummy_token() -> OAuth2Token {
        OAuth2Token {
            access_token: "at-123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: Some("verified".to_string()),
            id_token_claims: Some(serde_json::json!({
                "tid": "tenant-1",
                "oid": "object-1",
                "sub": "pairwise-sub",
            })),
        }
    }

    #[tokio::test]
    async fn get_user_info_maps_graph_fields_to_oauth2_user_info() {
        let server = armature_testkit::StubServer::builder()
            .route(
                "GET",
                "/me",
                armature_testkit::StubResponse::json(
                    200,
                    r#"{
                        "id": "abc-123",
                        "mail": "jane@example.com",
                        "userPrincipalName": "jane@contoso.onmicrosoft.com",
                        "displayName": "Jane Doe"
                    }"#,
                ),
            )
            .start()
            .await;

        let provider = test_provider(format!("{}/me", server.url()));
        let user_info = provider.get_user_info(&dummy_token()).await.unwrap();

        // Identity is keyed on tid + oid, never on the mutable `mail`.
        assert_eq!(user_info.sub, "tenant-1:object-1");
        assert_eq!(user_info.email.as_deref(), Some("jane@example.com"));
        assert_eq!(user_info.email_verified, Some(false));
        assert_eq!(user_info.name.as_deref(), Some("Jane Doe"));
        assert_eq!(user_info.additional["graph_id"], "abc-123");
    }

    #[tokio::test]
    async fn get_user_info_falls_back_to_user_principal_name_when_mail_absent() {
        let server = armature_testkit::StubServer::builder()
            .route(
                "GET",
                "/me",
                armature_testkit::StubResponse::json(
                    200,
                    r#"{
                        "id": "abc-456",
                        "userPrincipalName": "jane@contoso.onmicrosoft.com",
                        "displayName": "Jane Doe"
                    }"#,
                ),
            )
            .start()
            .await;

        let provider = test_provider(format!("{}/me", server.url()));
        let user_info = provider.get_user_info(&dummy_token()).await.unwrap();

        assert_eq!(user_info.sub, "tenant-1:object-1");
        assert_eq!(
            user_info.email.as_deref(),
            Some("jane@contoso.onmicrosoft.com")
        );
    }

    #[tokio::test]
    async fn get_user_info_requires_verified_id_token() {
        let server = armature_testkit::StubServer::builder()
            .route(
                "GET",
                "/me",
                armature_testkit::StubResponse::json(200, r#"{"id": "abc", "mail": "a@b.c"}"#),
            )
            .start()
            .await;
        let provider = test_provider(format!("{}/me", server.url()));
        let mut token = dummy_token();
        token.id_token = None;
        token.id_token_claims = None;
        assert!(provider.get_user_info(&token).await.is_err());
    }

    #[test]
    fn rejects_tenant_ids_that_are_not_hostnames() {
        for bad in ["common/../evil", "evil.com/x", "a@b", "https://x"] {
            let config = MicrosoftEntraConfig::new(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:3000/callback".to_string(),
                bad.to_string(),
            );
            assert!(MicrosoftEntraProvider::new(config).is_err(), "{bad}");
        }
        for ok in [
            "common",
            "contoso.onmicrosoft.com",
            "9188040d-6c67-4c5b-b112-36a304b66dad",
        ] {
            let config = MicrosoftEntraConfig::new(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:3000/callback".to_string(),
                ok.to_string(),
            );
            assert!(MicrosoftEntraProvider::new(config).is_ok(), "{ok}");
        }
    }

    #[test]
    fn debug_redacts_client_secret() {
        let config = MicrosoftEntraConfig::common(
            "client_id".to_string(),
            "very-secret".to_string(),
            "http://localhost:3000/callback".to_string(),
        );
        assert!(!format!("{config:?}").contains("very-secret"));
    }
}
