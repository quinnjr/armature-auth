// Okta OAuth2 provider

use crate::Result;
use crate::oauth2::{
    GenericOAuth2Provider, OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth,
};
use async_trait::async_trait;
use url::Url;

/// Okta provider configuration
#[derive(Clone)]
pub struct OktaConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub domain: String, // e.g., "dev-12345.okta.com" or "mycompany.okta.com"
    pub scopes: Vec<String>,
}

crate::providers::debug_redacting_client_secret!(OktaConfig {
    client_id,
    redirect_url,
    domain,
    scopes
});

impl OktaConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        domain: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
            domain,
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
}

/// Okta provider
pub struct OktaProvider {
    inner: GenericOAuth2Provider,
}

impl OktaProvider {
    /// # Errors
    ///
    /// [`crate::AuthError::Configuration`] if `domain` is not a bare hostname.
    pub fn new(config: OktaConfig) -> Result<Self> {
        crate::providers::validate_hostname("Okta domain", &config.domain)?;
        let issuer = format!("https://{}", config.domain);
        let jwks_uri = format!("https://{}/oauth2/v1/keys", config.domain);
        let auth_url = format!("https://{}/oauth2/v1/authorize", config.domain);
        let token_url = format!("https://{}/oauth2/v1/token", config.domain);
        let user_info_url = format!("https://{}/oauth2/v1/userinfo", config.domain);

        let oauth2_config = OAuth2Config::new(
            config.client_id,
            config.client_secret,
            auth_url,
            token_url,
            config.redirect_url,
        )
        .with_scopes(config.scopes)
        .with_user_info_url(user_info_url)
        .with_oidc(issuer, jwks_uri);

        let inner = GenericOAuth2Provider::new("okta".to_string(), oauth2_config)?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl OAuth2Provider for OktaProvider {
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
        self.inner.get_user_info(token).await
    }

    async fn refresh_token(&self, refresh_token: String) -> Result<OAuth2Token> {
        self.inner.refresh_token(refresh_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_okta_config() {
        let config = OktaConfig::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "dev-12345.okta.com".to_string(),
        );

        assert_eq!(config.domain, "dev-12345.okta.com");
        assert_eq!(config.scopes.len(), 3);
    }

    #[test]
    fn rejects_non_hostname_domain() {
        for bad in ["evil.com/x", "a@b", "https://x", "x.com:443"] {
            let config = OktaConfig::new(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:3000/callback".to_string(),
                bad.to_string(),
            );
            assert!(OktaProvider::new(config).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_redacts_client_secret() {
        let config = OktaConfig::new(
            "client_id".to_string(),
            "very-secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "dev-1.okta.com".to_string(),
        );
        assert!(!format!("{config:?}").contains("very-secret"));
    }
}
