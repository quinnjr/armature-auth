// Google OAuth2 provider

use crate::Result;
use crate::oauth2::{
    GenericOAuth2Provider, OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth,
};
use async_trait::async_trait;
use url::Url;

/// Google OAuth2 provider configuration
#[derive(Clone)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

crate::providers::debug_redacting_client_secret!(GoogleConfig {
    client_id,
    redirect_url,
    scopes
});

impl GoogleConfig {
    pub fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
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

/// Google OAuth2 provider
pub struct GoogleProvider {
    inner: GenericOAuth2Provider,
}

impl GoogleProvider {
    pub fn new(config: GoogleConfig) -> Result<Self> {
        let oauth2_config = OAuth2Config::new(
            config.client_id,
            config.client_secret,
            "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            "https://oauth2.googleapis.com/token".to_string(),
            config.redirect_url,
        )
        .with_scopes(config.scopes)
        // The OIDC userinfo endpoint (returns `sub`, unlike the legacy
        // `oauth2/v2/userinfo`, which returns `id`).
        .with_user_info_url("https://openidconnect.googleapis.com/v1/userinfo".to_string())
        .with_oidc(
            "https://accounts.google.com",
            "https://www.googleapis.com/oauth2/v3/certs",
        );

        let inner = GenericOAuth2Provider::new("google".to_string(), oauth2_config)?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl OAuth2Provider for GoogleProvider {
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
    fn test_google_config() {
        let config = GoogleConfig::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
        );

        assert_eq!(config.scopes.len(), 3);
        assert!(config.scopes.contains(&"openid".to_string()));
    }

    #[test]
    fn debug_redacts_client_secret() {
        let config = GoogleConfig::new(
            "client_id".to_string(),
            "very-secret".to_string(),
            "http://localhost:3000/callback".to_string(),
        );
        assert!(!format!("{config:?}").contains("very-secret"));
    }
}
