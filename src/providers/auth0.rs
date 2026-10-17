// Auth0 OAuth2 provider

use crate::Result;
use crate::oauth2::{
    GenericOAuth2Provider, OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth,
};
use async_trait::async_trait;
use url::Url;

/// Auth0 provider configuration
#[derive(Clone)]
pub struct Auth0Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub domain: String, // e.g., "myapp.us.auth0.com" or "mycompany.auth0.com"
    pub scopes: Vec<String>,
    pub audience: Option<String>, // Optional API audience
}

crate::providers::debug_redacting_client_secret!(Auth0Config {
    client_id,
    redirect_url,
    domain,
    scopes,
    audience
});

impl Auth0Config {
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
            audience: None,
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }
}

/// Auth0 provider
pub struct Auth0Provider {
    inner: GenericOAuth2Provider,
    audience: Option<String>,
}

impl Auth0Provider {
    /// # Errors
    ///
    /// [`crate::AuthError::Configuration`] if `domain` is not a bare hostname.
    pub fn new(config: Auth0Config) -> Result<Self> {
        crate::providers::validate_hostname("Auth0 domain", &config.domain)?;
        let issuer = format!("https://{}/", config.domain);
        let jwks_uri = format!("https://{}/.well-known/jwks.json", config.domain);
        let auth_url = format!("https://{}/authorize", config.domain);
        let token_url = format!("https://{}/oauth/token", config.domain);
        let user_info_url = format!("https://{}/userinfo", config.domain);

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

        let inner = GenericOAuth2Provider::new("auth0".to_string(), oauth2_config)?;

        Ok(Self {
            inner,
            audience: config.audience,
        })
    }
}

#[async_trait]
impl OAuth2Provider for Auth0Provider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn authorization_url(&self) -> Result<(Url, PendingAuth)> {
        let (mut url, pending) = self.inner.authorization_url()?;

        // Add audience parameter if specified
        if let Some(ref audience) = self.audience {
            url.query_pairs_mut().append_pair("audience", audience);
        }

        Ok((url, pending))
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
    fn test_auth0_config() {
        let config = Auth0Config::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "myapp.us.auth0.com".to_string(),
        );

        assert_eq!(config.domain, "myapp.us.auth0.com");
        assert_eq!(config.scopes.len(), 3);
    }

    #[test]
    fn test_auth0_with_audience() {
        let config = Auth0Config::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "myapp.us.auth0.com".to_string(),
        )
        .with_audience("https://api.myapp.com".to_string());

        assert!(config.audience.is_some());
    }

    #[test]
    fn rejects_non_hostname_domain() {
        for bad in ["evil.com/x", "a@b", "https://x"] {
            let config = Auth0Config::new(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:3000/callback".to_string(),
                bad.to_string(),
            );
            assert!(Auth0Provider::new(config).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_redacts_client_secret() {
        let config = Auth0Config::new(
            "client_id".to_string(),
            "very-secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "myapp.us.auth0.com".to_string(),
        );
        assert!(!format!("{config:?}").contains("very-secret"));
    }
}
