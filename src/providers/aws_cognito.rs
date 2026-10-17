// AWS Cognito OAuth2 provider

use crate::Result;
use crate::oauth2::{
    GenericOAuth2Provider, OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo, PendingAuth,
};
use async_trait::async_trait;
use url::Url;

/// AWS Cognito provider configuration
#[derive(Clone)]
pub struct AwsCognitoConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub user_pool_domain: String, // e.g., "my-app.auth.us-east-1.amazoncognito.com"
    pub region: String,           // e.g., "us-east-1"
    pub scopes: Vec<String>,
    /// User pool ID (e.g. `us-east-1_AbCdEf123`). Required for `id_token`
    /// verification; without it no `id_token` is exposed.
    pub user_pool_id: Option<String>,
}

crate::providers::debug_redacting_client_secret!(AwsCognitoConfig {
    client_id,
    redirect_url,
    user_pool_domain,
    region,
    scopes,
    user_pool_id
});

impl AwsCognitoConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        user_pool_domain: String,
        region: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
            user_pool_domain,
            region,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            user_pool_id: None,
        }
    }

    /// Set the user pool ID, enabling OIDC `id_token` verification.
    pub fn with_user_pool_id(mut self, user_pool_id: String) -> Self {
        self.user_pool_id = Some(user_pool_id);
        self
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
}

/// AWS Cognito provider
pub struct AwsCognitoProvider {
    inner: GenericOAuth2Provider,
}

impl AwsCognitoProvider {
    /// # Errors
    ///
    /// [`crate::AuthError::Configuration`] if `user_pool_domain` is not a
    /// bare hostname, or `region` / `user_pool_id` contain characters outside
    /// their AWS formats.
    pub fn new(config: AwsCognitoConfig) -> Result<Self> {
        crate::providers::validate_hostname("Cognito user pool domain", &config.user_pool_domain)?;
        if config.region.is_empty()
            || !config
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(crate::AuthError::Configuration(format!(
                "invalid AWS region {:?}",
                config.region
            )));
        }
        if let Some(pool) = &config.user_pool_id
            && (pool.is_empty()
                || !pool
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        {
            return Err(crate::AuthError::Configuration(format!(
                "invalid Cognito user pool id {pool:?}"
            )));
        }
        let auth_url = format!("https://{}/oauth2/authorize", config.user_pool_domain);
        let token_url = format!("https://{}/oauth2/token", config.user_pool_domain);
        let user_info_url = format!("https://{}/oauth2/userInfo", config.user_pool_domain);

        let oauth2_config = OAuth2Config::new(
            config.client_id,
            config.client_secret,
            auth_url,
            token_url,
            config.redirect_url,
        )
        .with_scopes(config.scopes)
        .with_user_info_url(user_info_url);
        let oauth2_config = match &config.user_pool_id {
            Some(pool) => {
                let issuer = format!(
                    "https://cognito-idp.{}.amazonaws.com/{}",
                    config.region, pool
                );
                let jwks_uri = format!("{issuer}/.well-known/jwks.json");
                oauth2_config.with_oidc(issuer, jwks_uri)
            }
            None => oauth2_config,
        };

        let inner = GenericOAuth2Provider::new("aws-cognito".to_string(), oauth2_config)?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl OAuth2Provider for AwsCognitoProvider {
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
    fn test_cognito_config() {
        let config = AwsCognitoConfig::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "my-app.auth.us-east-1.amazoncognito.com".to_string(),
            "us-east-1".to_string(),
        );

        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.scopes.len(), 3);
    }

    #[test]
    fn rejects_non_hostname_domain_and_bad_region() {
        let mk = |domain: &str, region: &str| {
            AwsCognitoProvider::new(AwsCognitoConfig::new(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:3000/callback".to_string(),
                domain.to_string(),
                region.to_string(),
            ))
        };
        assert!(mk("a.auth.us-east-1.amazoncognito.com", "us-east-1").is_ok());
        assert!(mk("evil.com/x", "us-east-1").is_err());
        assert!(mk("a@b", "us-east-1").is_err());
        assert!(mk("a.auth.us-east-1.amazoncognito.com", "us-east-1/../x").is_err());
    }

    #[test]
    fn debug_redacts_client_secret() {
        let config = AwsCognitoConfig::new(
            "client_id".to_string(),
            "very-secret".to_string(),
            "http://localhost:3000/callback".to_string(),
            "a.auth.us-east-1.amazoncognito.com".to_string(),
            "us-east-1".to_string(),
        );
        assert!(!format!("{config:?}").contains("very-secret"));
    }
}
