//! OAuth2 and OpenID Connect provider support.
//!
//! # Flow
//!
//! 1. [`OAuth2Provider::authorization_url`] returns the URL to redirect the
//!    user to **and** a [`PendingAuth`] holding the `state`, the PKCE (S256)
//!    verifier and, for OIDC, the `nonce`. Store the `PendingAuth`
//!    **server-side** (e.g. in the session store), keyed to the user's
//!    session. Never put it in a client-readable cookie: the PKCE verifier and
//!    nonce are secrets.
//! 2. On the callback, pass the returned `code`, the returned `state`, and the
//!    stored `PendingAuth` to [`OAuth2Provider::exchange_code`]. The library
//!    compares `state` in constant time, sends the PKCE verifier, and — when
//!    the provider is configured for OIDC — verifies the `id_token`
//!    (signature against the provider's JWKS, `iss`, `aud`, `exp`, `nonce`).
//!
//! An `id_token` is only ever exposed on [`OAuth2Token`] after that
//! verification; providers without OIDC settings never surface one.
//!
//! # HTTP
//!
//! All provider calls use a rustls `reqwest` client that does **not** follow
//! redirects: a 307/308 from a token endpoint would otherwise re-send the
//! `client_secret` and code to wherever it points.

use crate::{AuthError, Result};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use oauth2::basic::BasicTokenType;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointSet, ExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse,
    TokenResponse, TokenUrl,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;

/// Type alias for a fully configured OAuth2 client
type ConfiguredClient = oauth2::Client<
    StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    StandardTokenResponse<OidcExtraFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<OidcExtraFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    EndpointSet,
>;

/// How long a [`PendingAuth`] stays redeemable.
pub const PENDING_AUTH_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Clock skew tolerated when validating `id_token` time claims.
const ID_TOKEN_LEEWAY_SECS: u64 = 60;

/// How long a fetched JWKS is trusted before it is refetched.
const JWKS_TTL: Duration = Duration::from_secs(60 * 60);

/// Minimum spacing between JWKS refetches triggered by an unknown `kid`.
const JWKS_MIN_REFETCH: Duration = Duration::from_secs(60);

/// OAuth2 provider trait
#[async_trait]
pub trait OAuth2Provider: Send + Sync {
    /// Get the provider name
    fn name(&self) -> &str;

    /// Build the authorization URL (with PKCE S256, `state` and, for OIDC,
    /// `nonce`) and the [`PendingAuth`] that must be stored server-side until
    /// the callback.
    fn authorization_url(&self) -> Result<(Url, PendingAuth)>;

    /// Exchange the callback's authorization `code` for tokens.
    ///
    /// `returned_state` is the `state` query parameter from the callback;
    /// `pending` is the value stored when the flow started. Fails if the
    /// state does not match, the pending flow is older than
    /// [`PENDING_AUTH_MAX_AGE`], or (OIDC) the `id_token` does not verify.
    async fn exchange_code(
        &self,
        code: String,
        returned_state: &str,
        pending: PendingAuth,
    ) -> Result<OAuth2Token>;

    /// Get user info from token
    async fn get_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo>;

    /// Refresh access token. Any `id_token` in the refresh response is not
    /// surfaced (it cannot be bound to a nonce).
    async fn refresh_token(&self, refresh_token: String) -> Result<OAuth2Token>;
}

/// Server-side state of an authorization request in flight.
///
/// Holds the `state` value, the PKCE code verifier and (for OIDC) the
/// `nonce`. It is `Serialize`/`Deserialize` **only** so it can be kept in a
/// server-side session store between the redirect and the callback; it must
/// never be sent to the browser (no client-readable cookie, no hidden form
/// field). Secrets are redacted from `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingAuth {
    state: String,
    pkce_verifier: String,
    nonce: Option<String>,
    /// Unix seconds at which the flow started.
    created_at: i64,
}

impl PendingAuth {
    /// The `state` value sent in the authorization URL. It is not secret and
    /// can be used to key the server-side storage of this value.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Whether the flow started more than `max_age` ago.
    pub fn is_expired(&self, max_age: Duration) -> bool {
        let age = chrono::Utc::now().timestamp() - self.created_at;
        age < 0 || age as u64 > max_age.as_secs()
    }

    /// Constant-time check that `returned_state` is this flow's state.
    fn check_state(&self, returned_state: &str) -> Result<()> {
        if bool::from(self.state.as_bytes().ct_eq(returned_state.as_bytes())) {
            Ok(())
        } else {
            Err(AuthError::InvalidToken(
                "OAuth2 state mismatch (possible CSRF)".to_string(),
            ))
        }
    }

    /// The nonce sent with the request, if this was an OIDC flow.
    pub(crate) fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}

impl fmt::Debug for PendingAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuth")
            .field("state", &self.state)
            .field("pkce_verifier", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// OAuth2 token response.
///
/// The tokens are redacted from `Debug`. The type stays `Serialize` so an
/// application can persist provider tokens server-side (to call the provider
/// API later); do not return it to browsers.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// The raw OIDC `id_token`, present **only** after it was verified
    /// (signature, `iss`, `aud`, `exp`, `nonce`).
    pub id_token: Option<String>,
    /// The verified `id_token` claims; `None` whenever `id_token` is.
    #[serde(default)]
    pub id_token_claims: Option<serde_json::Value>,
}

impl fmt::Debug for OAuth2Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("OAuth2Token")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &redact(&self.refresh_token))
            .field("scope", &self.scope)
            .field("id_token", &redact(&self.id_token))
            .field("id_token_claims", &self.id_token_claims.is_some())
            .finish()
    }
}

/// Extra token-endpoint fields beyond the OAuth2 base response, needed to
/// read the OIDC `id_token` that a plain `BasicClient` response discards.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct OidcExtraFields {
    #[serde(default)]
    pub id_token: Option<String>,
}

impl fmt::Debug for OidcExtraFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcExtraFields")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ExtraTokenFields for OidcExtraFields {}

impl From<StandardTokenResponse<OidcExtraFields, oauth2::basic::BasicTokenType>> for OAuth2Token {
    /// Converts the token response, **dropping** any `id_token`: it is only
    /// attached by the provider after verification.
    fn from(token: StandardTokenResponse<OidcExtraFields, oauth2::basic::BasicTokenType>) -> Self {
        Self {
            access_token: token.access_token().secret().clone(),
            token_type: token.token_type().as_ref().to_string(),
            expires_in: token.expires_in().map(|d| d.as_secs()),
            refresh_token: token.refresh_token().map(|t| t.secret().clone()),
            scope: token.scopes().map(|s| {
                s.iter()
                    .map(|scope| scope.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            id_token: None,
            id_token_claims: None,
        }
    }
}

/// OAuth2 user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    pub sub: String, // Subject (user ID)
    pub email: Option<String>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// OpenID Connect settings for `id_token` verification.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    /// Expected `iss`. May contain the literal placeholder `{tenantid}`
    /// (Microsoft multi-tenant endpoints), which is replaced by the token's
    /// `tid` claim before comparison.
    pub issuer: String,
    /// The provider's JWKS endpoint.
    pub jwks_uri: String,
}

/// Generic OAuth2 client configuration.
///
/// `client_secret` is redacted from `Debug`.
#[derive(Clone)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub user_info_url: Option<String>,
    /// OIDC settings; when set and the `openid` scope is requested, a nonce is
    /// sent and the `id_token` is verified on code exchange.
    pub oidc: Option<OidcSettings>,
}

impl fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Config")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("user_info_url", &self.user_info_url)
            .field("oidc", &self.oidc)
            .finish()
    }
}

impl OAuth2Config {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        token_url: String,
        redirect_url: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url,
            token_url,
            redirect_url,
            scopes: Vec::new(),
            user_info_url: None,
            oidc: None,
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn with_user_info_url(mut self, url: String) -> Self {
        self.user_info_url = Some(url);
        self
    }

    /// Enable OIDC `id_token` verification against `issuer` and the keys at
    /// `jwks_uri`.
    pub fn with_oidc(mut self, issuer: impl Into<String>, jwks_uri: impl Into<String>) -> Self {
        self.oidc = Some(OidcSettings {
            issuer: issuer.into(),
            jwks_uri: jwks_uri.into(),
        });
        self
    }

    fn wants_oidc(&self) -> bool {
        self.oidc.is_some() && self.scopes.iter().any(|s| s == "openid")
    }
}

/// Build the HTTP client used for provider calls: rustls, bounded timeouts,
/// and **no redirect following**.
pub(crate) fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client with static configuration builds")
}

/// Adapter running oauth2's token requests over our redirect-less client.
struct TokenHttpClient<'a>(&'a reqwest::Client);

type HttpFuture<'c> = Pin<
    Box<
        dyn Future<
                Output = std::result::Result<
                    oauth2::HttpResponse,
                    oauth2::HttpClientError<reqwest::Error>,
                >,
            > + Send
            + 'c,
    >,
>;

impl<'c> oauth2::AsyncHttpClient<'c> for TokenHttpClient<'_> {
    type Error = oauth2::HttpClientError<reqwest::Error>;
    type Future = HttpFuture<'c>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request: reqwest::Request = request.try_into().map_err(Box::new)?;
            let response = self.0.execute(request).await.map_err(Box::new)?;
            let mut builder = oauth2::http::Response::builder()
                .status(response.status())
                .version(response.version());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let body = response.bytes().await.map_err(Box::new)?;
            builder
                .body(body.to_vec())
                .map_err(oauth2::HttpClientError::Http)
        })
    }
}

/// Generic OAuth2 provider implementation
pub struct GenericOAuth2Provider {
    name: String,
    client: ConfiguredClient,
    config: OAuth2Config,
    /// HTTP client for token, userinfo and JWKS requests. Built once: a
    /// `reqwest::Client` owns a connection pool and the TLS root store.
    http: reqwest::Client,
    /// Cached JWKS: (fetched at, key set).
    jwks: RwLock<Option<(Instant, jsonwebtoken::jwk::JwkSet)>>,
}

fn random_token() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    URL_SAFE_NO_PAD.encode(bytes)
}

impl GenericOAuth2Provider {
    /// The configured userinfo endpoint URL, if any.
    pub(crate) fn user_info_url(&self) -> Option<&str> {
        self.config.user_info_url.as_deref()
    }

    /// The redirect-less HTTP client.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn new(name: String, config: OAuth2Config) -> Result<Self> {
        let client = oauth2::Client::<
            StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
            StandardTokenResponse<OidcExtraFields, BasicTokenType>,
            StandardTokenIntrospectionResponse<OidcExtraFields, BasicTokenType>,
            StandardRevocableToken,
            StandardErrorResponse<oauth2::RevocationErrorResponseType>,
        >::new(ClientId::new(config.client_id.clone()))
        .set_client_secret(ClientSecret::new(config.client_secret.clone()))
        .set_auth_uri(
            AuthUrl::new(config.auth_url.clone())
                .map_err(|e| AuthError::AuthenticationFailed(e.to_string()))?,
        )
        .set_token_uri(
            TokenUrl::new(config.token_url.clone())
                .map_err(|e| AuthError::AuthenticationFailed(e.to_string()))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_url.clone())
                .map_err(|e| AuthError::AuthenticationFailed(e.to_string()))?,
        );

        if let Some(oidc) = &config.oidc {
            Url::parse(&oidc.jwks_uri)
                .map_err(|e| AuthError::Configuration(format!("invalid jwks_uri: {e}")))?;
        }

        Ok(Self {
            name,
            client,
            config,
            http: build_http_client(),
            jwks: RwLock::new(None),
        })
    }

    /// Fetch the JWKS, using the cache unless it is stale or `force` is set
    /// (and the last fetch is older than [`JWKS_MIN_REFETCH`]).
    async fn jwks(&self, force: bool) -> Result<jsonwebtoken::jwk::JwkSet> {
        if let Some((fetched, set)) = self.jwks.read().await.as_ref() {
            let age = fetched.elapsed();
            if age < JWKS_TTL && (!force || age < JWKS_MIN_REFETCH) {
                return Ok(set.clone());
            }
        }
        let oidc = self
            .config
            .oidc
            .as_ref()
            .ok_or_else(|| AuthError::Configuration("OIDC not configured".to_string()))?;
        let response = self
            .http
            .get(&oidc.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::HttpRequest(format!("JWKS fetch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AuthError::HttpRequest(format!(
                "JWKS fetch failed with status {}",
                response.status()
            )));
        }
        let set: jsonwebtoken::jwk::JwkSet = response
            .json()
            .await
            .map_err(|e| AuthError::InvalidResponse(format!("invalid JWKS: {e}")))?;
        *self.jwks.write().await = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    /// Verify an `id_token`: signature (JWKS, asymmetric algorithms only),
    /// `iss`, `aud` (+ `azp` when several audiences), `exp`, and `nonce`.
    pub(crate) async fn verify_id_token(
        &self,
        raw: &str,
        expected_nonce: &str,
    ) -> Result<serde_json::Value> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        // Select aws-lc-rs explicitly (see armature-jwt); Err = already set.
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();

        let oidc = self
            .config
            .oidc
            .as_ref()
            .ok_or_else(|| AuthError::Configuration("OIDC not configured".to_string()))?;
        let invalid = |msg: String| AuthError::InvalidToken(format!("id_token: {msg}"));

        let header = jsonwebtoken::decode_header(raw).map_err(|e| invalid(e.to_string()))?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::EdDSA
        ) {
            return Err(invalid(format!("algorithm {:?} not allowed", header.alg)));
        }

        let find = |set: &jsonwebtoken::jwk::JwkSet| -> Option<jsonwebtoken::jwk::Jwk> {
            match &header.kid {
                Some(kid) => set.find(kid).cloned(),
                None if set.keys.len() == 1 => set.keys.first().cloned(),
                None => None,
            }
        };
        let jwk = match find(&self.jwks(false).await?) {
            Some(jwk) => jwk,
            // Unknown kid: the provider may have rotated keys.
            None => find(&self.jwks(true).await?)
                .ok_or_else(|| invalid("no matching signing key".to_string()))?,
        };
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| invalid(e.to_string()))?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = ID_TOKEN_LEEWAY_SECS;
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let templated = oidc.issuer.contains("{tenantid}");
        if !templated {
            validation.set_issuer(&[&oidc.issuer]);
        }

        let data = jsonwebtoken::decode::<serde_json::Value>(raw, &key, &validation)
            .map_err(|e| invalid(e.to_string()))?;
        let claims = data.claims;

        if templated {
            let tid = claims
                .get("tid")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("missing tid".to_string()))?;
            let expected = oidc.issuer.replace("{tenantid}", tid);
            if claims.get("iss").and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
                return Err(invalid("issuer mismatch".to_string()));
            }
        }

        // OIDC Core 3.1.3.7: with several audiences, `azp` must be us.
        if let Some(serde_json::Value::Array(auds)) = claims.get("aud")
            && auds.len() > 1
            && claims.get("azp").and_then(serde_json::Value::as_str)
                != Some(self.config.client_id.as_str())
        {
            return Err(invalid("azp mismatch".to_string()));
        }

        let nonce = claims
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !bool::from(nonce.as_bytes().ct_eq(expected_nonce.as_bytes())) {
            return Err(invalid("nonce mismatch".to_string()));
        }

        Ok(claims)
    }
}

#[async_trait]
impl OAuth2Provider for GenericOAuth2Provider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorization_url(&self) -> Result<(Url, PendingAuth)> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_request = self
            .client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);

        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let nonce = self.config.wants_oidc().then(random_token);
        if let Some(nonce) = &nonce {
            auth_request = auth_request.add_extra_param("nonce", nonce.clone());
        }

        let (url, csrf_token) = auth_request.url();
        Ok((
            url,
            PendingAuth {
                state: csrf_token.secret().clone(),
                pkce_verifier: pkce_verifier.secret().clone(),
                nonce,
                created_at: chrono::Utc::now().timestamp(),
            },
        ))
    }

    async fn exchange_code(
        &self,
        code: String,
        returned_state: &str,
        pending: PendingAuth,
    ) -> Result<OAuth2Token> {
        pending.check_state(returned_state)?;
        if pending.is_expired(PENDING_AUTH_MAX_AGE) {
            return Err(AuthError::TokenExpired);
        }

        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier.clone()))
            .request_async(&TokenHttpClient(&self.http))
            .await
            .map_err(|e| {
                AuthError::AuthenticationFailed(format!("Token exchange failed: {}", e))
            })?;

        let raw_id_token = token.extra_fields().id_token.clone();
        let mut out: OAuth2Token = token.into();

        if let (Some(nonce), true) = (pending.nonce(), self.config.oidc.is_some()) {
            let raw = raw_id_token.ok_or_else(|| {
                AuthError::InvalidToken("id_token missing from OIDC token response".to_string())
            })?;
            let claims = self.verify_id_token(&raw, nonce).await?;
            out.id_token = Some(raw);
            out.id_token_claims = Some(claims);
        }

        Ok(out)
    }

    async fn get_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo> {
        let user_info_url =
            self.config.user_info_url.as_ref().ok_or_else(|| {
                AuthError::AuthenticationFailed("No user info URL configured".into())
            })?;

        let response = self
            .http
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

        let user_info: OAuth2UserInfo = response.json().await.map_err(|e| {
            AuthError::AuthenticationFailed(format!("Failed to parse user info: {}", e))
        })?;

        // A verified id_token pins the subject: userinfo must agree with it
        // (OIDC Core 5.3.2).
        if let Some(claims) = &token.id_token_claims
            && claims.get("sub").and_then(serde_json::Value::as_str) != Some(user_info.sub.as_str())
        {
            return Err(AuthError::InvalidResponse(
                "userinfo sub does not match id_token sub".to_string(),
            ));
        }

        Ok(user_info)
    }

    async fn refresh_token(&self, refresh_token: String) -> Result<OAuth2Token> {
        let token = self
            .client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token))
            .request_async(&TokenHttpClient(&self.http))
            .await
            .map_err(|e| AuthError::AuthenticationFailed(format!("Token refresh failed: {}", e)))?;

        Ok(token.into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use armature_testkit::{StubResponse, StubServer};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    const EC_PRIV: &str = include_str!("../tests/fixtures/oidc_test_ec_priv.pem");
    pub(crate) const CLIENT_ID: &str = "client_id";

    fn signing_key() -> EncodingKey {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        EncodingKey::from_ec_pem(EC_PRIV.as_bytes()).unwrap()
    }

    pub(crate) fn jwks_json(kid: &str) -> String {
        let mut jwk =
            jsonwebtoken::jwk::Jwk::from_encoding_key(&signing_key(), Algorithm::ES256).unwrap();
        jwk.common.key_id = Some(kid.to_string());
        serde_json::to_string(&jsonwebtoken::jwk::JwkSet { keys: vec![jwk] }).unwrap()
    }

    pub(crate) fn sign_id_token(claims: serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, &claims, &signing_key()).unwrap()
    }

    pub(crate) fn id_claims(issuer: &str, nonce: &str) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": issuer,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
        })
    }

    pub(crate) fn pending(nonce: Option<&str>) -> PendingAuth {
        PendingAuth {
            state: "state-123".to_string(),
            pkce_verifier: "v".repeat(43),
            nonce: nonce.map(str::to_string),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// A stub `/token` endpoint returning `extra` merged into a bearer token
    /// response.
    pub(crate) async fn token_server(extra: serde_json::Value) -> StubServer {
        let mut body = serde_json::json!({
            "access_token": "at-123", "token_type": "Bearer", "expires_in": 3600,
        });
        if let (Some(obj), serde_json::Value::Object(extra)) = (body.as_object_mut(), extra) {
            obj.extend(extra);
        }
        StubServer::builder()
            .route("POST", "/token", StubResponse::json(200, body.to_string()))
            .start()
            .await
    }

    /// A stub JWKS endpoint (`/jwks`) whose URL doubles as the issuer.
    pub(crate) async fn jwks_server() -> StubServer {
        StubServer::builder()
            .route("GET", "/jwks", StubResponse::json(200, jwks_json("k1")))
            .start()
            .await
    }

    pub(crate) fn config_for(token: &StubServer, oidc: Option<&StubServer>) -> OAuth2Config {
        let mut config = OAuth2Config::new(
            CLIENT_ID.to_string(),
            "client_secret".to_string(),
            format!("{}/authorize", token.url()),
            format!("{}/token", token.url()),
            "https://example.com/callback".to_string(),
        )
        .with_scopes(vec!["openid".to_string()]);
        if let Some(jwks) = oidc {
            config = config.with_oidc(jwks.url().to_string(), format!("{}/jwks", jwks.url()));
        }
        config
    }

    fn provider(config: OAuth2Config) -> GenericOAuth2Provider {
        GenericOAuth2Provider::new("test".to_string(), config).unwrap()
    }

    /// Exchange a code against a token endpoint that returns the id_token
    /// built by `make` (given the issuer), with OIDC verification enabled.
    async fn exchange_signed(make: impl Fn(&str) -> String, nonce: &str) -> Result<OAuth2Token> {
        let jwks = jwks_server().await;
        let id_token = make(jwks.url());
        let token = token_server(serde_json::json!({ "id_token": id_token })).await;
        provider(config_for(&token, Some(&jwks)))
            .exchange_code("code".to_string(), "state-123", pending(Some(nonce)))
            .await
    }

    #[test]
    fn test_oauth2_config() {
        let config = OAuth2Config::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://example.com/auth".to_string(),
            "https://example.com/token".to_string(),
            "https://example.com/callback".to_string(),
        )
        .with_scopes(vec!["openid".to_string(), "profile".to_string()])
        .with_user_info_url("https://example.com/userinfo".to_string());

        assert_eq!(config.client_id, "client_id");
        assert_eq!(config.scopes.len(), 2);
        assert!(config.user_info_url.is_some());
    }

    #[test]
    fn config_token_and_pending_debug_redact_secrets() {
        let config = OAuth2Config::new(
            "cid".to_string(),
            "super-secret-value".to_string(),
            "https://e/a".to_string(),
            "https://e/t".to_string(),
            "https://e/c".to_string(),
        );
        assert!(!format!("{config:?}").contains("super-secret-value"));

        let token = OAuth2Token {
            access_token: "at-secret".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: Some("rt-secret".to_string()),
            scope: None,
            id_token: Some("idt-secret".to_string()),
            id_token_claims: None,
        };
        let debug = format!("{token:?}");
        for secret in ["at-secret", "rt-secret", "idt-secret"] {
            assert!(!debug.contains(secret), "{debug}");
        }

        let pending = pending(Some("nonce-secret"));
        let debug = format!("{pending:?}");
        assert!(!debug.contains("nonce-secret"), "{debug}");
        assert!(!debug.contains(&"v".repeat(43)), "{debug}");
    }

    #[tokio::test]
    async fn authorization_url_has_pkce_s256_state_and_nonce() {
        let token = token_server(serde_json::json!({})).await;
        let jwks = jwks_server().await;
        let (url, pending) = provider(config_for(&token, Some(&jwks)))
            .authorization_url()
            .unwrap();
        let q: HashMap<String, String> = url.query_pairs().into_owned().collect();

        assert_eq!(
            q.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        // S256: challenge = b64url(sha256(verifier)).
        use sha2::Digest;
        let expected =
            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(pending.pkce_verifier.as_bytes()));
        assert_eq!(q.get("code_challenge"), Some(&expected));
        assert_eq!(q.get("state").map(String::as_str), Some(pending.state()));
        assert!(pending.nonce.is_some());
        assert_eq!(q.get("nonce"), pending.nonce.as_ref());
    }

    #[tokio::test]
    async fn no_nonce_without_oidc_settings_but_pkce_always() {
        let token = token_server(serde_json::json!({})).await;
        let (url, pending) = provider(config_for(&token, None))
            .authorization_url()
            .unwrap();
        assert!(pending.nonce.is_none());
        assert!(!url.query_pairs().any(|(k, _)| k == "nonce"));
        assert!(url.query_pairs().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn state_mismatch_is_rejected_before_any_request() {
        let token = token_server(serde_json::json!({})).await;
        let result = provider(config_for(&token, None))
            .exchange_code("code".to_string(), "attacker-state", pending(None))
            .await;
        assert!(
            matches!(result, Err(AuthError::InvalidToken(_))),
            "{result:?}"
        );
        assert!(token.requests().is_empty(), "no token request on bad state");
    }

    #[tokio::test]
    async fn expired_pending_auth_rejected() {
        let token = token_server(serde_json::json!({})).await;
        let mut old = pending(None);
        old.created_at -= PENDING_AUTH_MAX_AGE.as_secs() as i64 + 5;
        let result = provider(config_for(&token, None))
            .exchange_code("code".to_string(), "state-123", old)
            .await;
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn exchange_sends_pkce_verifier() {
        let token = token_server(serde_json::json!({})).await;
        provider(config_for(&token, None))
            .exchange_code("code".to_string(), "state-123", pending(None))
            .await
            .unwrap();
        let body = token.requests()[0].body_string();
        assert!(
            body.contains(&format!("code_verifier={}", "v".repeat(43))),
            "{body}"
        );
    }

    #[tokio::test]
    async fn unverified_id_token_is_never_exposed() {
        // No OIDC settings: an id_token in the response is dropped.
        let token =
            token_server(serde_json::json!({ "id_token": "header.payload.signature" })).await;
        let out = provider(config_for(&token, None))
            .exchange_code("code".to_string(), "state-123", pending(None))
            .await
            .unwrap();
        assert_eq!(out.access_token, "at-123");
        assert!(out.id_token.is_none());
        assert!(out.id_token_claims.is_none());
    }

    #[tokio::test]
    async fn valid_id_token_is_verified_and_exposed() {
        let out = exchange_signed(|iss| sign_id_token(id_claims(iss, "n-1"), "k1"), "n-1")
            .await
            .unwrap();
        assert!(out.id_token.is_some());
        assert_eq!(out.id_token_claims.unwrap()["sub"], "user-1");
    }

    #[tokio::test]
    async fn id_token_with_wrong_nonce_rejected() {
        let result =
            exchange_signed(|iss| sign_id_token(id_claims(iss, "other"), "k1"), "n-1").await;
        assert!(
            matches!(result, Err(AuthError::InvalidToken(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn id_token_with_wrong_audience_rejected() {
        let result = exchange_signed(
            |iss| {
                let mut c = id_claims(iss, "n-1");
                c["aud"] = serde_json::json!("someone-else");
                sign_id_token(c, "k1")
            },
            "n-1",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn id_token_with_wrong_issuer_rejected() {
        let result = exchange_signed(
            |_| sign_id_token(id_claims("https://evil.example", "n-1"), "k1"),
            "n-1",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expired_id_token_rejected() {
        let result = exchange_signed(
            |iss| {
                let mut c = id_claims(iss, "n-1");
                c["exp"] = serde_json::json!(chrono::Utc::now().timestamp() - 3600);
                sign_id_token(c, "k1")
            },
            "n-1",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn id_token_with_bad_signature_rejected() {
        let result = exchange_signed(
            |iss| {
                let good = sign_id_token(id_claims(iss, "n-1"), "k1");
                let (head, _sig) = good.rsplit_once('.').unwrap();
                format!("{head}.{}", URL_SAFE_NO_PAD.encode([7u8; 64]))
            },
            "n-1",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hmac_signed_id_token_rejected() {
        // alg confusion: an HS256 token "signed" with public material.
        let result = exchange_signed(
            |iss| {
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some("k1".to_string());
                jsonwebtoken::encode(
                    &header,
                    &id_claims(iss, "n-1"),
                    &EncodingKey::from_secret(jwks_json("k1").as_bytes()),
                )
                .unwrap()
            },
            "n-1",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn missing_id_token_rejected_when_oidc_expected() {
        let token = token_server(serde_json::json!({})).await;
        let jwks = jwks_server().await;
        let result = provider(config_for(&token, Some(&jwks)))
            .exchange_code("code".to_string(), "state-123", pending(Some("n-1")))
            .await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn token_client_does_not_follow_redirects() {
        // A token endpoint answering 307 must not cause the code and client
        // secret to be re-POSTed to the redirect target.
        let target = token_server(serde_json::json!({})).await;
        let redirector = StubServer::builder()
            .route(
                "POST",
                "/token",
                StubResponse::new(307, "")
                    .with_header("location", &format!("{}/token", target.url())),
            )
            .start()
            .await;
        let result = provider(config_for(&redirector, None))
            .exchange_code("code".to_string(), "state-123", pending(None))
            .await;
        assert!(result.is_err());
        assert!(target.requests().is_empty(), "redirect was followed");
    }
}
