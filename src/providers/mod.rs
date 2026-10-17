// OAuth2 provider implementations

use std::sync::OnceLock;

use crate::{AuthError, Result};

/// Shared `reqwest::Client` for the stateless (unit-struct) providers.
///
/// Building a `reqwest::Client` allocates a connection pool and loads the TLS
/// root store, so constructing one per request is wasteful. These providers
/// expose only static async methods and hold no state, so they share a single
/// lazily-initialized client and clone the cheap `Arc`-backed handle per call.
/// Like every provider client it does not follow redirects (see
/// [`crate::oauth2`]).
pub(crate) fn shared_http_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(crate::oauth2::build_http_client).clone()
}

/// Check that `host` is a bare DNS hostname (e.g. `dev-123.okta.com`) before
/// it is spliced into `https://{host}/...` endpoint URLs.
///
/// Rejects schemes, paths, userinfo (`@`), ports, query/fragment characters,
/// whitespace and anything else outside `[A-Za-z0-9.-]`, so a configured
/// domain cannot redirect token requests (and the client secret) elsewhere.
pub(crate) fn validate_hostname(kind: &str, host: &str) -> Result<()> {
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if host.is_empty() || host.len() > 253 || !labels_ok {
        return Err(AuthError::Configuration(format!(
            "{kind} must be a bare hostname such as `example.com` (got {host:?})"
        )));
    }
    Ok(())
}

/// Implement `Debug` for a provider config, redacting `client_secret`.
macro_rules! debug_redacting_client_secret {
    ($ty:ident { $($field:ident),* $(,)? }) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($field), &self.$field))*
                    .field("client_secret", &"<redacted>")
                    .finish()
            }
        }
    };
}
pub(crate) use debug_redacting_client_secret;

pub mod auth0;
pub mod aws_cognito;
pub mod discord;
pub mod github;
pub mod gitlab;
pub mod google;
pub mod linkedin;
pub mod microsoft;
pub mod okta;

pub use auth0::{Auth0Config, Auth0Provider};
pub use aws_cognito::{AwsCognitoConfig, AwsCognitoProvider};
pub use discord::{DiscordProvider, DiscordUser};
pub use github::{GitHubProvider, GitHubUser};
pub use gitlab::{GitLabProvider, GitLabUser};
pub use google::{GoogleConfig, GoogleProvider};
pub use linkedin::{LinkedInProvider, LinkedInUser};
pub use microsoft::{MicrosoftEntraConfig, MicrosoftEntraProvider};
pub use okta::{OktaConfig, OktaProvider};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_validation() {
        for ok in [
            "dev-123.okta.com",
            "myapp.us.auth0.com",
            "localhost",
            "a.b-c.d",
        ] {
            assert!(validate_hostname("domain", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "evil.com/x",
            "a@b",
            "user@evil.com",
            "https://x",
            "x.com:8443",
            "x.com?y",
            "x.com#y",
            " x.com",
            "x .com",
            "x..com",
            "-x.com",
            "x.com.",
            "x.com\\@evil",
        ] {
            assert!(validate_hostname("domain", bad).is_err(), "{bad:?}");
        }
    }
}
