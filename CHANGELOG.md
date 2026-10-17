# Changelog — `armature-auth`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- **Guards fail closed (Breaking).** `AuthGuard` now requires a verified `UserContext` extension (attached by `JwtAuthMiddleware`); a bare `Authorization: Bearer …` header no longer passes. `RoleGuard`/`PermissionGuard` no longer consult the header at all, and an empty requirement (`RoleGuard::any(vec![])`, `PermissionGuard::any(vec![])`) now means "any authenticated caller" instead of "allow". Missing identity is `AuthError::Unauthorized`; insufficient role/permission stays `Forbidden`. Migration: register `JwtAuthMiddleware` ahead of guarded routes.
- `AuthGuard`, `RoleGuard` and `PermissionGuard` implement `armature_core::Guard` (missing identity → `Error::Unauthorized`, otherwise `Error::Forbidden`), so they plug into core routing. With both traits in scope, call `Guard::can_activate(&guard, &req)`.
- **Refresh tokens are no longer accepted as access tokens.** `JwtAuthMiddleware` and `JwtStrategy` verify with `JwtManager::verify_access`, rejecting tokens whose `token_use` is present and not `"access"` (or with the refresh `typ` header). The middleware also rejects tokens without a subject claim and requests with more than one `Authorization` header, and accepts the `Bearer` scheme case-insensitively.
- `JwtAuthMiddleware` also inserts `armature_core::VerifiedIdentity` (the subject) on successful verification, so core's fail-closed `AuthenticationGuard` admits the request. Register it with `Application::use_middleware` so it runs before guards.
- `JwtAuthMiddleware::optional` no longer forwards a rejected credential: the `Authorization` header is stripped and a new `RejectedCredentials` marker extension is inserted.
- **API keys are no longer stored in plaintext (Breaking).** `ApiKeyManager::new(store, pepper)` now requires a ≥ 32-byte server-side pepper and returns `Result`; the store only ever receives `ApiKey::key_hash` = hex `HMAC-SHA256(pepper, key)` (the `key` field is gone), and `ApiKeyStore::find_by_key` is replaced by `find_by_key_hash`. `generate`/`rotate` return a `GeneratedApiKey` whose `secret()` is the only copy of the plaintext (redacted `Debug`, not `Serialize`). `validate` re-checks the hash in constant time. `ApiKey`'s `Debug` redacts the hash. `ApiKeyManager::hash_key` is now a keyed method. Migration: provision a pepper, re-issue keys (existing plaintext rows cannot be converted without the keys).
- **Magic links (Breaking).** Records store only `MagicLinkToken::token_hash` (SHA-256); `MagicLinkToken::generate` returns an `IssuedMagicLink` holding the plaintext once. Redemption is single-step and atomic: `redeem_magic_link(store, token)` over the new `MagicLinkStore::consume` (with `InMemoryMagicLinkStore`), or `MagicLinkToken::consume(candidate)` for a record you hold exclusively. `verify_token`, `mark_used` and `to_url` on the record are removed. Migration: store `issued.record`, e-mail `issued.to_url(..)`, redeem with `redeem_magic_link`.
- **TOTP replay protection (Breaking).** `TotpSecret::verify(code, time_step, last_accepted_step)` now returns `Option<u64>` — the matched time step to persist — and never accepts a step at or before `last_accepted_step`; `verify_and_record` updates it in place. `time_step == 0` is an `InvalidTimeStep` error instead of a panic. `TotpSecret::from_base32` validates and returns `Result`. `TotpSecret` is no longer `Serialize`/`Deserialize` (persist `to_base32()` explicitly) and redacts `Debug`.
- **Backup codes stored hashed (Breaking).** `BackupCodes::generate` returns `GeneratedBackupCodes` (`stored` + one-time `plaintext()`); `BackupCodes` holds `code_hashes` only, accepts codes with or without hyphens/case, and redacts `Debug`. Codes now carry 80 bits (was 64) so the unkeyed hash is not brute-forceable.
- **OAuth2/OIDC (Breaking).** PKCE (S256) on every flow, library-verified `state` (constant time), OIDC `nonce`. `OAuth2Provider::authorization_url` returns `(Url, PendingAuth)` and `exchange_code(code, returned_state, pending)` replaces `exchange_code(code)`; `PendingAuth` (redacted `Debug`, serializable for server-side session storage only) expires after 10 minutes. `id_token`s are verified (JWKS, asymmetric algorithms only, `iss`/`aud`/`azp`/`exp`/`nonce`) and are only exposed — with their claims in the new `OAuth2Token::id_token_claims` — after verification; providers without OIDC settings (`OAuth2Config::with_oidc`) never surface one. Google, Microsoft, Okta, Auth0 and Cognito (with the new `AwsCognitoConfig::with_user_pool_id`) are configured for OIDC. `get_user_info` rejects a userinfo `sub` that differs from the verified `id_token`'s.
- **Microsoft identity (Breaking).** `MicrosoftEntraProvider::get_user_info` keys the user on the verified `id_token`'s `tid` + `oid` (`sub` = `"{tid}:{oid}"`), reports `email_verified: Some(false)` for the mutable Graph `mail`, and errors without a verified `id_token`.
- All provider HTTP calls (token, userinfo, JWKS) use a rustls client that does not follow redirects, so a 307/308 cannot re-send the client secret and code elsewhere. oauth2's own reqwest 0.12 client is no longer used (`oauth2` with `default-features = false`).
- Provider domains (Okta, Auth0, Cognito user-pool domain, Microsoft tenant) must be bare hostnames; constructors reject schemes, paths, `@`, ports and whitespace. Cognito `region`/`user_pool_id` are validated too. Google userinfo moved to the OIDC endpoint (returns `sub`).
- Secrets are redacted from `Debug`: `OAuth2Config.client_secret`, every provider config, `OAuth2Token` tokens, `SamlConfig.sp_private_key`, `LocalCredentials.password` (also skipped when serializing), `JwtCredentials.token`.
- **Password hashing.** Argon2id defaults raised to m = 64 MiB, t = 3, p = 1 (configurable via `PasswordHasher::with_argon2_params`; existing hashes still verify). bcrypt hashing rejects passwords over 72 bytes instead of truncating, and verification no longer truncates. New `PasswordHasher::needs_rehash`, `hash_async`/`verify_async` (Tokio blocking pool) and `with_bcrypt_cost`. `LocalStrategy` hashes on the blocking pool and rehashes on login through the new `LocalUserStore::update_password_hash` (default no-op).
- **SAML replay protection (Breaking).** Accepted assertion IDs are recorded in a pluggable `AssertionReplayCache` (default per-process `InMemoryReplayCache`; `SamlServiceProvider::with_replay_cache` for a shared one) until the assertion's earliest `NotOnOrAfter`, and replays are rejected. `SamlProvider::validate_response` now requires the AuthnRequest ID (plus optional RelayState) and is async; the uncorrelated `validate_response(saml_response)` and `validate_response_with_request_id` are removed. IdP-initiated SSO goes through the explicit `SamlServiceProvider::validate_unsolicited_response`, refused unless `allow_idp_initiated`. `SamlAssertion` gains `assertion_id`.

### Changed

- **Breaking:** requires `armature-jwt` with `JwtConfig::new` returning `Result` (see its changelog).
- TLS: with `oauth2`'s HTTP client gone, the only OpenSSL in the tree comes from the opt-in `saml` (samael/xmlsec) and `webauthn` (webauthn-rs) features; `native-tls` is not present.

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- **Breaking:** requires `armature-jwt` 0.4 (was `0.3`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.

### Changed — dependencies

- `argon2` `0.5` → `0.6` (default features; `std` no longer exists), `base64` `0.23`, `quick-xml` `0.42`, `reqwest` `0.13`. Argon2 hashing now uses `hash_password`'s built-in 16-byte getrandom salt and `password_hash::phc::PasswordHash`; algorithm and parameters are unchanged (argon2id, v=19, m=19456, t=2, p=1). A test pins a PHC string produced by argon2 0.5, so hashes stored before the upgrade still verify. No public API change.

## [0.3.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.
- Requires `armature-jwt` 0.3 (was `0.2`); it moved its minor in the same train for the same reason.

## [0.2.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
