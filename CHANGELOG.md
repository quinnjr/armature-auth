# Changelog — `armature-auth`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- Adopted the `auth` criterion benchmark (password hashing, API keys, guards, OAuth2, session IDs) from the root package's `benches/`. Run it with `cargo bench -p armature-auth --bench auth`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry.

### Fixed

- **Breaking:** `SamlConfig::allow_idp_initiated` defaults to `false`, and `validate_response_with_request_id` correlates `InResponseTo` and RelayState. The generated RelayState was previously handed to the caller and never checked, leaving SSO login-CSRF and unsolicited-response replay open.
- **Breaking:** `MagicLinkToken::verify` is renamed `is_usable`, and the new `verify_token(candidate)` performs the constant-time secret comparison. The old name checked only expiry and the used flag while the module example presented it as the login check.
- Backup codes use all eight bytes of entropy (64 bits). Half were drawn and discarded, leaving 32 bits on a 2FA bypass credential.
- An unknown username now runs a dummy KDF verification, closing a timing-based user-enumeration oracle.
- `ApiKeyManager` rate-limit state moved to a `DashMap`; every validation previously serialized on one process-wide mutex held across a sweep.

### Changed — `0.1.3` → `0.1.4`

- Migrated onto `armature-core` `0.8`'s `Bytes`-backed request and response types. No behavior change beyond what that migration implies; see [`armature-core/CHANGELOG.md`](../armature-core/CHANGELOG.md).

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
