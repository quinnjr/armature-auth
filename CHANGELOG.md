# Changelog — `armature-auth`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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
