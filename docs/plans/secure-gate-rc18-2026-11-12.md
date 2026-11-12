# secure-gate 0.9.0-rc.18 (aescrypt-rs rc.19, aescrypt-cli rc.7)

**Status (2026-11-12):** built in PR #82, released through `/publish-prep` the same day.

## Why

secure-gate 0.9.0-rc.18 is on crates.io (index checked: live, rust-version 1.87) and is the
last candidate before 0.9.0. encrypted-file-vault pins this crate exactly and also depends on
secure-gate directly, so it can take rc.18 only once a release of this crate pins rc.18 too.

## Measured state

rc.18's breaks: the bech32 checksum types become private, `traits::revealed_secrets` is
renamed to `traits::encoded_secret`, and serde's `derive` is no longer enabled for
dependents. This crate enables only `rand` and `ct-eq` and names none of those, so no code
changes. The MSRV stays 1.87.

## Change

- `=0.9.0-rc.17` → `=0.9.0-rc.18` in `Cargo.toml`, `aescrypt-cli/Cargo.toml`, `fuzz/Cargo.toml`.
- Library 0.2.0-rc.19; CLI 0.1.0-rc.7 with its library pin moved to `=0.2.0-rc.19`.
- Both lockfiles via `cargo update -p secure-gate`.
- The `aescrypt-rs-secure-gate` skill no longer records a secure-gate version (main, 615875f),
  so this PR leaves it alone.

## Verification

Rust 1.87 per the `aescrypt-rs-publish-prep` profile: fmt, clippy (host and both cross
targets, split by crate), tests on 1.87 and stable, docs with and without private items,
`bench --no-run`, fuzz smoke tests, CI green, library dry run. The CLI dry run and packaged-CLI
test need library rc.19 on crates.io, so they run after the library is published.
