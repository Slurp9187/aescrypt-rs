# secure-gate 0.9.0-rc.16 and MSRV 1.87

**Status (2026-10-29):** approved by the owner and being built. Verified against main at `b49bcf4`.

## Why

secure-gate 0.9.0-rc.16 is on crates.io (index checked: not yanked, `rust_version` 1.87). It
raises secure-gate's MSRV from 1.85 to 1.87 for RUSTSEC-2026-0385. The advisory is about ctutils
< 0.4.4, which secure-gate reaches only through its `sealed` feature. Every patched ctutils
declares rust-version 1.87.

This crate enables only `rand` and `ct-eq`, so ctutils is not in its build. A dependency that
declares 1.87 still sets the floor, so taking rc.16 means declaring 1.87 ourselves. The owner
approved the raise on 2026-10-29.

secure-gate's owner plans to soak rc.16 for a few days and then promote it unchanged to 0.9.0.
A real build against it now is the feedback they asked for.

## Measured state

- **rc.16 removed two APIs.** `from_rng` and the `From*Str` decoder traits are gone. Nothing in
  `src/`, `tests/`, `benches/`, `aescrypt-cli/` or `fuzz/` uses either.
- **rc.16 requires `zeroize ^1.9.1`.** `Cargo.lock` holds 1.8.2, so the lockfile has to move.
  zeroize 1.9.1 declares rust-version 1.85. This crate never calls
  `EncodedSecret::into_zeroizing`, so its opaque `Debug` does not affect us.
- **1.85 is declared in:**
  - `rust-version` in `Cargo.toml`, `aescrypt-cli/Cargo.toml` and `fuzz/Cargo.toml`
  - `rust-toolchain.toml`
  - `.github/workflows/msrv.yml`
  - the MSRV section of `src/lib.rs`
  - the badges and MSRV lines in `README.md`, `aescrypt-cli/README.md` and `fuzz/README.md`
  - the CI-check list in `.claude/skills/aescrypt-rs-publish-prep/SKILL.md`
- **Library 0.2.0-rc.17 is published,** so this change opens library **0.2.0-rc.18**.
- **The CLI's library pin.** CLI 0.1.0-rc.5 pins the registry library `=0.2.0-rc.16` with no
  `path` (`docs/plans/cli-rc5-release-2026-10-28.md`). That library pins secure-gate rc.15.
  Leaving the CLI there while it takes secure-gate rc.16 would put two secure-gate copies in its
  graph. This is the "next real library change" that the rc.5 plan says restores `path`.

## Change (one PR)

1. **secure-gate.** Change `=0.9.0-rc.15` to `=0.9.0-rc.16` in all three manifests. The lines
   stay character-identical.
2. **MSRV.** Change 1.85 to 1.87 everywhere listed above.
   - The `Cargo.toml` and `msrv.yml` comments that called clap 4.6's 1.85 a "zero margin" edge
     are reworded. The floor now comes from secure-gate.
   - `bench --no-run` stays in CI as the guard on dev-dependency drift.
   - criterion 0.8 (rustc 1.86) now fits under the floor. It is **not** bumped here; that would
     be a separate change.
3. **Versions.**
   - Library: `0.2.0-rc.18`, `## [0.2.0-rc.18] - Unreleased`.
   - CLI: `aescrypt-rs = { path = "..", version = "=0.2.0-rc.18" }` (`path` restored), version
     `0.1.0-rc.6`, `## [0.1.0-rc.6] - Unreleased`.
   - Each changelog names RUSTSEC-2026-0385 as the reason for the MSRV raise.
4. **Lockfiles.** Run `cargo update -p secure-gate -p zeroize` at the root and in `fuzz/`. Never
   a bare `cargo update`. Then check `cargo tree -i ctutils`, which should find nothing.

## Verification

- `cargo +1.87`: `fmt --check`; `clippy --workspace --all-targets --all-features -D warnings`
  (host, plus linux-gnu and aarch64-apple-darwin targets); `test --workspace --all-features`;
  `doc` with `-D warnings`, with and without private items; `bench --no-run`.
- `cargo +stable test --workspace --all-features`.
- The fuzz crate's smoke tests on 1.87.
- Both CI workflows green on the PR.
- The owner publishes later from main at the tags: library first, then the CLI.
