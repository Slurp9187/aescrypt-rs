# secure-gate 0.9.0-rc.16 and MSRV 1.87

**Status (2026-10-29):** approved by the owner and built in PR #81; scope widened the same day (see the addendum). Verified against main at `b49bcf4`.

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

## Addendum (2026-10-29): dependency refresh and RustCrypto zeroize

The owner asked for a recency check of every dependency, with `zeroize` turned on wherever a
dependency now offers it, all in this release. They also asked for the tags
(`v0.2.0-rc.18`, `aescrypt-cli-v0.1.0-rc.6`) on the merge commit once it is done.

**What the index showed** (latest release, its rust-version, and whether it has `zeroize`):

| Crate | Was | Now | Note |
| --- | --- | --- | --- |
| `aes` | 0.8 | 0.9 | `zeroize` via an optional dep; 0.9.3 needs 1.89, so 1.87 resolves 0.9.2 |
| `hmac` | 0.12 | 0.13 | **new `zeroize` feature** (`digest/zeroize`) |
| `sha2` | 0.10 | 0.11 | **new `zeroize` feature**; 0.11.1 needs 1.88, so 1.87 resolves 0.11.0 |
| `pbkdf2` | 0.12 | 0.13 | `default-features = false, features = ["hmac"]` |
| `criterion` (dev) | 0.7 | 0.8 | rustc 1.86, fits the new floor |
| `expectrl` (unix dev) | 0.7 | 0.9 | `Session` became generic: use `session::OsSession` and the `Expect` trait |
| everything else | | | already on the newest compatible minor; lockfiles refreshed |

**Port to cipher 0.5 / digest 0.11:**
- `BlockEncrypt`/`BlockDecrypt` → `BlockCipherEncrypt`/`BlockCipherDecrypt`.
- `BlockClosure`/`BlockBackend` → `BlockCipherEncClosure`/`BlockCipherEncBackend`, which take
  `&B`.
- `proc_block_inplace` → `encrypt_block_inplace`.
- `GenericArray::from_mut_slice` → `From<&mut [u8; N]>`, or `try_into` on chunks.
- `Mac::new_from_slice` → `KeyInit::new_from_slice`.

**Checked from source:**
- `Sha256` and `Aes256Enc`/`Aes256Dec` implement `ZeroizeOnDrop` with the features on (a
  compile-time test).
- `Hmac<Sha256>` does not declare the marker. Its two SHA-256 cores have `Drop` impls that wipe
  their state under `sha2/zeroize`, and its `BlockBuffer` wipes under `block-buffer/zeroize`,
  which `digest/zeroize` enables. That feature is active in our graph (`cargo tree -e
  features`).
- What stays out of reach: stale copies left by moves, and the unwiped stack batch of `aes`'s
  software backend. The Security Model, README, inline comments and changelogs now say this.

**Public API:** `encryption::encrypt_session_block` and `encryption::write_hmac` name `aes` and
`hmac` types, so those change. The crate-root API names no RustCrypto type.

**Gates:** the same as above, plus a throughput comparison against main (alternating rounds) to
show the AES-NI span loop kept its speed. Cross-target clippy is now split by crate, because
criterion 0.8's `alloca` build script cannot cross-compile from Windows.

## Addendum 2 (2026-10-29): secure-gate rc.17

secure-gate 0.9.0-rc.17 is on crates.io (index checked: live, rust-version 1.87) and replaces
rc.16 as the 0.9.0 candidate. The secure-gate owner asked every dependent to take it inside its
current unpublished release, so this PR re-pins all three manifests to `=0.9.0-rc.17`.

rc.17's changes:
- bech32 goes from 0.11 to 0.12. That is optional and off here: it appears in the lockfile but
  is never compiled (`cargo tree -i bech32` prints nothing).
- Poly1305 state is now wiped under `sealed`, which this crate does not enable.
- A lockfile refresh.

No code change was needed.
