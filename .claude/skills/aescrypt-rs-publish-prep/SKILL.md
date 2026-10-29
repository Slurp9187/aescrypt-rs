---
name: aescrypt-rs-publish-prep
description: This repo's release facts for the global publish-prep skill — the two crates (aescrypt-rs library, aescrypt-cli), their tags, which files carry each version, the CLI's exact pin on the library that must move in the same commit as a library bump, the CI-equivalent checks, release order, and Windows traps. Use when bumping either crate's version, cutting or tagging a release, publishing, or when cargo fails to resolve `aescrypt-rs` after a bump.
---

# Releasing aescrypt-rs and aescrypt-cli

The order, tag mechanics and dry-run rules are in the global `publish-prep` skill, and what a
changelog may claim is in `changelog-protocol`. **This file records only what is true of this
repo.**

## Two crates, two version lines

| Crate | Manifest | Changelog | Tag |
| --- | --- | --- | --- |
| `aescrypt-rs` (library) | `Cargo.toml` | `CHANGELOG.md` | `v<version>`, e.g. `v0.2.0-rc.N` |
| `aescrypt-cli` | `aescrypt-cli/Cargo.toml` | `aescrypt-cli/CHANGELOG.md` | `aescrypt-cli-v<version>`, e.g. `aescrypt-cli-v0.1.0-rc.N` |

They are versioned independently; the CLI does **not** mirror the library's version (it did
until 0.1.0-rc.1). `aescrypt-cli --version` prints both, as
`aescrypt-cli <cli version> (aescrypt-rs <library version>)`. The library's comes from
`aescrypt_rs::VERSION`, so it names the library actually linked and needs no edit on a bump
(until 0.1.0-rc.4 a hand-kept `lib_version!` macro in the CLI's `lib.rs` carried it).

## The CLI pins the library exactly — move the pin with every library bump

`aescrypt-cli/Cargo.toml` has
`aescrypt-rs = { path = "..", version = "=<library version>" }`: the path is for the
workspace, and crates.io sees only the exact version. Release candidates break APIs between
each other, so the pin is `=` on purpose; don't loosen it to a caret, and don't drop the
`path` (the CLI's tests and CI would then stop exercising the library in the repo).

**One sanctioned exception: a CLI release on an unchanged library.** When the library's
`src/` is unchanged since its last published version and its open version holds nothing for
consumers, the CLI may pin that published version from crates.io with no `path` (CLI
0.1.0-rc.5 on library rc.16, `docs/plans/cli-rc5-release-2026-10-28.md`). That avoids an
empty library release. The lockfile then carries both `aescrypt-rs` versions, and
`-p aescrypt-rs` needs `@<version>`. **Restore `path` in the same commit as the next real
library change.**

So **a library bump is not complete until the CLI follows it**, in the same commit. Otherwise
`cargo check` fails with `failed to select a version for the requirement aescrypt-rs = "=…"`.

**Library bump touches:**
1. `Cargo.toml`: `version`.
2. `CHANGELOG.md`: open `## [<version>] - Unreleased`.
3. `aescrypt-cli/Cargo.toml`: the `=<version>` pin. `tests::lib_pin_is_exact` fails if it is
   not an exact pin on the library the build linked.
4. Both lockfiles: run `cargo check --workspace` at the root, and `cargo metadata` (or any
   build) in `fuzz/`. `fuzz/` is outside the workspace and has its own lockfile.

Within a release-candidate line, nothing else names the version. The README dependency snippet
is `aescrypt-rs = "0.2.0-rc"`, which selects the newest RC, so it moves only when the line
does: to `"0.2.0"` at the stable release, or to the next line's `-rc`.

**CLI bump touches:**
1. `aescrypt-cli/Cargo.toml`: `version`.
2. `aescrypt-cli/CHANGELOG.md`: open `## [<version>] - Unreleased`.
3. `Cargo.lock`: run `cargo check --workspace`.

The install lines in `README.md` and `aescrypt-cli/README.md` are
`cargo install aescrypt-cli --version "^0.1.0-rc"`, the newest RC (plain `cargo install` skips
release candidates). Like the snippet, they move only when the line does.

## Release order

**Library before CLI.** The CLI's dry run and publish resolve its `=` pin from crates.io, so
a CLI that pins an unpublished library version cannot be packaged.

If the library has already been bumped on `main` while a CLI release is still unpublished,
publish the CLI from its tag, not from `main`:

```text
git worktree add --detach O:\Projects\Worktrees\aescrypt-rs-publish aescrypt-cli-v<version>
cd O:\Projects\Worktrees\aescrypt-rs-publish
cargo publish -p aescrypt-cli --locked
```

## Checks before a dry run (what CI runs)

Rust 1.87 is pinned in `rust-toolchain.toml`, and the lint and docs jobs use it too.

- `cargo +1.87 fmt --all --check`
- `cargo +1.87 clippy --workspace --all-targets --all-features -- -D warnings`, plus the same
  with `--target x86_64-unknown-linux-gnu` and `--target aarch64-apple-darwin`. The Windows
  host never compiles the `cfg(unix)` code, and CI's macOS job only runs tests.
- `cargo +1.87 test --workspace --all-features` (README examples run as doctests)
- `RUSTDOCFLAGS=-D warnings cargo +1.87 doc --workspace --no-deps --all-features`, then again
  with `--document-private-items`
- `cargo +1.87 bench --no-run`
- `cargo publish -p <crate> --locked --dry-run`
- For the CLI, also test the **packaged** crate: `cargo package -p aescrypt-cli --no-verify`,
  unpack the `.crate` outside the repo, run `cargo test` there. It sees the rewritten
  `[dependencies.aescrypt-rs]` table, which `lib_pin_is_exact` must still read.

## Registry index

- Library: `https://index.crates.io/ae/sc/aescrypt-rs`
- CLI: `https://index.crates.io/ae/sc/aescrypt-cli`

A 404 means the crate has never been published.

## Windows traps that have cost time here

- **PowerShell `[IO.File]` and child processes ignore `Set-Location`.** Relative paths resolve
  against the process directory, which is the shared checkout. Use absolute paths and set
  `WorkingDirectory`, or scratch files land in the repo.
- **PowerShell 5.1 mangles `"` inside native arguments**, so `git commit -m` with quotes
  breaks. Write the message to a file and use `git commit -F`.
- **`ctrl_c_at_prompt_exits_at_once` fails under Git Bash**, because of how Git Bash's console is
  inherited. Run the CLI suite from PowerShell; CI is unaffected.
- **Restoring a file with `Copy-Item` keeps its old timestamp**, so cargo may not rebuild it.
  Touch the file afterwards.
