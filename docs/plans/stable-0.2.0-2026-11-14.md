# aescrypt-rs 0.2.0 and aescrypt-cli 0.1.0 stable (2026-11-14)

## Why now

aescrypt-rs has been held at release candidate only because secure-gate, its one
substantive dependency, was still shipping breaking changes between its own release
candidates. secure-gate 0.9.0 was published on 2026-11-14. It is on the crates.io index,
not yanked, and declares rust-version 1.87.

0.9.0 has the same API as 0.9.0-rc.19. The only source changes are doc comments in
`src/sealed/`, a feature this crate does not enable, and the dependency tables are the
same. So the stable release needs no code change.

The owner decided on 2026-11-14 that the CLI goes stable with the library.

## Changes (one PR, worktree `O:\Projects\Worktrees\aescrypt-rs-stable-020`)

1. **secure-gate pin:** `=0.9.0-rc.19` becomes `"0.9"` in `Cargo.toml`,
   `aescrypt-cli/Cargo.toml` and `fuzz/Cargo.toml`, and the three lines stay
   character-identical.
   - The exact pin was only there because the RCs broke between each other. In a stable
     crate it would stop every consumer from taking secure-gate patch releases, security
     fixes included.
   - Rewrite the comment above the pin in `Cargo.toml`: the NOTE that `"0.9"` resolves
     to nothing stops being true once 0.9.0 exists.
   - Update both lockfiles with `cargo update -p secure-gate`.
2. **Library:** `0.2.0-rc.20` becomes `0.2.0`.
   - `CHANGELOG.md` gets `## [0.2.0] - 2026-11-14`, saying it is the first stable
     release and what semver now covers.
   - The README dependency snippet `"0.2.0-rc"` becomes `"0.2"`, and the paragraph about
     release candidates goes.
3. **CLI:** `0.1.0-rc.8` becomes `0.1.0`.
   - Its library pin becomes `=0.2.0`. It stays exact, because a binary ships the
     combination it was tested on, and `lib_pin_is_exact` enforces that.
   - Reword that test's doc comment, which justifies the pin with RC breakage.
   - In both READMEs, `cargo install aescrypt-cli --version "^0.1.0-rc"` becomes a plain
     `cargo install aescrypt-cli`, and the RC note in `aescrypt-cli/README.md` goes.
   - `aescrypt-cli/CHANGELOG.md` gets `## [0.1.0] - 2026-11-14`.
4. **Repo skills:** update `aescrypt-rs-publish-prep`, which describes RC snippets and
   install lines, and `aescrypt-rs-secure-gate`, whose dependency line shows the `=` pin,
   to the stable state.

The open issues #66, #77 and #78 are additive. They can land in 0.2.x, so none of them
blocks the release.

## Verification

- Run the CI-equivalent checks from `aescrypt-rs-publish-prep` on 1.87:
  - fmt
  - clippy, on the host and on the cross targets
  - doc, with and without private items
  - `bench --no-run`
  - the fuzz smoke tests
  - the tests from PowerShell
- Run the tests on stable.
- Pass the changelog checker for both crates.
- Do a library dry run. The CLI dry run and the packaged-CLI test need 0.2.0 on
  crates.io first, so they run after the owner publishes the library.
- Get CI green on the PR, squash-merge it, then push annotated tags `v0.2.0` and
  `aescrypt-cli-v0.1.0`. The owner publishes from main at the tags.
