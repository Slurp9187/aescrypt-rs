# aescrypt-cli 0.1.0-rc.5: release on the published library, tested first

**Status (2026-10-28, UTC):** planned. Verified at main `7cafda7`. Content: the 64 KiB seal chunk
(#79, `docs/plans/cli-seal-chunk-2026-10-28.md`). The test list is the EFV coordinator's,
relayed for the owner, who asked for testing before publishing. Refs #72.

## Measured state

- **The CLI pins** `aescrypt-rs = { path = "..", version = "=0.2.0-rc.17" }`.
- **Library rc.17 is empty for consumers.** `git diff v0.2.0-rc.16..main -- src/` is empty. The
  only manifest change is the new `[[bench]] small_files` and its comment. Publishing it only to
  satisfy the CLI's pin would be an empty release.
- **The owner's decision (via the coordinator):** CLI rc.5 depends on the published
  `aescrypt-rs =0.2.0-rc.16`. Library rc.17 stays open on main until it has real content.

## Change: pin the registry release (one PR)

- **`aescrypt-cli/Cargo.toml`:** `aescrypt-rs = { version = "=0.2.0-rc.16" }`, with no `path`,
  and a comment explaining why. Cargo allows the registry release and the workspace's own
  library in one graph. The lockfile carries both, and `-p aescrypt-rs` would need `@<version>`.
- **`lib_pin_is_exact`** keeps working unchanged: it reads `version = "=..."` and compares it with
  `aescrypt_rs::VERSION`, which now comes from the registry crate.
- **CLI CHANGELOG:** "Built on `aescrypt-rs` 0.2.0-rc.16, unchanged from rc.4."
- **The trade, stated:** while the path is off, the CLI's tests run against registry rc.16, not
  the repo's library. That is the same code today. The `path` returns in the same commit as the
  first real library change, and the repo publish skill gets a line saying so.
- **Fallback:** if the workspace can't build both, or CI breaks in more than a few lines, cut
  library rc.17 instead and say why.

## Tests before the cut (on the exact commit to be tagged)

| # | Check | Pass when |
|---|---|---|
| 1 | Gates: fmt; clippy 1.85 `-D warnings` for host, Linux and macOS; library and CLI tests on 1.85 and stable; docs; bench build; fuzz smoke; `cargo publish -p aescrypt-cli --dry-run` against registry rc.16; packaged-crate test | all green |
| 2 | Interop with stock AES Crypt 4.7.0.0 (`C:\Program Files\AES Crypt\aescrypt.exe`): CLI-encrypted files decrypt there, and stock-encrypted files decrypt through the CLI to a file and to stdout | every hash matches |
| 3 | Stdout decrypt at 0 B, 1 B, 16 B, 65,535 / 65,536 / 65,537 B, 3 × 64 KiB and 1 GiB; tampered file; wrong password; truncated stdin pipe | hashes match; every failure leaves stdout empty and exits nonzero |
| 4 | No plaintext on disk: scan the stage during a 1 GiB stdout decrypt for a known marker; kill midway and inspect what's left | zero hits; leftovers are ciphertext or nothing |
| 5 | Peak memory (working set) of a stdout decrypt at 64 MiB and 1 GiB | flat |
| 6 | `small-audit` of #79's diff (wipe after every step, buffer reuse) | no unresolved finding |

Big files go in `O:\EFV-drive\perf\aescrypt-cli-rc5\`. One PASS/FAIL line per item goes to the
coordinator.

## Then

Cut (CHANGELOG date, via PR), dry run on the merge commit, tag `aescrypt-cli-v0.1.0-rc.5`, push
and verify it. The owner publishes.

## Non-scope

- Library rc.17's release.
- #77 and #78: parked, with EFV's profile on each.
