# aescrypt-cli: seal the stdout stage 64 KiB at a time

**Status (2026-10-28, UTC):** built, in the PR that records this result; for aescrypt-cli 0.1.0-rc.5. Verified at main `8bbd5f7`.
Follows #72 (the sealed stage, PR #74). The EFV coordinator agreed: EFV uses only the library,
so this is CLI-only, and it does not wait on the EFV PERFORMANCE profile (#77, #78). PRs for
this plan say `Plan: docs/plans/cli-seal-chunk-2026-10-28.md` and `Refs #72`.

## Measured state (before)

- **Decrypting to stdout** seals pass 2's plaintext into a temp file (AES-256-CTR under a
  per-stage random key), and `Sealed::copy_out` unseals it to stdout after the whole decryption
  succeeds (`aescrypt-cli/src/output.rs`).
- **The chunk is 4 KiB** (`SEAL_CHUNK`). Each `Sealed::write` and each `copy_out` step builds a
  fresh stack `Fixed` chunk, and `apply_keystream` a fresh `SEAL_CHUNK + 16` keystream buffer.
  At 1 GiB that is about 262,000 stage writes, 262,000 reads back and 262,000 stdout writes,
  against about 16,000 64 KiB writes for file to file.
- **Measured** on one desktop (Ryzen 9 9950X3D, AES-NI; ratios matter, absolute times are
  lower elsewhere), release CLI, 1 GiB random file, warm page cache, all on C:, output hashes
  matched:

  | decrypt 1 GiB | time |
  |---|---|
  | file to file | about 2.0 s (to-disk timings swing to 8-11 s under write-back pressure) |
  | stdout to NUL, `SEAL_CHUNK` = 4 KiB | 4.25-4.4 s |
  | stdout to NUL, throwaway build with 64 KiB | 2.37-2.79 s |

## Target model

The stage is sealed and unsealed **64 KiB at a time**, the library's largest span, through
**two heap buffers made once per stage** and wiped on drop: one plaintext chunk and one
keystream. One AES call per chunk, as now. Everything else is unchanged: the seal, the key,
the all-or-nothing stdout, error labels, and the stage's place and permissions.

## Change (one PR)

- `SEAL_CHUNK = 64 * 1024`.
- `Sealed` holds `chunk: Dynamic<[u8]>` (`SEAL_CHUNK`) and `keystream: Dynamic<[u8]>`
  (`SEAL_CHUNK + 16`), each `Dynamic::new(vec![0u8; len])`, the library's `heap_span` idiom: a
  boxed slice cannot grow, so no unwiped copy is left behind, and nothing 64 KiB sits on the
  stack.
- `apply_keystream` takes the keystream buffer. The CTR arithmetic is unchanged; the worst case
  is skip 15 + 65,536 rounded up to 65,552 = `SEAL_CHUNK + 16`.
- `Sealed::write` and `copy_out` reuse both buffers.

## Tests and acceptance

- `sealed_stage_round_trips_and_holds_no_plaintext`: sizes across the new edges (65,535,
  65,536, 65,537 and 200,000 added), written in 7,001-byte pieces **and** in one `write_all`.
- New: the keystream at a fixed key is the same however the bytes are split across calls.
- **Falsified:** a broken CTR offset turns the round-trip test red.
- Unchanged and green: `sealed_stages_have_their_own_keys`, `dropped_stages_leave_nothing`,
  `changed_input_writes_nothing_to_stdout`, the stdout tests in `tests/run.rs`.
- Gates: fmt; clippy 1.85 for host, Linux and macOS; tests on 1.85 and stable; docs with and
  without private items; `bench --no-run`; fuzz smoke tests.
- **Acceptance:** decrypting 1 GiB to stdout to NUL takes at most about 1.4x file to file on
  the machine above, with matching output hashes.

## Result

Release CLIs from main (`c2d3fd6`) and the branch, three alternating rounds, same machine and
file as above. Every stdout output matched the plaintext's SHA-256.

| decrypt 1 GiB | main | branch |
|---|---|---|
| file to file | 2.41–4.34 s | 1.96–4.45 s (same code; disk write-back noise) |
| stdout to NUL | 4.35–5.01 s | 2.14–2.70 s |
| stdout to a file | 6.96–9.41 s | 2.63–2.91 s |

**Acceptance met:** stdout to NUL in rounds 2 and 3 took 2.14 s against 1.96–1.98 s file to
file, about 1.1×. Both new tests went red with the CTR offset broken (`skip` dropped), then
green restored. All gates passed.

## Non-scope

- **Releasing CLI rc.5.** It pins `aescrypt-rs = "=0.2.0-rc.17"`, so library rc.17 is
  published first; each is its own `/publish-prep`.
- **Library speed work** (#77, #78): waits on the EFV PERFORMANCE profile.
- **Putting the stage on the destination's volume:** stdout has no destination; the system
  temp directory stays.
