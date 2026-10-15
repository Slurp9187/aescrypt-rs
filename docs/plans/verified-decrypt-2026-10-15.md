# aescrypt-rs: verify-first decrypt (`decrypt_verified`) for EFV #1193

**Status (2026-10-15):** approved by the owner. The EFV streaming coordinator decided
Q1–Q6 as recommended; Q7, publishing 0.2.0-rc.13, stays with the owner. Tracking issue
#58, CLI follow-up #59, built in PR #60 (S1–S6).

## Context

`decrypt` (src/decryption/decrypt.rs:165) works in one pass. `decrypt_cbc_loop`
(src/decryption/stream/context.rs:114) writes each plaintext block to `W` as soon as it
decrypts it. `verify_payload_hmac` (src/decryption/stream/versions.rs:33) checks the tag
only after EOF. As a result, unauthenticated plaintext reaches the caller's writer, and the
docs say so (decrypt.rs:55-65). EFV's `AescryptProtocol::decrypt_streaming` passes its own
`W` straight through, which breaks #1193's contract that the tag is verified before any
plaintext is released.

The owner's fix is an **additive two-pass decrypt over `R: Read + Seek`**. Pass 1 streams
the ciphertext through the HMAC and checks the tag. Pass 2 seeks back, decrypts to `W` and
re-checks the tag. The one-pass `decrypt` stays as it is, for non-seekable input. EFV
adopts the new function in #1193 A3 (EFV ZIP & AGE STREAMING).

## Research findings

### (a) What the HMAC covers, for each version

Taken from the code: `hmac.update` runs over every 16-byte ciphertext block
(context.rs:140), and over nothing else.

| Ver | Payload key | Session block | Final-block length comes from | Length authenticated? | Verdict |
|---|---|---|---|---|---|
| v0 | setup key used directly (session.rs:73) | none | header byte 5, low nibble (read.rs:102) | **no** | **Safe for content.** Every released byte comes from an authenticated block. The length is malleable by up to 15 bytes, which the format cannot fix. Bonus: a wrong password now writes **0 bytes**. Today it writes garbage, because v0 has no session check. |
| v1 | session key | HMAC'd (setup key) | trailer byte 0, low nibble (trailer.rs:31) | **no** | Safe for content. Same length limit as v0. |
| v2 | session key | HMAC'd | trailer byte 0 | **no** | Same as v1. Extensions are parsed before authentication, bounded, and not re-read in pass 2. |
| v3 | session key | HMAC'd, version byte folded in | PKCS#7 inside the ciphertext | **yes** | **Fully safe.** With the final-block check in pass 1 (below), the result is "Ok or 0 bytes written". |

**Does the truncated last block need a check of its own? No.** The modulo byte only chooses
how much of one authenticated block to release: 1 to 16 bytes, and `0` means 16
(trailer.rs:52). It can never inject bytes the attacker chose. At worst it truncates real
data or exposes the encryptor's own fill bytes. Those bytes are authenticated, but their
meaning is not. No check can close the gap, because the format has no authenticated length
to compare against. The high nibble of the modulo byte is ignored today. Rejecting a
non-zero high nibble would add a compatibility risk and still not close the gap, so I
recommend against it (Q5). Removing or reordering whole blocks changes the HMAC, so the
existing check catches it. Verify-first proves **every released byte is authentic
ciphertext decrypted under the session key**. For v3 it also proves the exact length.

**Gap found: v3 PKCS#7.** Padding is validated only after decryption (trailer.rs:65). If a
file has a valid HMAC but bad padding (a broken encryptor, not an attacker), pass 2 would
already have written every block except the last before it failed. **Fix:** pass 1 also
decrypts the final ciphertext block into a `Block16`, which zeroizes and is never written,
and validates the padding with the existing constant-time logic. The block and the one
before it (or the session IV) are still in the 64-byte ring after `advance_tail`: the
final block is at `tail-16` and its CBC chaining input is at `tail-32`. That makes the
promise "no plaintext reaches W unless decrypt will succeed" true for v3 too, apart from
I/O errors and input that changes between passes (Q4).

### (b) KDF once, key held in its wrapper

Split `decrypt` into a private `open_session(&mut R) -> SessionState`. It holds `version`,
`reserved_modulo`, `session_iv: Iv16` and `session_key: Aes256Key32`, all existing
zeroizing aliases. `SessionState` derives no `Clone`. The payload start is recorded with
`input.stream_position()` after the session block, not assumed to be 0, so an AES Crypt
stream embedded at an offset also works. Pass 2 does `seek(SeekFrom::Start(payload_start))`
and reuses the same `SessionState` by reference. There is no second KDF, header parse or
session HMAC. `decrypt` itself becomes `open_session` followed by
`decrypt_ciphertext_stream`, and its behavior is unchanged.

### (c) The #1193 contract and its guards

- **Bounded memory.** Both passes use the existing 64-byte ring and fixed `SpanBuffer`s.
  The only new state is one `Trailer32` tag and one `Option<u8>` modulo from pass 1.
  Nothing scales with the input size.
- **Cancel driven by the reader.** `read_until_full` (utilities.rs:110) returns any read
  error at once, `Interrupted` included, and the error becomes `AescryptError::Io`.
  Cancelling in pass 1 writes 0 bytes. Cancelling in pass 2 returns `Io` after some
  verified plaintext has been written, and the caller discards `W`. The KDF itself cannot
  be interrupted, which is the same convention as the siblings.
- **secure-gate =0.9.0-rc.12 hygiene.** No new alias is needed. The pass-1 tag is a
  `Trailer32` and the v3 check block is a `Block16`. One caveat: there are now two
  `HmacSha256` states, and `hmac` 0.12 cannot zeroize them. That is the class of residue
  the crate-level Security Model already documents. The doc note is updated; nothing new
  is introduced.
- **Byte-identical output.** On `Ok`, the output is identical to `decrypt` on all 63
  vectors. On `Err` the two differ by design: verified writes 0 bytes where `decrypt`
  writes a partial result.
- **Tamper test.** Flipping the last ciphertext byte writes 0 bytes to a counting `W`, for
  each version.

Each guard is removed once and seen to fail, then put back:

| Guard | Test that must fail without it |
|---|---|
| G1 pass-1 tag check | flip the last ciphertext byte (each version) → `W` gets 0 bytes |
| G2 v3 final-block padding check in pass 1 | a crafted v3 file with a valid HMAC and bad padding, built with the `encrypt_with_fixed_session` helper (tests/vector_tests.rs:30) → 0 bytes |
| G3 pass-2 cross-check (tag **and** v1/v2 modulo byte equal pass 1's) | a `Read + Seek` wrapper that changes the modulo byte, or a ciphertext byte, between passes → `Err` |
| G4 seek to the recorded payload start, not to 0 | a vector behind a 7-byte prefix → identical output |
| G5 bounded memory | the counting-allocator test; falsified by buffering through a `Vec` |
| G6 cancel | a reader that errors on read N in pass 1 → `Io` and 0 bytes |

### (d) Name and return type

The siblings use `decrypt_to` and `decrypt_ooxml_to`. There, `_to` marks the streaming form
as opposed to a `Vec` form. Here `decrypt` already streams to a `W`, so `decrypt_to` would
suggest the wrong difference. **Recommendation:**

```rust
pub fn decrypt_verified<R: Read + Seek, W: Write>(input: R, output: W, password: &str)
    -> Result<DecryptOutcome, AescryptError>;

#[non_exhaustive]
pub struct DecryptOutcome { pub version: u8, pub plaintext_len: u64 }
impl DecryptOutcome { pub fn length_authenticated(&self) -> bool { self.version == 3 } }
```

This follows the siblings' shared shape: `(reader, writer, password)`, and a decrypt that
returns a `#[non_exhaustive] DecryptOutcome`. It drops `IntegrityOutcome`, because AES
Crypt's HMAC is mandatory, so the result would always be "verified". `version` tells EFV's
rotation that a file is legacy v0–v2 and should be upgraded. `length_authenticated()`
reports the v0–v2 limit honestly.

## Design summary (files)

- `src/decryption/decrypt.rs`: `open_session` (private), `decrypt` rewritten on top of it
  (same behavior), and the new `decrypt_verified`.
- `src/decryption/stream/context.rs`: the ring loop gets a MAC-only mode. It uses the same
  framing and index advance, but skips AES and writes nothing, so pass 1 and pass 2 cannot
  disagree about where the trailer is.
- `src/decryption/stream/versions.rs`: a new `verify_ciphertext_stream(...) -> PassOne { tag,
  modulo }` that does the pass-1 trailer checks plus the v3 final-block check. The pass-2
  path compares against `PassOne` with `ct_eq`, giving the new error
  `"input changed between verification and decryption"`.
- `src/decryption/stream/trailer.rs`: the PKCS#7 check is split into one that validates
  and one that writes, so pass 1 can validate without writing.
- `src/decryption/mod.rs` and `src/lib.rs`: export `decrypt_verified` and `DecryptOutcome`.
- The docs say **"On any `Err` the caller discards W"** in those words, as the siblings do.
  They also tell callers to pass a `BufReader<File>` (which is `Seek`), because the loop
  reads 16 bytes at a time.

## Slices (filed as one aescrypt-rs issue with this checklist, in the style of #49)

| # | Work | Done when |
|---|---|---|
| S1 | Refactor with no behavior change: `open_session`, the MAC-only ring mode, and the split PKCS#7 validate/write. | `decrypt` passes the full suite unchanged, all 63 vectors included. |
| S2 | `decrypt_verified` and `DecryptOutcome`: pass 1 (tag + v3 final block), seek, pass 2, and the G3 cross-check. | Byte-identical to `decrypt` on all 63 vectors and on the round-trip tests. |
| S3 | `tests/verified_decrypt_tests.rs`: G1–G4 and G6, wrong-password v0 → 0 bytes, a documented v0–v2 modulo-malleability test (shows the format limit), and an empty v1/v2/v3 payload. | Each guard removed once and seen to fail. Results recorded in the PR. |
| S4 | `tests/streaming_memory.rs`, a test binary of its own with a counting `#[global_allocator]`. It encrypts 64 MiB and 256 MiB from a pattern reader to a temp file, then runs `decrypt_verified` from a `BufReader<File>` to a counting sink. Peak growth must be ≤ a fixed bound that does not depend on size. | Green. Falsified by buffering through a `Vec`. |
| S5 | A differential fuzz target, `fuzz/src/lib.rs`, run over `Cursor`. If verified returns `Ok`, `decrypt` returns `Ok` with the same bytes. If verified fails with a non-`Io` error, 0 bytes were written. Add a stable smoke test. | The fuzz smoke tests pass. |
| S6 | Docs: `decrypt` points callers to `decrypt_verified`, the crate-level Security Model is updated, a README section is added as a compiled doctest (readme-doctests), and the CHANGELOG gets an `0.2.0-rc.13 - Unreleased` entry (changelog-protocol). | The doc and lint gates are green. |

Order: S1 → S2 → S3 and S4 in parallel → S5 → S6. This is one PR from the worktree
`O:\Projects\Worktrees\aescrypt-rs-verified-decrypt`. The plan doc lands in `docs/plans/`
with it. Cutting the rc is the owner's call. After it is published, send the version and
tag to EFV ZIP & AGE STREAMING and to the coordinator.

## Open questions (each with a recommendation)

1. **Name:** I recommend `decrypt_verified`, not `decrypt_to` (see (d)).
2. **Return type:** I recommend `DecryptOutcome { version, plaintext_len }` with
   `#[non_exhaustive]` and `length_authenticated()`. The alternative is `()`, which tells
   rotation nothing.
3. **v3 padding check in pass 1:** I recommend **yes**. It decrypts one block, which is
   never released. It goes slightly past "no decryption in pass 1", but it closes the one
   v3 path where verified plaintext could reach `W` before the call fails.
4. **Input mutated between passes:** two passes cannot un-write data. G3 turns the change
   into an `Err`, but `W` may already hold plaintext of the changed input. I recommend
   **documenting** that `R` must not change during the call and keeping "On any `Err`
   discard W". EFV meets this because it owns its spooled temp file. Hashing each chunk
   in pass 1 would break the memory bound.
5. **Reject a non-zero high nibble in the v0–v2 modulo byte?** I recommend **no**. It is a
   compatibility risk and does not close the length gap.
6. **aescrypt-cli:** I recommend a separate follow-up issue so that file inputs use
   `decrypt_verified`. stdin stays one-pass; its output is already staged to a temp file.
7. **Release line:** I recommend additive work in `0.2.0-rc.13`, with no 0.3.0, per the
   versioning policy.

## Verification

- `cargo test --workspace` on stable and on `+1.85`, `cargo clippy --all-targets -D
  warnings`, `cargo doc` with the deny lints, `cargo bench --no-run`, and the fuzz smoke
  tests (aescrypt-rs-publish-prep lists the CI-equivalent set).
- The guard-falsification table (G1–G6), with each removal's failing output recorded in
  the PR.
- The S4 memory test and its falsification.
