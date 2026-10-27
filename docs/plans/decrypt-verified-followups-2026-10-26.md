# aescrypt-rs: speed follow-ups after the span loop — F1, F2, F3

**Status (2026-10-26, UTC):** F1 approved by the owner to **measure first**. If the
measurement says go, F1 ships in **0.2.0-rc.16** (owner's decision), and the release waits
for it. F2 and F3 stay parked. Verified at main `072ffef`, with #71 (encrypt `CbcSpan`) green
and about to merge. Tracking: master issue #68 (lines F1–F3). PRs for this plan say
`Plan: docs/plans/decrypt-verified-followups-2026-10-26.md` and `Refs #68`. Predecessor:
[`span-loop-2026-10-26.md`](span-loop-2026-10-26.md).

## Measured state

Measured, on one x86 desktop with AES-NI and SHA-NI (Ryzen 9 9950X3D), at 64 MiB from
memory to `io::sink()` with `benches/throughput.rs`. Absolute speed will be lower on most
machines; only ratios are meant to carry over.

| | 0.2.0-rc.15 | main + #71 |
|---|---|---|
| `encrypt` | 494 MiB/s | 730 MiB/s |
| `decrypt` (one pass: HMAC + AES) | 571 MiB/s | 1.97 GiB/s |
| `decrypt_verified` (two passes) | 372 MiB/s | 1.10 GiB/s |

`decrypt_verified` reads the payload twice:
- **Pass 1** (`verify_ciphertext_stream`, `src/decryption/stream/versions.rs`) streams it
  through the payload HMAC and checks the file's tag.
- **Pass 2** (`decrypt_stream` with `verified`) decrypts, and re-computes the same HMAC
  only to detect the input changing between passes (`"input changed between verification
  and decryption"`).

So that second HMAC protects against a change between passes; it does not authenticate the
file.

## F1: a cheaper second check

### Target model
Both passes compute a one-time Poly1305 over the ciphertext, under a key drawn fresh per
call, and compare the two tags in constant time. Pass 1 keeps the HMAC, which is what
authenticates the file; pass 2 drops it.

| | today | with F1 |
|---|---|---|
| pass 1 | HMAC | HMAC + Poly1305 |
| pass 2 | HMAC + AES | Poly1305 + AES |

The file format and official AES Crypt compatibility are untouched: the file's own
HMAC-SHA256 trailer is still what pass 1 verifies.

### Security argument (to be reviewed with the code)
- Poly1305 is used as an ε-almost-Δ-universal hash. Its key (r, s) is drawn per call from
  the secure-gate CSPRNG (`Fixed::from_random`, the crate's existing `rand` feature), held
  in a wrapper and wiped on drop, along with the `poly1305` state (its `zeroize` feature).
- Neither tag is ever output, and they are compared in constant time. An adversary who
  changes the input between passes therefore chooses pass 2's bytes with no key-dependent
  information, and gets one comparison per key.
- The chance that a changed input matches is at most about 8·⌈L/16⌉ / 2¹⁰⁶ per call: about
  2⁻⁸¹ at 64 MiB, and about 2⁻⁶⁷ at 1 TiB.
- One key over two messages is fine here. Poly1305's single-use rule protects the key from
  an attacker who sees tags, and this attacker sees none.

### Dependency
`poly1305 = { version = "0.8", features = ["zeroize"] }`. It is the 0.8 line on purpose:
it uses `universal-hash` 0.5 and `crypto-common` 0.1, the same generation as `aes` 0.8 and
`hmac` 0.12, and has MSRV 1.56. 0.9.x would pull a second `crypto-common` (0.2) into the
graph. Its AVX2 backend is picked at runtime.

### Spike first (nothing committed)
A scratch crate on the same locked versions (`aes` 0.8.4, `hmac` 0.12.1, `sha2` 0.10.9),
plus `poly1305` 0.8, times each primitive over 64 MiB, fed in 64 KiB spans as the real
loop does:
- **H:** HMAC-SHA256 `update`.
- **P:** Poly1305 `update_padded`.
- **A:** AES-256 `decrypt_blocks_inout` plus the CBC XOR, which is today's pass-2 AES
  work.

**Model:** `today ≈ H + (H + A)` and `F1 ≈ (H + P) + (P + A)`. The model is checked against
the measured `decrypt_verified`. If it is off by more than 15%, the prototype check below
decides instead of the model.

**Go/no-go:** go if the predicted `decrypt_verified` gain is **≥ 15%**. If not, the numbers
are recorded here and on #68, and F1 is closed as not worth a dependency.

**Prototype check:** the first build commit is re-benched against today's
`decrypt_verified`. If the real gain is under 15%, it is reverted, and rc.16 releases
without it.

### Build (if go)
- **Code:**
  - `src/decryption/stream/versions.rs`: `verify_ciphertext_stream` and `decrypt_stream`'s
    `verified` branch. `VerifiedTrailer` gains the Poly1305 tag.
  - `src/decryption/stream/context.rs`: the span loop feeds whichever MACs the pass needs.
- **Tests:**
  - `input_changed_between_passes_*` (ciphertext, modulo byte, tag) must still fail
    correctly.
  - Falsification: the Poly1305 check removed once must turn them red.
  - The golden suite, the 63 vectors, the memory bound and the fuzz smoke tests stay green.
  - Re-bench `decrypt_verified`.
- **Docs:**
  - The crate-level Security Model gets the argument above.
  - The rc.16 CHANGELOG gets the speed-up, the dependency and the argument.
  - The repo secure-gate skill gets the new wrapped key.
- **Dependency:** the root `Cargo.toml` (with a comment on why 0.8), plus both lockfiles.

## F2: a `&[u8]` entry point (parked)

`decrypt_verified_slice(input: &[u8], output: W, password: &str) -> Result<DecryptOutcome>`.
A borrowed slice cannot change during the call, so it needs one MAC pass and then the
decrypting pass, with no second check at all: close to one-pass `decrypt` speed. It only
helps callers holding the whole file in memory, such as EFV's `decrypt_to_vec`.

**secure-gate: inside, not at the boundary.** The input is ciphertext, which is public.
Plaintext still streams to `W` and is never returned, and the spans stay `Dynamic<[u8]>`.
This crate keeps secure-gate types out of public signatures on purpose: see
`.claude/skills/aescrypt-rs-secure-gate`, "Boundary". A caller with a wrapped ciphertext
calls it inside its own `with_secret`.

## F3: opt-in threads (parked)

A default-off Cargo feature using `std::thread::scope`, with no new dependency:
- **Encrypt:** the CBC chain and the HMAC on two threads over alternating spans.
- **Pass 2 of `decrypt_verified`:** the second check on one thread, AES and writes on the
  other.

The output stays byte-identical.

**Name: `parallel`.**
- Not `rayon`. BLAKE3 calls its feature `rayon` because it enables the optional
  `rayon-core` dependency (`rayon = ["dep:rayon-core"]`). Cargo's convention names a
  feature after the optional dependency it enables. This one enables none.
- Not `thread`, which reads like a thread-safety switch.
- `parallel` is what the `cc` crate calls the same capability.
- If F3 ever used rayon, to share an application's thread pool, it should be called
  `rayon`, as BLAKE3's is.

## Non-scope

- **The KDF.** PBKDF2's cost is the password hardening, by design.
- **Per-call span allocation and wiping.** It costs microseconds.
- **CLI buffering.** Its reader and writer pass 64 KiB calls straight through.

## Guardrails

- The file format is byte-identical; `tests/span_golden_tests.rs` checks it.
- `decrypt_verified` releases no plaintext before the tag and padding checks; nor does it on
  input that changed between passes.
- secure-gate: Tier 1 only. Every key and every plaintext buffer is wrapped.
- `#![forbid(unsafe_code)]`, MSRV 1.85, and a single `crypto-common` in the graph.
- Numbers name their machine, and only ratios are claimed to carry over.
