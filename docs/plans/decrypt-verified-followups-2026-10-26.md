# aescrypt-rs: speed follow-ups after the span loop — F1, F2, F3

**Status (2026-10-26, UTC):** **F1 measured at +8.8%**, below the 15% bar set before measuring
(see [Spike result](#spike-result-no-go)). The owner judged 8.8% worth it for bulk work:
**F1 is planned for 0.2.0-rc.17**, built after EFV re-measures end to end on rc.16, with the
prototype check below. 0.2.0-rc.16 releases without it. F2 and F3 stay
parked; the spike's numbers make F2 the stronger candidate. Before the spike: F1 approved
by the owner to measure first, and to ship in rc.16 if the measurement said go. Verified at main `ee36a0e`, with #71 (encrypt `CbcSpan`)
merged. Tracking: master issue #68 (lines F1–F3). PRs for this plan say
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

### Spike result: no-go

A scratch crate (outside the repo) on `aes` 0.8.4, `hmac` 0.12.1, `sha2` 0.10.9 and
`poly1305` 0.8.0, built in release with 1.85. Times are the best of 9 runs over 64 MiB, fed
in 64 KiB spans, on the same x86 desktop with AES-NI. Each combination is timed as one loop,
so overlap inside a pass is measured, not modelled.

| work per span | time | throughput |
|---|---|---|
| H: HMAC-SHA256 | 23.9 ms | 2.62 GiB/s |
| P: Poly1305 | 9.7 ms | 6.41 GiB/s |
| A: AES-256 decrypt + CBC XOR | 7.2 ms | 8.65 GiB/s |
| H+A: today's pass 2 | 30.6 ms | 2.04 GiB/s |
| H+P: F1's pass 1 | 33.5 ms | 1.86 GiB/s |
| P+A: F1's pass 2 | 16.5 ms | 3.79 GiB/s |

- **The model is valid.** It puts today's `decrypt_verified` at H + (H+A) = 1.15 GiB/s,
  against 1.10 measured in the crate, within 5%.
- **The prediction:** F1 = (H+P) + (P+A) = 1.25 GiB/s, **+8.8%**. Three runs gave
  +8.8 to +8.9%.
- **Size does not change it.** Repeated over a 1 GiB buffer, which streams from DRAM instead of
  possibly sitting in this CPU's 96 MB 3D V-cache, every throughput matched within 2% (H 2.61,
  P 6.40, A 8.76 GiB/s), and the prediction was again +8.9%. The work is compute-bound, so
  the ratio holds at any size. For files on disk the gain can only shrink: when pass 2 cannot
  re-read from the page cache, both passes wait on the disk, and below about 1 GiB/s of read
  speed the disk, not the MAC, sets the pace.
- **Why it falls short.** Poly1305 is only about 2.4× faster than HMAC here, F1 runs it in
  both passes, and H and P do not overlap in one loop (H+P ≈ H + P). The saving per byte
  is H − 2P, which is small.

**Decision:** under the 15% bar, so not in rc.16. The owner then weighed +8.8% as worth it
for bulk operations against the new dependency and the security argument, and moved F1 to
**rc.17**. It will be built after EFV's end-to-end numbers on rc.16, with the prototype check
re-benching the first commit. The build steps below stand.

**What it says about F2.** F2 needs no second check at all, so its cost is H (pass 1) plus
A (pass 2): 23.9 + 7.2 ≈ 31 ms, against today's ≈ 55 ms. That is roughly **+75%** for
in-memory input on this machine (a model, not a measurement of F2).

### Build (rc.17)
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
decrypting pass, with no second check at all: close to one-pass `decrypt` speed (modelled at
roughly +75% over today's `decrypt_verified` by F1's spike, above). It only helps callers
holding the whole file in memory, such as EFV's `decrypt_to_vec`.

**Precondition (the sharp edge).** "A borrowed slice cannot change" holds for memory Rust
owns, not for a memory-mapped file: if a caller passes a `&[u8]` from a mapping that another
process can write, and the file changes between the passes, pass 2 would release plaintext
that pass 1's tag never covered. That is exactly what the second check exists to stop. F2's
docs must forbid writable mappings, or F2 keeps a check (F1's) and gains less.

**When:** after rc.16, and only if EFV's end-to-end numbers show in-memory verified decrypts
of large items matter. Small items are dominated by the 600,000-iteration KDF.

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
