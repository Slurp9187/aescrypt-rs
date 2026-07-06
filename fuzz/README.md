# aescrypt-rs fuzz suite

A [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) suite for
`aescrypt-rs`. All harness logic lives in a stable-compilable library
(`src/lib.rs`) with smoke tests; the `fuzz_targets/*.rs` binaries are thin
libFuzzer wrappers gated behind the nightly-only `fuzzing` feature.

## Targets

| Target             | Input                          | Oracle |
| ------------------ | ------------------------------ | ------ |
| `decrypt_raw`      | arbitrary bytes → `decrypt()`  | no panic, no OOM |
| `roundtrip_v3`     | valid v3 file + mutations      | authentication: any *accepted* mutated file must decrypt to the original plaintext (else auth bypass) |
| `roundtrip_legacy` | hand-built v0–v2 file + mutations | untampered files round-trip exactly (continuous differential test of the builder vs. the read path); tampered files never panic and may only differ in final-block **length** (≤ 15 bytes), never in the decrypted prefix |
| `stream_decrypt`   | `[config, modulo]` + ciphertext stream | ring-buffer / trailer / PKCS#7 path: no panic |
| `parsers`          | arbitrary bytes → header chain | no panic |

## Running (Linux/macOS, nightly)

```sh
cargo +nightly fuzz run <target> -- -timeout=10 -max_len=4096
```

Longer campaign with a memory cap:

```sh
cargo +nightly fuzz run decrypt_raw -- -max_total_time=600 -timeout=10 -max_len=4096 -rss_limit_mb=4096
```

### Why `-timeout` matters for `decrypt_raw`

A v3 header can legally request up to 5 000 000 PBKDF2-HMAC-SHA512 iterations
(the crate's DoS ceiling). That is *seconds* of work per exec, so a crafted
header can legitimately stall a single run. `-timeout=10` lets libFuzzer flag a
genuinely stuck input without treating the intentional 5M cap as a bug — the cap
is the crate's defense, not a defect. The structured targets sidestep this by
building inputs with tiny iteration counts.

## Toolchain gotcha: `+nightly` is required

The repo's `rust-toolchain.toml` pins **1.70**. `cargo fuzz ...` invoked *bare*
resolves 1.70 and fails (cargo-fuzz needs nightly features). Always use
`cargo +nightly fuzz ...` — the `+nightly` sets `RUSTUP_TOOLCHAIN` for the nested
cargo calls, overriding the toolchain file.

## Windows

`cargo +nightly fuzz build` **compiles and links** all targets on Windows/MSVC,
but the resulting binaries **cannot run locally**: they are ASan/SanitizerCoverage
instrumented, and Rust does not ship the matching `clang_rt.asan_dynamic-x86_64.dll`
for the MSVC target (a stock LLVM copy is ABI-incompatible and yields
`STATUS_ENTRYPOINT_NOT_FOUND`; dropping the sanitizer with `-s none` then leaves
`__stop___sancov_pcs` unresolved at link time). This is a Rust-on-Windows
limitation, not a suite defect. **Fuzzing runs on Linux CI** (see
`.github/workflows/fuzz.yml`).

For local validation on Windows, run the stable smoke tests instead — they drive
the exact same `fuzz_*` entry points on any toolchain:

```sh
cargo test --no-default-features --manifest-path fuzz/Cargo.toml
```

## Smoke tests (any toolchain, no nightly)

```sh
cargo test --no-default-features --manifest-path fuzz/Cargo.toml
```

`--no-default-features` turns off `libfuzzer-sys`, so only the harness library
and its `#[cfg(test)]` smoke tests build. The most important of these,
`smoke_legacy_builder_roundtrips`, proves `build_legacy_file` matches the real
v0/v1/v2 wire format byte-for-byte across every final-block shape.

## Seed corpora

Seeds live under `corpus/<target>/` and are committed. Regenerate them with:

```sh
cargo test --no-default-features --manifest-path fuzz/Cargo.toml \
    generate_seed_corpus -- --ignored
```

`decrypt_raw` and `stream_decrypt` seeds use a fixed password (`fuzz-password`)
and `iterations = 1` so they reach the success path without multi-second execs.
The two structured targets (`roundtrip_v3`, `roundtrip_legacy`) have no seed
corpus — libFuzzer synthesizes their `Arbitrary` inputs.

## Triaging a crash

Any crash artifact under `artifacts/<target>/` is a real finding. Minimize and
reproduce it:

```sh
cargo +nightly fuzz tmin <target> artifacts/<target>/<crash-file>
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```
