//! `benches/small_files.rs`
//! Fixed cost per call: `encrypt`, `decrypt` and `decrypt_verified` on small
//! payloads, with a 1-iteration KDF so the stream loop's own cost shows.
//!
//! The other benches miss this. `encrypt.rs` and `decrypt.rs` run a
//! 10 000-iteration KDF, which swamps small payloads, and `throughput.rs` only
//! measures 64 MiB. A first version of 0.2.0-rc.16 allocated, zeroed and wiped
//! two 64 KiB spans per call, which made files under about 10 KiB 2–5× slower
//! than 0.2.0-rc.15, and none of them noticed (#68, #73). The sizes include
//! the edges of the growing spans (1, 4 and 16 KiB) and one byte past each,
//! where a call grows to the next span.
//!
//! It uses only the public API, so it also runs against an older release. To
//! compare with 0.2.0-rc.15, run both builds with one target directory, so
//! that criterion finds the saved baseline:
//!
//! ```text
//! git worktree add --detach ../aescrypt-rs-rc15 v0.2.0-rc.15
//! # copy this file into ../aescrypt-rs-rc15/benches/, and add to its Cargo.toml:
//! #   [[bench]]
//! #   name = "small_files"
//! #   harness = false
//! cd ../aescrypt-rs-rc15
//! cargo bench --bench small_files --target-dir ../bench-target -- --save-baseline rc15
//! cd -
//! cargo bench --bench small_files --target-dir ../bench-target -- --baseline rc15
//! ```

// Bench crate: helpers and fixtures are explained by the benchmarks that use them.
#![allow(clippy::missing_docs_in_private_items)]
// `criterion_group!` generates an undocumented `pub fn benches`; this is a bench binary, not an API.
#![allow(missing_docs)]

use aescrypt_rs::{decrypt, decrypt_verified, encrypt};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::{Cursor, sink};

const PASSWORD: &str = "small-file-bench";

/// Empty, the span edges and one byte past each, and two larger sizes for
/// contrast.
const SIZES: &[usize] = &[
    0,
    1024,
    1025,
    4096,
    4097,
    16 * 1024,
    16 * 1024 + 1,
    64 * 1024,
    1024 * 1024,
];

fn plaintext(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 9)) as u8)
        .collect()
}

fn bench_small_files(c: &mut Criterion) {
    for (name, op) in [("encrypt", 0), ("decrypt", 1), ("decrypt_verified", 2)] {
        let mut group = c.benchmark_group(format!("small_files/{name}"));
        for &size in SIZES {
            let input = plaintext(size);
            let mut file = Vec::new();
            encrypt(Cursor::new(&input), &mut file, PASSWORD, 1).unwrap();

            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| match op {
                0 => b.iter(|| {
                    let mut out = Vec::with_capacity(size + 256);
                    encrypt(Cursor::new(black_box(&input)), &mut out, PASSWORD, 1).unwrap();
                    black_box(out)
                }),
                1 => b.iter(|| decrypt(Cursor::new(black_box(&file)), sink(), PASSWORD).unwrap()),
                _ => b.iter(|| {
                    decrypt_verified(Cursor::new(black_box(&file)), sink(), PASSWORD).unwrap()
                }),
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_small_files);
criterion_main!(benches);
