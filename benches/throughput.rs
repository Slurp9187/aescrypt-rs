//! `benches/throughput.rs`
//! Streaming throughput at 64 MiB: `encrypt`, `decrypt` and `decrypt_verified`
//! from memory to `io::sink()`, with one KDF iteration so the stream loop
//! dominates (#68). The other benches stop at 10 MiB and time the KDF too.

// Bench crate: helpers and fixtures are explained by the benchmarks that use them.
#![allow(clippy::missing_docs_in_private_items)]
// `criterion_group!` generates an undocumented `pub fn benches`; this is a bench binary, not an API.
#![allow(missing_docs)]

use aescrypt_rs::{decrypt, decrypt_verified, encrypt};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::{Cursor, sink};
use std::time::Duration;

const LEN: usize = 64 * 1024 * 1024;
const PASSWORD: &str = "throughput-bench";

fn plaintext() -> Vec<u8> {
    (0..LEN as u64)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 9)) as u8)
        .collect()
}

fn bench_throughput(c: &mut Criterion) {
    let input = plaintext();
    let mut encrypted = Vec::with_capacity(LEN + 1024);
    encrypt(Cursor::new(&input), &mut encrypted, PASSWORD, 1).unwrap();

    let mut group = c.benchmark_group("throughput_64MiB");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Bytes(LEN as u64));

    group.bench_function("encrypt", |b| {
        b.iter(|| encrypt(Cursor::new(black_box(&input)), sink(), PASSWORD, 1).unwrap());
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| decrypt(Cursor::new(black_box(&encrypted)), sink(), PASSWORD).unwrap());
    });
    group.bench_function("decrypt_verified", |b| {
        b.iter(|| {
            decrypt_verified(Cursor::new(black_box(&encrypted)), sink(), PASSWORD).unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
