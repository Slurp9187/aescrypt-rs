// benches/decrypt.rs
//! Decrypt-only benchmarks (pre-encrypted data) — secure-gate v0.5.5 + modern API

use aescrypt_rs::{decrypt, encrypt};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secure_gate::Dynamic;
use std::hint::black_box;
use std::io::Cursor;

const KDF_ITERATIONS: u32 = 10_000;

// --- Size constants ---
const KB: usize = 1024;
const MB: usize = 1024 * 1024;

fn format_size(bytes: usize) -> String {
    if bytes >= MB {
        format!("{} MiB", bytes / MB)
    } else if bytes >= KB {
        format!("{} KiB", bytes / KB)
    } else {
        format!("{bytes} B")
    }
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    // Secure password — zero-cost, auto-zeroized on drop
    let password: Dynamic<String> = Dynamic::new("benchmark-password".to_string());

    let sizes = [KB, 64 * KB, MB, 10 * MB];

    for &size in &sizes {
        // --- Pre-encrypt once (outside the timed loop) ---
        let input = vec![0x41u8; size]; // Repeating 'A'
        let mut encrypted = Vec::with_capacity(size + 1024);
        {
            let mut src = Cursor::new(&input);
            encrypt(
                &mut src,
                &mut encrypted,
                &password, // encrypt takes ownership
                KDF_ITERATIONS,
            )
            .unwrap();
        }

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("size", format_size(size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut dst = Vec::with_capacity(size);
                    let mut src = Cursor::new(black_box(&encrypted));

                    // decrypt takes ownership → we clone the password each time
                    decrypt(&mut src, &mut dst, black_box(&password)).unwrap();

                    black_box(dst)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
