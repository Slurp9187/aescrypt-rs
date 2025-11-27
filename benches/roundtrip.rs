// benches/roundtrip.rs
//! Round-trip (encrypt → decrypt) benchmarks – works with secure-gate 0.5.5+

use aescrypt_rs::{decrypt, encrypt};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secure_gate::Dynamic; // ← new API
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

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    // Explicit type annotation – required because Dynamic is generic
    let password: Dynamic<String> = Dynamic::new("benchmark-password".to_string());

    let sizes = [KB, 64 * KB, MB, 10 * MB];

    for &size in &sizes {
        let input = vec![0x41u8; size]; // repeating 'A'

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("size", format_size(size)),
            &size,
            |b, _| {
                // Clone once outside the timed loop – cloning a Box<String> is cheap
                let password = password.clone();

                b.iter(|| {
                    // ----- encrypt -------------------------------------------------
                    let mut encrypted = Vec::with_capacity(size + 1024);
                    {
                        let mut src = Cursor::new(black_box(&input));

                        // Clone for encrypt since it takes Dynamic<String> by value
                        let pw_for_encrypt = password.clone();

                        encrypt(
                            black_box(pw_for_encrypt),
                            &mut src,
                            &mut encrypted,
                            KDF_ITERATIONS,
                        )
                        .unwrap();
                    }

                    // ----- decrypt -------------------------------------------------
                    let mut decrypted = Vec::with_capacity(size);
                    {
                        let mut src = Cursor::new(black_box(&encrypted));

                        // Clone for decrypt
                        let pw_for_decrypt = password.clone();

                        decrypt(
                            &mut src,
                            &mut decrypted,
                            black_box(pw_for_decrypt), // ← Dynamic<String> by value
                        )
                        .unwrap();
                    }

                    black_box(decrypted);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
