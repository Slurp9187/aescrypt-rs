// benches/encrypt.rs (or roundtrip.rs)
use aescrypt_rs::{consts::DEFAULT_PBKDF2_ITERATIONS, encrypt};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secure_gate::Dynamic;
use std::hint::black_box;
use std::io::Cursor;

fn bench_encrypt_with_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_with_kdf");

    // Secure password — zero-cost, auto-zeroized
    let password: Dynamic<String> = Dynamic::new("benchmark-password".to_string());

    let sizes = [
        1,
        1024,
        64 * 1024,
        1024 * 1024,
        10 * 1024 * 1024, // 1B → 10MiB
    ];

    for &size in &sizes {
        let input = vec![0x41u8; size]; // Repeating 'A'

        // Reduce iterations for large inputs (realistic usage)
        let iters = if size <= 1024 {
            DEFAULT_PBKDF2_ITERATIONS
        } else {
            10_000
        };

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("size", format_size(size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut dst = Vec::with_capacity(size + 1024); // Avoid reallocations
                    let mut src = Cursor::new(black_box(&input));

                    // encrypt() now takes Dynamic<String> by value
                    // We clone it here — cheap (just a Box<String> clone)
                    encrypt(&mut src, &mut dst, black_box(&password), black_box(iters)).unwrap();

                    black_box(dst)
                });
            },
        );
    }

    group.finish();
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    if bytes >= MB {
        format!("{} MiB", bytes / MB)
    } else if bytes >= KB {
        format!("{} KiB", bytes / KB)
    } else {
        format!("{bytes} B")
    }
}

criterion_group!(benches, bench_encrypt_with_kdf);
criterion_main!(benches);
