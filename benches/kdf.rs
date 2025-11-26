//! benches/kdf.rs
//! Consolidated KDF benchmarks – multi-iter PBKDF2 + ACKDF
use aescrypt_rs::{derive_secure_ackdf_key, derive_secure_pbkdf2_key};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use secure_gate::{fixed_alias, Dynamic, Fixed};
use std::hint::black_box;
use std::time::Duration;

fixed_alias!(Key32, 32);

fn kdf_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF");
    // Faster runs for slow high-iter benches
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(20);

    let pw: Dynamic<String> = Dynamic::new("benchmark-password".to_string());
    let salt: Fixed<[u8; 16]> = Fixed::new([0x42; 16]);

    // PBKDF2 with various iterations (from original kdf.rs)
    for &iters in &[1_000, 10_000, 100_000, 300_000] {
        let id = BenchmarkId::new("pbkdf2_iterations", iters);
        group.bench_with_input(id, &iters, |b, &iters| {
            b.iter(|| {
                let mut key = Key32::new([0u8; 32]);
                derive_secure_pbkdf2_key(black_box(&pw), black_box(&salt), iters, &mut key)
                    .unwrap();
                black_box(key);
            });
        });
    }

    // ACKDF fixed 8192 (from both originals)
    group.bench_function("ackdf_8192", |b| {
        b.iter(|| {
            let mut key = Key32::new([0u8; 32]);
            let _ = derive_secure_ackdf_key(black_box(&pw), black_box(&salt), &mut key);
            black_box(key);
        });
    });

    group.finish();
}

criterion_group!(benches, kdf_benches);
criterion_main!(benches);
