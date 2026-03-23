//! benches/iterations.rs
//! Benchmark various iteration counts for encryption/decryption operations
//!
//! Tests performance impact of different PBKDF2 iteration counts

use aescrypt_rs::aliases::PasswordString;
use aescrypt_rs::{decrypt, encrypt};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use std::io::Cursor;

fn bench_encrypt_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_iterations");
    group.sample_size(10); // Fewer samples for slow iterations
    
    let password = PasswordString::new("benchmark-password".to_string());
    let plaintext = b"test data for iteration benchmarking";
    
    let iterations = vec![1, 10, 100, 1_000, 10_000, 100_000, 300_000, 500_000];
    
    for &iters in &iterations {
        let id = BenchmarkId::new("iterations", iters);
        group.bench_with_input(id, &iters, |b, &iters| {
            b.iter(|| {
                let mut encrypted = Vec::new();
                encrypt(
                    Cursor::new(black_box(plaintext)),
                    &mut encrypted,
                    black_box(&password),
                    iters,
                )
                .unwrap();
                black_box(encrypted);
            });
        });
    }
    
    group.finish();
}

fn bench_roundtrip_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip_iterations");
    group.sample_size(10); // Fewer samples for slow iterations
    
    let password = PasswordString::new("benchmark-password".to_string());
    let plaintext = b"test data for roundtrip benchmarking";
    
    let iterations = vec![1, 10, 100, 1_000, 10_000, 100_000, 300_000];
    
    for &iters in &iterations {
        let id = BenchmarkId::new("iterations", iters);
        group.bench_with_input(id, &iters, |b, &iters| {
            b.iter(|| {
                // Encrypt
                let mut encrypted = Vec::new();
                encrypt(
                    Cursor::new(black_box(plaintext)),
                    &mut encrypted,
                    black_box(&password),
                    iters,
                )
                .unwrap();
                
                // Decrypt
                let mut decrypted = Vec::new();
                decrypt(
                    Cursor::new(black_box(&encrypted)),
                    &mut decrypted,
                    black_box(&password),
                )
                .unwrap();
                
                black_box(decrypted);
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_iterations,
    bench_roundtrip_iterations
);
criterion_main!(benches);

