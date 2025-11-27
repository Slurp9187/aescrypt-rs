use aescrypt_rs::aliases::Password;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

fn bench_batch(c: &mut Criterion) {
    let password = Password::new("benchmark".to_string());
    let data = black_box(vec![0u8; 10_000_000]); // 10 MB

    let mut group = c.benchmark_group("batch-ops");

    for n_files in [1, 2, 4, 8, 16] {
        group.bench_with_input(BenchmarkId::new("parallel", n_files), &n_files, |b, &n| {
            let mut batch = (0..n)
                .map(|_| (std::io::Cursor::new(data.clone()), Vec::new()))
                .collect::<Vec<_>>();
            b.iter(|| {
                aescrypt_rs::encrypt_batch(&mut batch, &password, 100_000).unwrap();
            });
        });

        group.bench_with_input(
            BenchmarkId::new("sequential", n_files),
            &n_files,
            |b, &n| {
                b.iter(|| {
                    for _ in 0..n {
                        let mut out = Vec::new();
                        aescrypt_rs::encrypt(
                            std::io::Cursor::new(&data),
                            &mut out,
                            &password,
                            100_000,
                        )
                        .unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_batch);
criterion_main!(benches);
