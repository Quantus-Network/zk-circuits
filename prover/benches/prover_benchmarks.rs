use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover");
    group.sample_size(10); // Reduce sample size since proving is expensive

    group.bench_function("commit_and_prove", |b| {
        b.iter(|| {
            let prover = WormholeProver::new();
            let inputs = CircuitInputs::test_default();
            black_box(prover.commit(&inputs).unwrap().prove().unwrap());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_prove);
criterion_main!(benches); 