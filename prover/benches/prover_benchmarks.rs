use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use std::time::Duration;

const MEASUREMENT_TIME_S: u64 = 60;

fn bench_prove(c: &mut Criterion) {
    // let mut group = c.benchmark_group("prover");
    // group.sample_size(10); // Reduce sample size since proving is expensive
    //
    // group.bench_function("commit_and_prove", |b| {
    c.bench_function("prover", |b| {
        b.iter(|| {
            let prover = WormholeProver::new();
            let inputs = CircuitInputs::test_default();
            black_box(prover.commit(&inputs).unwrap().prove().unwrap());
        })
    });

    // group.finish();
}

fn benches() {
    let mut criterion =
        Criterion::default().measurement_time(Duration::from_secs(MEASUREMENT_TIME_S));

    bench_prove(&mut criterion);

    criterion.final_summary();
}

// criterion_group!(benches, bench_prove);
criterion_main!(benches);