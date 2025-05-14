#![cfg(feature = "testing")]
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

const MEASUREMENT_TIME_S: u64 = 20;

fn create_proof_benchmark(c: &mut Criterion) {
    c.bench_function("prover_create_proof", |b| {
        b.iter(|| {
            let prover = WormholeProver::new();
            let inputs = CircuitInputs::default();
            prover.commit(&inputs).unwrap().prove().unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(MEASUREMENT_TIME_S));
    targets = create_proof_benchmark
);
criterion_main!(benches);
