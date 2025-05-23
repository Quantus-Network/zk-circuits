// use std::fs;
// use plonky2::util::serialization::DefaultGateSerializer;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

const MEASUREMENT_TIME_S: u64 = 20;

fn create_proof_benchmark(c: &mut Criterion) {
    c.bench_function("prover_create_proof", |b| {
        b.iter(|| {
            let prover = WormholeProver::new(true);
            // let circuit_bytes = prover.circuit_data.common.to_bytes(&DefaultGateSerializer).unwrap();
            // fs::write("common.bin", circuit_bytes).unwrap();
            let inputs = CircuitInputs::test_inputs();
            prover.commit(&inputs).unwrap().prove().unwrap()
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(MEASUREMENT_TIME_S))
        .sample_size(10);
    targets = create_proof_benchmark
);
criterion_main!(benches);
