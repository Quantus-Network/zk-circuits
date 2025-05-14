#![cfg(feature = "testing")]
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;

const MEASUREMENT_TIME_S: u64 = 20;

fn verify_proof_benchmark(c: &mut Criterion) {
    c.bench_function("verifier_verify_proof", |b| {
        let inputs = CircuitInputs::default();
        let proof = WormholeProver::default()
            .commit(&inputs)
            .unwrap()
            .prove()
            .unwrap();

        b.iter(|| {
            let verifier = WormholeVerifier::new();
            verifier.verify(proof.clone()).unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(MEASUREMENT_TIME_S));
    targets = verify_proof_benchmark
);
criterion_main!(benches);
