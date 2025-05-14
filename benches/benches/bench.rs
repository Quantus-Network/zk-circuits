//! Benchmarks for the wormhole circuit prover and verifier.
#![cfg(feature = "testing")]
use std::time::Duration;

use criterion::{Criterion, criterion_main};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::prover::WormholeProver;
use wormhole_verifier::verifier::WormholeVerifier;

const MEASUREMENT_TIME_S: u64 = 20;

fn create_proof(c: &mut Criterion) {
    c.bench_function("prover", |b| {
        b.iter(|| {
            let prover = WormholeProver::new();
            let inputs = CircuitInputs::default();
            prover.commit(&inputs).unwrap().prove().unwrap();
        });
    });
}

fn verify_proof(c: &mut Criterion) {
    c.bench_function("verifier", |b| {
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

fn benches() {
    let mut criterion =
        Criterion::default().measurement_time(Duration::from_secs(MEASUREMENT_TIME_S));

    create_proof(&mut criterion);
    verify_proof(&mut criterion);

    criterion.final_summary();
}

criterion_main!(benches);
