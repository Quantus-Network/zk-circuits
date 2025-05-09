use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(100); // Verification is faster than proving

    // Generate a proof once to reuse
    let prover = WormholeProver::new();
    let inputs = CircuitInputs::test_default();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    group.bench_function("verify", |b| {
        let verifier = WormholeVerifier::new();
        b.iter(|| {
            black_box(verifier.verify(proof.clone()).unwrap());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches); 