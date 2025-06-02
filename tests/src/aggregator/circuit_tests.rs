use crate::circuit_helpers::{build_and_prove_test, setup_test_builder_and_witness};
use crate::test_helpers::storage_proof::TestInputs;
use hashbrown::HashMap;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::recursion::dummy_circuit::{dummy_circuit, dummy_proof};
use wormhole_aggregator::circuit::{WormholeProofAggregatorInner, WormholeProofAggregatorTargets};
use wormhole_aggregator::MAX_NUM_PROOFS_TO_AGGREGATE;
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[cfg(test)]
fn run_test() -> anyhow::Result<plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = setup_test_builder_and_witness(false);
    let targets = WormholeProofAggregatorTargets::new(&mut builder, CIRCUIT_CONFIG);
    WormholeProofAggregatorInner::circuit(&targets, &mut builder);

    let aggregator = WormholeProofAggregatorInner::new(CIRCUIT_CONFIG);
    aggregator.fill_targets(&mut pw, targets)?;
    build_and_prove_test(builder, pw)
}

#[cfg(test)]
#[ignore = "takes too long"]
#[test]
fn build_and_verify_proof() {
    // Create proofs.
    let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
    for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let inputs = CircuitInputs::test_inputs();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        proofs.push(proof);
    }
    run_test().unwrap();
}

#[cfg(test)]
#[ignore = "takes too long"]
#[test]
fn few_proofs_pass() {
    // Create proofs.
    let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
    let mut dummy_proofs = Vec::new();
    for i in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        if i < MAX_NUM_PROOFS_TO_AGGREGATE / 2 {
            let inputs = CircuitInputs::test_inputs();
            let proof = prover.commit(&inputs).unwrap().prove().unwrap();
            proofs.push(proof);
        } else {
            let dummy_circuit = dummy_circuit(&prover.circuit_data.common);
            let dummy_proof = dummy_proof(&dummy_circuit, HashMap::new()).unwrap();
            dummy_proofs.push(dummy_proof);
        }
    }

    // Get the number of valid proofs before appending the dummy proofs.
    proofs.extend_from_slice(&dummy_proofs);

    run_test().unwrap();
}
