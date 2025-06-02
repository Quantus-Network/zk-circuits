#![cfg(test)]
use plonky2::plonk::circuit_data::CircuitConfig;
use wormhole_aggregator::{aggregator::WormholeProofAggregator, MAX_NUM_PROOFS_TO_AGGREGATE};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

use crate::test_helpers::storage_proof::TestInputs;

const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[test]
#[ignore = "takes too long"]
fn push_proof_to_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::new(CIRCUIT_CONFIG);
    aggregator.push_proof(proof).unwrap();

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), 1);
}

#[test]
#[ignore = "takes too long"]
fn push_proof_to_full_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::new(CIRCUIT_CONFIG);

    // Fill up the proof buffer.
    for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let result = aggregator.push_proof(proof.clone());
    assert!(result.is_err());

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), MAX_NUM_PROOFS_TO_AGGREGATE);
}

#[test]
#[ignore = "takes too long"]
fn aggregate_single_proof() {
    // Create a proof.
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::new(CIRCUIT_CONFIG);
    aggregator.push_proof(proof).unwrap();

    aggregator.aggregate().unwrap();
    aggregator.prove().unwrap();
}
