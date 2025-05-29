use crate::test_helpers::storage_proof::TestInputs;
use plonky2::plonk::circuit_data::CircuitConfig;
use wormhole_circuit::inputs::{CircuitInputs, PublicCircuitInputs};
use wormhole_prover::WormholeProver;

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[test]
fn commit_and_prove() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    prover.commit(&inputs).unwrap().prove().unwrap();
}

#[test]
#[ignore = "debug"]
fn get_public_inputs() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let public_inputs = proof.public_inputs;
    println!("{:?}", public_inputs);
}

#[test]
fn proof_can_be_deserialized() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let public_inputs = PublicCircuitInputs::try_from(proof).unwrap();
    println!("{:?}", public_inputs);
}
