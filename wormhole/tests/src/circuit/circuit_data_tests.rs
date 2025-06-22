use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::Hasher;
use std::fs;
use wormhole_circuit::circuit::{circuit_data_from_bytes, circuit_data_to_bytes, WormholeCircuit};
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{felts_to_bytes, u128_to_felts};

#[test]
fn test_circuit_data_serialization() {
    // Build the circuit from source
    let config = CircuitConfig::standard_recursion_config();
    let circuit = WormholeCircuit::new(config);
    let built_circuit_data = circuit.build_circuit();

    // Serialize the circuit data to bytes
    let serialized_bytes =
        circuit_data_to_bytes(&built_circuit_data).expect("Failed to serialize circuit data");

    // Deserialize the bytes back to circuit data
    let deserialized_circuit_data =
        circuit_data_from_bytes(&serialized_bytes).expect("Failed to deserialize circuit data");

    // Re-serialize the deserialized circuit data
    let reserialized_bytes = circuit_data_to_bytes(&deserialized_circuit_data)
        .expect("Failed to re-serialize circuit data");

    // Assert that the original and re-serialized bytes are identical
    assert_eq!(serialized_bytes, reserialized_bytes);
}

#[test]
fn test_prover_and_verifier_from_file_e2e() -> Result<()> {
    // Generate a non-ZK circuit and write it to a temporary file.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();
    let circuit_bytes = circuit_data_to_bytes(&circuit_data).map_err(|e| anyhow::anyhow!(e))?;
    fs::write("circuit_data.bin", &circuit_bytes)?;

    // Create a prover and verifier from the temporary file.
    let prover = WormholeProver::from_file()?;
    let verifier = WormholeVerifier::from_file()?;

    // Create inputs
    let funding_account = SubstrateAccount::new(&[2u8; 32])?;
    let exit_account = SubstrateAccount::new(&[2u8; 32])?;
    let funding_amount = 1000u128;
    let transfer_count = 0u64;

    let mut leaf_inputs_felts = Vec::new();
    leaf_inputs_felts.push(F::from_noncanonical_u64(transfer_count));
    leaf_inputs_felts.extend_from_slice(&funding_account.0);
    leaf_inputs_felts.extend_from_slice(&exit_account.0);
    leaf_inputs_felts.extend_from_slice(&u128_to_felts(funding_amount));

    let leaf_inputs_hash = PoseidonHash::hash_no_pad(&leaf_inputs_felts);
    let root_hash: [u8; 32] = felts_to_bytes(&leaf_inputs_hash.elements)
        .try_into()
        .unwrap();

    let secret = vec![1u8; 32];
    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret: secret.clone(),
            funding_account: (*funding_account).into(),
            storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
            unspendable_account: UnspendableAccount::new(&secret).account_id.into(),
            transfer_count,
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::new(&secret, 0).hash.into(),
            root_hash: root_hash.into(),
            exit_account: (*exit_account).into(),
        },
    };

    // Generate and verify a proof
    let prover_next = prover.commit(&inputs)?;
    let proof = prover_next.prove()?;
    verifier.verify(proof).map_err(|e| anyhow::anyhow!(e))?;

    // Clean up the temporary file
    fs::remove_file("circuit_data.bin")?;

    Ok(())
}
