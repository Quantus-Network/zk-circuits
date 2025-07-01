use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use std::fs;
use std::path::Path;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::circuit::{circuit_data_from_bytes, circuit_data_to_bytes};
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::circuit::{D, F};
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
    // Create a temp directory for the test files
    let temp_dir = "temp_test_bins_e2e";
    fs::create_dir_all(temp_dir)?;

    // Generate circuit and write component files to the temporary directory.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize and write common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let common_path = Path::new(temp_dir).join("common.bin");
    fs::write(&common_path, &common_bytes)?;

    // Serialize and write verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let verifier_path = Path::new(temp_dir).join("verifier.bin");
    fs::write(&verifier_path, &verifier_only_bytes)?;

    // Serialize and write prover only data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prover_path = Path::new(temp_dir).join("prover.bin");
    fs::write(&prover_path, &prover_only_bytes)?;

    // Create a prover and verifier from the temporary files.
    let prover = WormholeProver::new_from_files(&prover_path, &common_path)?;
    let verifier = WormholeVerifier::new_from_files(&verifier_path, &common_path)?;

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
            unspendable_account: UnspendableAccount::from_secret(&secret).account_id.into(),
            transfer_count,
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(&secret, 0).hash.into(),
            root_hash: root_hash.into(),
            exit_account: (*exit_account).into(),
        },
    };

    // Generate and verify a proof
    let prover_next = prover.commit(&inputs)?;
    let proof = prover_next.prove()?;
    verifier.verify(proof)?;

    // Clean up the temporary directory
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}
