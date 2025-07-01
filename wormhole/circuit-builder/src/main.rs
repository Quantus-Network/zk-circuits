use anyhow::{anyhow, Result};
use std::fs::{create_dir_all, write};

use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::D;

fn main() -> Result<()> {
    println!("Building wormhole circuit...");
    let config = CircuitConfig::standard_recursion_config();
    let circuit = WormholeCircuit::new(config);
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    println!("Serializing circuit data...");

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    create_dir_all("generated-bins")?;

    // Serialize common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize common data: {}", e))?;
    write("generated-bins/common.bin", common_bytes)?;
    println!("Common data saved to generated-bins/common.bin");

    // Serialize verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize verifier data: {}", e))?;
    write("generated-bins/verifier.bin", verifier_only_bytes)?;
    println!("Verifier data saved to generated-bins/verifier.bin");

    // Serialize prover only data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .map_err(|e| anyhow!("Failed to serialize prover data: {}", e))?;
    write("generated-bins/prover.bin", prover_only_bytes)?;
    println!("Prover data saved to generated-bins/prover.bin");

    Ok(())
}
