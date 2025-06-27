use std::fs::{create_dir_all, File};
use std::io::Write;

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use wormhole_circuit::circuit::WormholeCircuit;
use zk_circuits_common::circuit::D;

fn main() {
    println!("Building wormhole circuit...");
    let circuit = WormholeCircuit::default();
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

    create_dir_all("generated-bins").unwrap();

    // Serialize common data
    let common_bytes = common_data.to_bytes(&gate_serializer).unwrap();
    let mut file = File::create("generated-bins/common.bin").unwrap();
    file.write_all(&common_bytes).unwrap();
    println!("Common data saved to generated-bins/common.bin");

    // Serialize verifier only data
    let verifier_only_bytes = verifier_data.verifier_only.to_bytes().unwrap();
    let mut file = File::create("generated-bins/verifier.bin").unwrap();
    file.write_all(&verifier_only_bytes).unwrap();
    println!("Verifier data saved to generated-bins/verifier.bin");

    // Serialize prover only data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .unwrap();
    let mut file = File::create("generated-bins/prover.bin").unwrap();
    file.write_all(&prover_only_bytes).unwrap();
    println!("Prover data saved to generated-bins/prover.bin");
}
