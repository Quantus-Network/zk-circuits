use std::fs::File;
use std::io::Write;
use wormhole_circuit::circuit::{circuit_data_to_bytes, WormholeCircuit};

fn main() {
    println!("Building wormhole circuit...");
    let circuit = WormholeCircuit::default();
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    println!("Serializing circuit data...");
    let serialized_circuit = circuit_data_to_bytes(&circuit_data).unwrap();
    println!("Circuit data serialized.");

    let mut file = File::create("circuit_data.bin").unwrap();
    file.write_all(&serialized_circuit).unwrap();
    println!("Circuit data saved to circuit_data.bin");
}
