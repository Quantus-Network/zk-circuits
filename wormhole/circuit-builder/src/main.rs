use anyhow::Result;

fn main() -> Result<()> {
    circuit_builder::generate_circuit_binaries("generated-bins", true)
}
