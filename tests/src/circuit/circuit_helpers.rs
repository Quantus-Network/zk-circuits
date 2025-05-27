use plonky2::{
    field::types::Field,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};

/// Convenience function for initializing a test circuit environment.
pub fn setup_test_builder_and_witness(
    use_public_inputs: bool,
) -> (
    CircuitBuilder<F, D>,
    plonky2::iop::witness::PartialWitness<F>,
) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = plonky2::iop::witness::PartialWitness::new();

    if use_public_inputs {
        let public_inputs = builder.add_virtual_targets(4);
        builder.register_public_inputs(&public_inputs);
    }

    (builder, pw)
}

/// Convenience function for building and verifying a test function. The circuit is assumed to
/// have been setup prior to calling this function.
pub fn build_and_prove_test<C: GenericConfig<D, F = F>>(
    builder: CircuitBuilder<F, D>,
    pw: plonky2::iop::witness::PartialWitness<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let data = builder.build::<C>();
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok(proof)
}
