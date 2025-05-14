use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::circuit::{slice_to_field_elements, CircuitFragment, D, F};
use crate::inputs::CircuitInputs;

#[derive(Debug, Default)]
pub struct ExitAccount([u8; 32]);

impl ExitAccount {
    pub fn new(address: [u8; 32]) -> Self {
        Self(address)
    }
}

impl From<&CircuitInputs> for ExitAccount {
    fn from(value: &CircuitInputs) -> Self {
        Self::new(value.exit_account)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: HashOutTarget,
}

impl CircuitFragment for ExitAccount {
    type PrivateInputs = ();
    type Targets = ExitAccountTargets;

    /// Builds a dummy circuit to include the exit account as a public input.
    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let address = builder.add_virtual_hash_public_input();
        ExitAccountTargets { address }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        _inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        let address = HashOut::from_partial(&slice_to_field_elements(&self.0));
        pw.set_hash_target(targets.address, address)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };

    use super::*;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    fn run_test(exit_account: &ExitAccount) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = ExitAccount::circuit(&mut builder);

        exit_account.fill_targets(&mut pw, targets, ()).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn run_circuit() {
        let exit_account = ExitAccount::default();
        run_test(&exit_account).unwrap();
    }
}
