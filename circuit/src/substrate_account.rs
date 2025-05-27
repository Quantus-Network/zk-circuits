#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::circuit::{CircuitFragment, Digest, D, F};
use crate::codec::{ByteCodec, FieldElementCodec};
use crate::inputs::CircuitInputs;
use crate::utils::{bytes_to_felts, felts_to_bytes};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct SubstrateAccount(Digest);

impl SubstrateAccount {
    pub fn new(address: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(address)
    }
}

impl ByteCodec for SubstrateAccount {
    fn to_bytes(&self) -> Vec<u8> {
        felts_to_bytes(&self.0)
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let address = bytes_to_felts(slice).try_into().map_err(|_| {
            anyhow::anyhow!("failed to deserialize bytes into exit account address")
        })?;
        Ok(SubstrateAccount(address))
    }
}

impl FieldElementCodec for SubstrateAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.0.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for ExitAccount address, got: {}",
                elements.len()
            ));
        }

        let address = elements.try_into()?;
        Ok(Self(address))
    }
}

impl From<&CircuitInputs> for SubstrateAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        inputs.public.exit_account
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: HashOutTarget,
}

impl ExitAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            address: builder.add_virtual_hash_public_input(),
        }
    }
}

impl CircuitFragment for SubstrateAccount {
    type PrivateInputs = ();
    type Targets = ExitAccountTargets;

    /// Builds a dummy circuit to include the exit account as a public input.
    fn circuit(Self::Targets { address: _ }: &Self::Targets, _builder: &mut CircuitBuilder<F, D>) {}

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        _inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.address, self.0.into())
    }
}
