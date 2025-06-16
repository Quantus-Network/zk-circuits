use plonky2::field::types::Field;
use plonky2::{
    hash::hash_types::HashOutTarget, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};

use crate::inputs::CircuitInputs;
use crate::substrate_account::SubstrateAccount;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::utils::{u128_to_felts, FELTS_PER_U128};

pub const NUM_LEAF_INPUT_FELTS: usize = 11;

#[derive(Debug, Clone)]
pub struct LeafTargets {
    pub nonce: Target,
    pub funding_account: HashOutTarget,
    pub to_account: HashOutTarget,
    pub funding_amount: [Target; FELTS_PER_U128],
}

impl LeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let nonce = builder.add_virtual_target();
        let funding_account = builder.add_virtual_hash();
        let to_account = builder.add_virtual_hash();
        let funding_amount = std::array::from_fn(|_| builder.add_virtual_public_input());

        Self {
            nonce,
            funding_account,
            to_account,
            funding_amount,
        }
    }

    pub fn collect_to_vec(&self) -> Vec<Target> {
        std::iter::once(self.nonce)
            .chain(self.funding_account.elements)
            .chain(self.to_account.elements)
            .chain(self.funding_amount)
            .collect()
    }
}

#[derive(Debug)]
pub struct LeafInputs {
    pub nonce: F,
    pub funding_account: SubstrateAccount,
    pub to_account: SubstrateAccount,
    pub funding_amount: [F; FELTS_PER_U128],
}

impl LeafInputs {
    pub fn new(
        nonce: u32,
        funding_account: SubstrateAccount,
        to_account: SubstrateAccount,
        funding_amount: u128,
    ) -> Self {
        let nonce = F::from_canonical_u32(nonce);
        let funding_amount = u128_to_felts(funding_amount);
        Self {
            nonce,
            funding_account,
            to_account,
            funding_amount,
        }
    }
}

impl From<&CircuitInputs> for LeafInputs {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            inputs.private.funding_nonce,
            inputs.private.funding_account,
            inputs.public.exit_account,
            inputs.public.funding_amount,
        )
    }
}
