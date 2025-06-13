use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::substrate_account::SubstrateAccount;
use zk_circuits_common::utils::{Digest, FELTS_PER_U128};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::felts_to_hashout,
};

#[derive(Debug, Clone)]
pub struct LeafTargets {
    nonce: Target,
    funding_account: HashOutTarget,
    to_account: HashOutTarget,
    funding_amount: [Target; FELTS_PER_U128],
    leaf_inputs_hash: HashOutTarget,
}

impl LeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let nonce = builder.add_virtual_target();
        let funding_account = builder.add_virtual_hash();
        let to_account = builder.add_virtual_hash();
        let funding_amount = std::array::from_fn(|_| builder.add_virtual_target());
        let leaf_inputs_hash = builder.add_virtual_hash();

        Self {
            nonce,
            funding_account,
            to_account,
            funding_amount,
            leaf_inputs_hash,
        }
    }
}

#[derive(Debug)]
pub struct LeafInputs {
    nonce: F,
    funding_account: SubstrateAccount,
    to_account: SubstrateAccount,
    funding_amount: [F; FELTS_PER_U128],
    leaf_inputs_hash: Digest,
}

impl LeafInputs {
    pub fn new(
        nonce: F,
        funding_account: SubstrateAccount,
        to_account: SubstrateAccount,
        funding_amount: [F; FELTS_PER_U128],
        leaf_inputs_hash: Digest,
    ) -> Self {
        Self {
            nonce,
            funding_account,
            to_account,
            funding_amount,
            leaf_inputs_hash,
        }
    }
}

impl CircuitFragment for LeafInputs {
    type Targets = LeafTargets;

    /// Computes the hash of all the leaf inputs and compares that against the one found in the
    /// leaf node.
    fn circuit(
        &Self::Targets {
            nonce,
            funding_account,
            to_account,
            funding_amount,
            leaf_inputs_hash,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Setup constraints.
        let mut preimage = vec![nonce];
        preimage.extend(funding_account.elements);
        preimage.extend(to_account.elements);
        preimage.extend(funding_amount);

        let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
        builder.connect_hashes(computed_hash, leaf_inputs_hash);
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        let funding_account = felts_to_hashout(&self.funding_account.0);
        let to_account = felts_to_hashout(&self.to_account.0);
        let leaf_inputs_hash = felts_to_hashout(&self.leaf_inputs_hash);

        pw.set_target(targets.nonce, self.nonce)?;
        pw.set_hash_target(targets.funding_account, funding_account)?;
        pw.set_hash_target(targets.to_account, to_account)?;
        pw.set_target_arr(&targets.funding_amount, &self.funding_amount)?;
        pw.set_hash_target(targets.leaf_inputs_hash, leaf_inputs_hash)
    }
}
