#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::bail;
#[cfg(feature = "std")]
use std::vec::Vec;

use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    inputs::CircuitInputs,
    storage_proof::leaf::{LeafInputs, LeafTargets},
};
use zk_circuits_common::utils::bytes_to_felts;
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::BYTES_PER_ELEMENT,
};
use zk_circuits_common::{gadgets::is_const_less_than, utils::felts_to_hashout};

pub mod leaf;

pub const MAX_PROOF_LEN: usize = 20;
pub const PROOF_NODE_MAX_SIZE_F: usize = 73;
pub const PROOF_NODE_MAX_SIZE_B: usize = 256;
pub const FELTS_PER_AMOUNT: usize = 2;

#[derive(Debug, Clone)]
pub struct StorageProofTargets {
    pub root_hash: HashOutTarget,
    pub proof_len: Target,
    pub proof_data: Vec<Vec<Target>>,
    pub indices: Vec<Target>,
    pub leaf_inputs: LeafTargets,
}

impl StorageProofTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Setup targets. Each 8-bytes are represented as their equivalent field element. We also
        // need to track total proof length to allow for variable length.
        let proof_data: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_targets(PROOF_NODE_MAX_SIZE_F))
            .collect();

        let indices: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();

        Self {
            root_hash: builder.add_virtual_hash_public_input(),
            proof_len: builder.add_virtual_target(),
            proof_data,
            indices,
            leaf_inputs: LeafTargets::new(builder),
        }
    }
}

/// A storgae proof along with an array of indices where the hash child ndoes are placed.
#[derive(Debug, Clone)]
pub struct ProcessedStorageProof {
    pub proof: Vec<Vec<u8>>,
    pub indices: Vec<usize>,
}

impl ProcessedStorageProof {
    pub fn new(proof: Vec<Vec<u8>>, indices: Vec<usize>) -> anyhow::Result<Self> {
        if proof.len() != indices.len() {
            bail!(
                "indices length must be equal to proof length, actual lengths: {}, {}",
                proof.len(),
                indices.len()
            );
        }

        Ok(Self { proof, indices })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct StorageProof {
    pub proof: Vec<Vec<F>>,
    pub indices: Vec<F>,
    pub root_hash: [u8; 32],
    pub leaf_inputs: LeafInputs,
}

impl StorageProof {
    pub fn new(
        processed_proof: &ProcessedStorageProof,
        root_hash: [u8; 32],
        leaf_inputs: LeafInputs,
    ) -> Self {
        let proof: Vec<Vec<F>> = processed_proof
            .proof
            .iter()
            .map(|node| bytes_to_felts(node))
            .collect();

        let indices = processed_proof
            .indices
            .iter()
            .map(|&i| {
                // Divide by 16 to get the field element index instead of the hex index.
                let i = i / (BYTES_PER_ELEMENT * 2);
                F::from_canonical_usize(i)
            })
            .collect();

        StorageProof {
            proof,
            indices,
            root_hash,
            leaf_inputs,
        }
    }
}

impl From<&CircuitInputs> for StorageProof {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            &inputs.private.storage_proof,
            inputs.public.root_hash,
            LeafInputs::from(inputs),
        )
    }
}

impl CircuitFragment for StorageProof {
    type Targets = StorageProofTargets;

    #[allow(unused_variables)]
    fn circuit(
        &Self::Targets {
            root_hash,
            proof_len,
            ref proof_data,
            ref indices,
            ref leaf_inputs,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Setup constraints.

        // Calculate the leaf inputs hash.
        let leaf_inputs_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf_inputs.collect_to_vec());

        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        let n_log = (usize::BITS - (MAX_PROOF_LEN - 1).leading_zeros()) as usize;
        for i in 0..MAX_PROOF_LEN {
            let node = &proof_data[i];

            // Chech if this is a valid proof node or a dummy one.
            let is_proof_node = is_const_less_than(builder, i, proof_len, n_log);

            // Check if this is a leaf node.
            let i_t = builder.constant(F::from_canonical_usize(i));
            let is_leaf_node = builder.is_equal(i_t, proof_len);

            // Compute the hash of this node and compare it against the previous hash.
            let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.clone());
            for y in 0..4 {
                let diff = builder.sub(computed_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_proof_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            // Update `prev_hash` to the hash of the child that's stored within this node.
            // We first find the hash using the commited index.
            let mut found_hash = vec![
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
            ];
            let expected_hash_index = indices[i];
            for (j, _felt) in node.iter().enumerate().take(PROOF_NODE_MAX_SIZE_F - 4) {
                let felt_index = builder.constant(F::from_canonical_usize(j));
                let is_start_of_hash = builder.is_equal(felt_index, expected_hash_index);

                // If this is the start of the hash, set the next 4 felts of `found_hash`.
                for (hash_i, felt) in found_hash.iter_mut().enumerate() {
                    *felt = builder.select(is_start_of_hash, node[j + hash_i], *felt);
                }
            }

            // Lastly, we do an additional check if this is the leaf node - that the hash of its
            // inputs is contained within the node. Note: we only compare the last 3 felts since
            // the stored leaf inputs hash does not always contain the first nibble.
            for y in 1..4 {
                let diff = builder.sub(leaf_inputs_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_leaf_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            prev_hash = HashOutTarget::from_vec(found_hash);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        const EMPTY_PROOF_NODE: [F; PROOF_NODE_MAX_SIZE_F] = [F::ZERO; PROOF_NODE_MAX_SIZE_F];

        pw.set_hash_target(targets.root_hash, slice_to_hashout(&self.root_hash))?;
        pw.set_target(targets.proof_len, F::from_canonical_usize(self.proof.len()))?;

        for i in 0..MAX_PROOF_LEN {
            match self.proof.get(i) {
                Some(node) => {
                    let mut padded_proof_node = node.clone();
                    padded_proof_node.resize(PROOF_NODE_MAX_SIZE_F, F::ZERO);
                    pw.set_target_arr(&targets.proof_data[i], &padded_proof_node)?;
                }
                None => pw.set_target_arr(&targets.proof_data[i], &EMPTY_PROOF_NODE)?,
            }
        }

        for i in 0..MAX_PROOF_LEN {
            let &felt = self.indices.get(i).unwrap_or(&F::ZERO);
            pw.set_target(targets.indices[i], felt)?;
        }

        // Set leaf input targets.
        let funding_account = felts_to_hashout(&self.leaf_inputs.funding_account.0);
        let to_account = felts_to_hashout(&self.leaf_inputs.to_account.0);

        pw.set_target(targets.leaf_inputs.nonce, self.leaf_inputs.nonce)?;
        pw.set_hash_target(targets.leaf_inputs.funding_account, funding_account)?;
        pw.set_hash_target(targets.leaf_inputs.to_account, to_account)?;
        pw.set_target_arr(
            &targets.leaf_inputs.funding_amount,
            &self.leaf_inputs.funding_amount,
        )?;

        Ok(())
    }
}

fn slice_to_hashout(slice: &[u8]) -> HashOut<F> {
    let elements = bytes_to_felts(slice);
    HashOut {
        elements: elements.try_into().unwrap(),
    }
}
