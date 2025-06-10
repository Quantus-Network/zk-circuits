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

use crate::inputs::CircuitInputs;
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::gadgets::is_const_less_than;
use zk_circuits_common::utils::{bytes_to_felts, u128_to_felts, ZERO_DIGEST};

pub const MAX_PROOF_LEN: usize = 20;
pub const PROOF_NODE_MAX_SIZE_F: usize = 73;
pub const PROOF_NODE_MAX_SIZE_B: usize = 256;
pub const FELTS_PER_AMOUNT: usize = 2;

#[derive(Debug, Clone)]
pub struct StorageProofTargets {
    pub funding_amount: [Target; 2],
    pub root_hash: HashOutTarget,
    pub proof_len: Target,
    pub proof_data: Vec<Vec<Target>>,
    pub indices: Vec<Target>,
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
            funding_amount: builder.add_virtual_public_input_arr::<FELTS_PER_AMOUNT>(),
            root_hash: builder.add_virtual_hash_public_input(),
            proof_len: builder.add_virtual_target(),
            proof_data,
            indices,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct StorageProof {
    funding_amount: [F; FELTS_PER_AMOUNT],
    pub proof: Vec<Vec<F>>,
    indices: Vec<F>,
    pub root_hash: [u8; 32],
}

impl StorageProof {
    pub fn new(
        proof: &[Vec<u8>],
        indices: &[u8],
        root_hash: [u8; 32],
        funding_amount: u128,
    ) -> Self {
        // TODO: Check that these are the same length.
        let proof = proof.iter().map(|node| bytes_to_felts(&node)).collect();
        let indices = indices.iter().map(|&i| F::from_canonical_u8(i)).collect();

        StorageProof {
            funding_amount: u128_to_felts(funding_amount),
            proof,
            indices,
            root_hash,
        }
    }
}

impl From<&CircuitInputs> for StorageProof {
    fn from(inputs: &CircuitInputs) -> Self {
        // The storage proof contains both the proof itself and also the indices where to look for
        // hashes.
        let proof = &inputs.private.storage_proof.0;
        let indices = &inputs.private.storage_proof.1;

        Self::new(
            &proof,
            &indices,
            inputs.public.root_hash,
            inputs.public.funding_amount,
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
            ref funding_amount,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Setup constraints.
        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        let n_log = (usize::BITS - (MAX_PROOF_LEN - 1).leading_zeros()) as usize;
        for i in 0..MAX_PROOF_LEN {
            let node = &proof_data[i];

            let is_proof_node = is_const_less_than(builder, i, proof_len, n_log);
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
            for (j, _felt) in node.iter().enumerate() {
                let felt_index = builder.constant(F::from_canonical_usize(j));
                let is_start_of_hash = builder.is_equal(felt_index, expected_hash_index);

                // If this is the start of the hash, set the next 4 fetls of `found_hash`.
                for (hash_i, felt) in found_hash.iter_mut().enumerate() {
                    *felt = builder.select(is_start_of_hash, node[j + hash_i], *felt);
                }
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

        // TODO: Set indices.
        let empty_hash = ZERO_DIGEST.to_vec();
        for i in 0..MAX_PROOF_LEN {
            let hash = self.hashes.get(i).unwrap_or(&empty_hash);
            pw.set_hash_target(targets.hashes[i], HashOut::from_partial(&hash[..4]))?;
        }
        // TODO: just a placeholder until we complete leaf hash
        pw.set_target(targets.funding_amount[0], F::ZERO)?;
        pw.set_target(targets.funding_amount[1], F::ZERO)?;
        Ok(())
    }
}

fn slice_to_hashout(slice: &[u8]) -> HashOut<F> {
    let elements = bytes_to_felts(slice);
    HashOut {
        elements: elements.try_into().unwrap(),
    }
}
