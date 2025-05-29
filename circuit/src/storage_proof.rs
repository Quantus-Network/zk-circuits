#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(feature = "std")]
use std::vec;

use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::circuit::{CircuitFragment, D, F};
use crate::gadgets::is_const_less_than;
use crate::inputs::CircuitInputs;
use crate::utils::{bytes_to_felts, u128_to_felts};

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
    pub hashes: Vec<HashOutTarget>,
}

impl StorageProofTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Setup targets. Each 8-bytes are represented as their equivalent field element. We also
        // need to track total proof length to allow for variable length.
        let proof_data: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_targets(PROOF_NODE_MAX_SIZE_F))
            .collect();

        let hashes: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect();

        Self {
            funding_amount: builder.add_virtual_public_input_arr::<FELTS_PER_AMOUNT>(),
            root_hash: builder.add_virtual_hash_public_input(),
            proof_len: builder.add_virtual_target(),
            proof_data,
            hashes,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct StorageProof {
    funding_amount: [F; FELTS_PER_AMOUNT],
    pub proof: Vec<Vec<F>>,
    hashes: Vec<Vec<F>>,
    pub root_hash: [u8; 32],
}

impl StorageProof {
    /// The input is a storage proof as a tuple where each part is split at the index where the child node's
    /// hash, if any, appears within this proof node; and a root hash.
    pub fn new(proof: &[(Vec<u8>, Vec<u8>)], root_hash: [u8; 32], funding_amount: u128) -> Self {
        // First construct the proof and the hash array
        let mut constructed_proof = Vec::with_capacity(proof.len());
        let mut hashes = Vec::with_capacity(proof.len());
        for (left, right) in proof {
            let mut proof_node = Vec::with_capacity(PROOF_NODE_MAX_SIZE_B);
            proof_node.extend_from_slice(left);
            proof_node.extend_from_slice(right);

            // We make sure to convert to field elements after an eventual hash has been appended.
            let proof_node_f = bytes_to_felts(&proof_node);
            let hash = bytes_to_felts(right)[..4].to_vec();

            constructed_proof.push(proof_node_f);
            hashes.push(hash);
        }

        StorageProof {
            funding_amount: u128_to_felts(funding_amount),
            proof: constructed_proof,
            hashes,
            root_hash,
        }
    }
}

impl From<&CircuitInputs> for StorageProof {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            &inputs.private.storage_proof,
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
            ref hashes,
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
            prev_hash = hashes[i];
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

        let empty_hash = vec![F::ZERO; 4];
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
