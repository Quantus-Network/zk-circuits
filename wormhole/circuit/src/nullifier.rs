#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::codec::ByteCodec;
use crate::codec::FieldElementCodec;
use crate::inputs::CircuitInputs;
use plonky2::field::types::Field;
use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::utils::{bytes_to_felts, felts_to_bytes, string_to_felt, Digest};

pub const NULLIFIER_SALT: &str = "~nullif~";
pub const SECRET_NUM_TARGETS: usize = 4;
pub const NONCE_NUM_TARGETS: usize = 1;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = 4;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + NONCE_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize = 4 + 4 + 1 + 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    pub secret: Vec<F>,
    transfer_count: F,
}

impl Nullifier {
    pub fn new(secret: &[u8], transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt = string_to_felt(NULLIFIER_SALT);
        let secret = bytes_to_felts(secret);
        let transfer_count = F::from_noncanonical_u64(transfer_count);

        preimage.push(salt);
        preimage.extend(secret.clone());
        preimage.push(transfer_count);

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(felts_to_bytes(&self.hash));
        bytes.extend(felts_to_bytes(&self.secret));
        bytes.extend(felts_to_bytes(&[self.transfer_count]));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let hash_size = 4 * f_size; // 4 field elements
        let secret_size = 4 * f_size; // 4 field elements
        let transfer_count_size = f_size; // 1 field element
        let total_size = hash_size + secret_size + transfer_count_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for Nullifier, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let hash = bytes_to_felts(&slice[offset..offset + hash_size])
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += hash_size;

        // Deserialize secret
        let secret = bytes_to_felts(&slice[offset..offset + secret_size]);
        if secret.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for secret, got: {}",
                secret.len()
            ));
        }
        offset += secret_size;

        // Deserialize transfer_count
        let transfer_count = bytes_to_felts(&slice[offset..offset + transfer_count_size])
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Failed to deserialize transfer_count"))?;

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl FieldElementCodec for Nullifier {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.hash.to_vec());
        elements.extend(self.secret.clone());
        elements.push(self.transfer_count);
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        let hash_size = 4; // 32 bytes = 4 field elements
        let secret_size = 4; // 32 bytes = 4 field elements
        let transfer_count_size = 1; // 1 field element
        let total_size = hash_size + secret_size + transfer_count_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for Nullifier, got: {}",
                total_size,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let hash = elements[offset..offset + hash_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += hash_size;

        // Deserialize secret
        let secret = elements[offset..offset + secret_size].to_vec();
        offset += secret_size;

        // Deserialize funding_nonce
        let transfer_count = elements[offset];

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl From<&CircuitInputs> for Nullifier {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(&inputs.private.secret, inputs.private.transfer_count)
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    hash: HashOutTarget,
    pub secret: Vec<Target>,
    transfer_count: Target,
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // TODO: reuse target from other fragment here
        Self {
            hash: builder.add_virtual_hash_public_input(),
            secret: builder.add_virtual_targets(SECRET_NUM_TARGETS),
            transfer_count: builder.add_virtual_target(),
        }
    }
}

impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(
        &Self::Targets {
            hash,
            ref secret,
            transfer_count,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let mut preimage = Vec::new();
        let salt = builder.constant(string_to_felt(NULLIFIER_SALT));
        preimage.push(salt);
        preimage.extend(secret);
        preimage.push(transfer_count);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_target_arr(&targets.secret, &self.secret)?;
        pw.set_target(targets.transfer_count, self.transfer_count)?;
        Ok(())
    }
}
