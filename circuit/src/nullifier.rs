#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::codec::ByteCodec;
use crate::utils::{bytes_to_felts, felts_to_bytes, string_to_felt, Digest};
use crate::{
    circuit::{CircuitFragment, D, F},
    codec::FieldElementCodec,
};
use plonky2::field::types::Field;
use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

pub const NULLIFIER_SALT: &str = "~nullif~";
pub const SECRET_NUM_TARGETS: usize = 4;
pub const NONCE_NUM_TARGETS: usize = 1;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = 4;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + NONCE_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize = 4 + 4 + 1 + 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    // FIXME: Should not be public, remove once hash is precomputed in tests.
    pub hash: Digest,
    pub secret: Vec<F>,
    funding_nonce: F,
    funding_account: Vec<F>,
}

impl Nullifier {
    pub fn new(secret: &[u8], funding_nonce: u32, funding_account: &[u8]) -> Self {
        let mut preimage = Vec::new();
        let salt = string_to_felt(NULLIFIER_SALT);
        let secret = bytes_to_felts(secret);
        let funding_nonce = F::from_canonical_u32(funding_nonce);
        let funding_account = bytes_to_felts(funding_account);
        preimage.push(salt);
        preimage.extend(secret.clone());
        preimage.push(funding_nonce);
        preimage.extend(funding_account.clone());

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret,
            funding_nonce,
            funding_account,
        }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(felts_to_bytes(&self.hash));
        bytes.extend(felts_to_bytes(&self.secret));
        bytes.extend(felts_to_bytes(&[self.funding_nonce]));
        bytes.extend(felts_to_bytes(&self.funding_account));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let hash_size = 4 * f_size; // 4 field elements
        let secret_size = 4 * f_size; // 4 field elements
        let nonce_size = f_size; // 1 field element
        let funding_account_size = 4 * f_size; // 4 field elements
        let total_size = hash_size + secret_size + nonce_size + funding_account_size;

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

        // Deserialize funding_nonce
        let funding_nonce = bytes_to_felts(&slice[offset..offset + nonce_size])
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Failed to deserialize funding_nonce"))?;
        offset += nonce_size;

        // Deserialize funding_account
        let funding_account = bytes_to_felts(&slice[offset..offset + funding_account_size]);
        if funding_account.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for funding_account, got: {}",
                funding_account.len()
            ));
        }

        Ok(Self {
            hash,
            secret,
            funding_nonce,
            funding_account,
        })
    }
}

impl FieldElementCodec for Nullifier {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.hash.to_vec());
        elements.extend(self.secret.clone());
        elements.push(self.funding_nonce);
        elements.extend(self.funding_account.clone());
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        let hash_size = 4; // 32 bytes = 4 field elements
        let secret_size = 4; // 32 bytes = 4 field elements
        let nonce_size = 1; // 1 field element
        let funding_account_size = 4; // 32 bytes = 4 field elements
        let total_size = hash_size + secret_size + nonce_size + funding_account_size;

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
        let funding_nonce = elements[offset];
        offset += nonce_size;

        // Deserialize funding_account
        let funding_account = elements[offset..offset + funding_account_size].to_vec();

        Ok(Self {
            hash,
            secret,
            funding_nonce,
            funding_account,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    hash: HashOutTarget,
    pub secret: Vec<Target>,
    funding_nonce: Target,
    pub funding_account: Vec<Target>,
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // TODO: reuse target from other fragment here
        Self {
            hash: builder.add_virtual_hash_public_input(),
            secret: builder.add_virtual_targets(SECRET_NUM_TARGETS),
            funding_nonce: builder.add_virtual_target(),
            funding_account: builder.add_virtual_targets(FUNDING_ACCOUNT_NUM_TARGETS),
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
            funding_nonce,
            ref funding_account,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let mut preimage = Vec::new();
        let salt = builder.constant(string_to_felt(NULLIFIER_SALT));
        preimage.push(salt);
        preimage.extend(secret);
        preimage.push(funding_nonce);
        preimage.extend(funding_account);

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
        pw.set_target(targets.funding_nonce, self.funding_nonce)?;
        pw.set_target_arr(&targets.funding_account, &self.funding_account)?;
        Ok(())
    }
}
