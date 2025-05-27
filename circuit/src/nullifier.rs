#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::utils::{bytes_to_felts, felts_to_bytes, string_to_felt};
use crate::{
    circuit::{CircuitFragment, Digest, D, F},
    codec::FieldElementCodec,
};
use crate::{codec::ByteCodec, inputs::CircuitInputs};
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nullifier {
    hash: Digest,
}

impl Nullifier {
    pub fn new(secret: &[u8], funding_nonce: u32, funding_account: &[u8]) -> Self {
        let mut preimage = Vec::new();
        let salt = string_to_felt(NULLIFIER_SALT);
        let secret = bytes_to_felts(secret);
        let funding_nonce = F::from_canonical_u32(funding_nonce);
        let funding_account = bytes_to_felts(funding_account);
        preimage.push(salt);
        preimage.extend(secret);
        preimage.push(funding_nonce);
        preimage.extend(funding_account);

        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let hash = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { hash }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        felts_to_bytes(&self.hash)
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let hash = bytes_to_felts(slice)
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize bytes into nullifier hash"))?;
        Ok(Self { hash })
    }
}

impl FieldElementCodec for Nullifier {
    fn to_field_elements(&self) -> Vec<F> {
        self.hash.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for Nullifier, got: {}",
                elements.len()
            ));
        }

        let hash = elements.try_into()?;
        Ok(Self { hash })
    }
}

impl From<&CircuitInputs> for Nullifier {
    fn from(inputs: &CircuitInputs) -> Self {
        inputs.public.nullifier
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

#[derive(Debug)]
pub struct NullifierInputs {
    pub secret: Vec<F>,
    funding_nonce: F,
    pub funding_account: Vec<F>,
}

impl NullifierInputs {
    pub fn new(secret: &[u8], funding_nonce: u32, funding_account: &[u8]) -> Self {
        let secret = bytes_to_felts(secret);
        let funding_nonce = F::from_canonical_u32(funding_nonce);
        let funding_account = bytes_to_felts(funding_account);
        Self {
            secret,
            funding_nonce,
            funding_account,
        }
    }
}

impl CircuitFragment for Nullifier {
    type PrivateInputs = NullifierInputs;
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
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_target_arr(&targets.secret, &inputs.secret)?;
        pw.set_target(targets.funding_nonce, inputs.funding_nonce)?;
        pw.set_target_arr(&targets.funding_account, &inputs.funding_account)?;
        Ok(())
    }
}
