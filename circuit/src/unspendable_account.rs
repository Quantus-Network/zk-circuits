#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::utils::{bytes_to_felts, felts_to_bytes, string_to_felt};
use crate::{
    circuit::{CircuitFragment, Digest, D, F},
    codec::FieldElementCodec,
};
use crate::{codec::ByteCodec, inputs::CircuitInputs};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 4;
pub const UNSPENDABLE_SALT: &str = "wormhole";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UnspendableAccount {
    pub account_id: Digest,
}

impl UnspendableAccount {
    pub fn new(secret: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let mut preimage = Vec::new();
        preimage.push(string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(bytes_to_felts(secret));

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let account_id = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { account_id }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        felts_to_bytes(&self.account_id)
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let account_id = bytes_to_felts(slice).try_into().map_err(|_| {
            anyhow::anyhow!("failed to deserialize bytes into unspendable account hash")
        })?;
        Ok(Self { account_id })
    }
}

impl FieldElementCodec for UnspendableAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.account_id.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for Unspendable Account, got: {}",
                elements.len()
            ));
        }

        let account_id = elements.try_into()?;
        Ok(Self { account_id })
    }
}

impl From<&CircuitInputs> for UnspendableAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        inputs.private.unspendable_account
    }
}

#[derive(Debug, Clone)]
pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    pub secret: Vec<Target>,
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: builder.add_virtual_hash_public_input(),
            secret: builder.add_virtual_targets(PREIMAGE_NUM_TARGETS),
        }
    }
}

#[derive(Debug)]
pub struct UnspendableAccountInputs {
    pub secret: Vec<F>,
}

impl UnspendableAccountInputs {
    pub fn new(secret: &[u8]) -> Self {
        let secret = bytes_to_felts(secret);
        Self { secret }
    }
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(
        &Self::Targets {
            account_id,
            ref secret,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = builder.constant(string_to_felt(UNSPENDABLE_SALT));
        let mut preimage = Vec::new();
        preimage.push(salt);
        preimage.extend(secret);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        pw.set_target_arr(&targets.secret, &inputs.secret)?;

        Ok(())
    }
}

impl Default for UnspendableAccount {
    fn default() -> Self {
        let preimage =
            hex::decode("cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229")
                .unwrap();
        Self::new(&preimage)
    }
}

impl Default for UnspendableAccountInputs {
    fn default() -> Self {
        let preimage =
            hex::decode("cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229")
                .unwrap();
        Self::new(&preimage)
    }
}
