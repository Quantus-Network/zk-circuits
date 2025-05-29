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

use crate::codec::ByteCodec;
use crate::utils::{bytes_to_felts, felts_to_bytes, string_to_felt};
use crate::{
    circuit::{CircuitFragment, D, F},
    codec::FieldElementCodec,
    utils::Digest,
};

pub const SECRET_NUM_TARGETS: usize = 4;
pub const PREIMAGE_NUM_TARGETS: usize = 5;
pub const UNSPENDABLE_SALT: &str = "wormhole";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    pub account_id: Digest,
    pub secret: Vec<F>,
}

impl UnspendableAccount {
    pub fn new(secret: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let mut preimage = Vec::new();
        let secret_felts = bytes_to_felts(secret);
        preimage.push(string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(secret_felts.clone());

        if preimage.len() != PREIMAGE_NUM_TARGETS {
            panic!(
                "Expected secret to be 32 bytes (4 field elements), got {} field elements",
                preimage.len() - 1
            );
        }

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        // println!("inner_hash: {:?}", hex::encode(felts_to_bytes(&inner_hash)));
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let account_id = Digest::from(outer_hash);

        Self {
            account_id,
            secret: secret_felts,
        }
    }
}

// impl From<&CircuitInputs> for UnspendableAccount {
//     fn from(inputs: &CircuitInputs) -> Self {
//         Self{
//             account_id: inputs.private.unspendable_account.account_id,
//             preimage: inputs.private.unspendable_account.preimage,
//         }
//     }
// }

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(felts_to_bytes(&self.account_id));
        bytes.extend(felts_to_bytes(&self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let account_id_size = 4 * f_size; // 4 field elements
        let preimage_size = 5 * f_size; // 5 field elements
        let total_size = account_id_size + preimage_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id = bytes_to_felts(&slice[offset..offset + account_id_size])
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        offset += account_id_size;

        // Deserialize preimage
        let preimage = bytes_to_felts(&slice[offset..offset + preimage_size]);

        Ok(Self {
            account_id,
            secret: preimage,
        })
    }
}

impl FieldElementCodec for UnspendableAccount {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.account_id.to_vec());
        elements.extend(self.secret.clone());
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        // Expected sizes
        let account_id_size = 4;
        let secret_size = 4;
        let total_size = account_id_size + secret_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id = elements[offset..offset + account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        offset += account_id_size;

        // Deserialize preimage
        let secret = elements[offset..offset + secret_size].to_vec();

        Ok(Self { account_id, secret })
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
            account_id: builder.add_virtual_hash(),
            secret: builder.add_virtual_targets(SECRET_NUM_TARGETS),
        }
    }
}

impl CircuitFragment for UnspendableAccount {
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
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        pw.set_target_arr(&targets.secret, &self.secret)?;

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
