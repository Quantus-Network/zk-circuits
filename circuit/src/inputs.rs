use anyhow::bail;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};

use crate::{
    circuit::{C, D, F},
    codec::FieldElementCodec,
    substrate_account::SubstrateAccount,
    nullifier::Nullifier,
    unspendable_account::UnspendableAccount,
};
use crate::circuit::Digest;
use crate::utils::{felts_to_u128, field_elements_to_bytes};

const PUBLIC_INPUTS_FELTS_LEN: usize = 19;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: Nullifier,
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: SubstrateAccount,
}

impl TryFrom<ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        let public_inputs = proof.public_inputs;

        if public_inputs.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                public_inputs.len()
            )
        }

        let funding_amount = felts_to_u128(public_inputs[0..2].to_vec());
        let nullifier = Nullifier::from_field_elements(&public_inputs[2..6])?;

        let root_hash: [u8; 32] = field_elements_to_bytes(&public_inputs[6..10])
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize root hash from public inputs"))?;

        let exit_account = SubstrateAccount::from_field_elements(&public_inputs[10..14])?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}

/// All of the private inputs required for the circuit.
#[derive(Debug)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the preimage of the nullifier and the unspendable account
    pub secret: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    pub funding_nonce: u32,
    pub funding_account: SubstrateAccount,
    /// The unspendable account hash.
    pub unspendable_account: UnspendableAccount,
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use crate::substrate_account::SubstrateAccount;
    use crate::nullifier::{self, Nullifier};
    use crate::storage_proof::test_helpers::{default_proof, ROOT_HASH};
    use crate::unspendable_account::{self, UnspendableAccount};

    use super::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};

    impl Default for CircuitInputs {
        fn default() -> Self {
            let nullifier_preimage = hex::decode(nullifier::test_helpers::PREIMAGE).unwrap();
            let unspendable_account_preimage =
                hex::decode(unspendable_account::test_helpers::PREIMAGES[0]).unwrap();
            let root_hash: [u8; 32] = hex::decode(ROOT_HASH).unwrap().try_into().unwrap();

            let nullifier = Nullifier::new(&nullifier_preimage);
            let unspendable_account = UnspendableAccount::new(&unspendable_account_preimage);
            let exit_account = SubstrateAccount::new(&[254u8; 32]).unwrap();
            let funding_account = SubstrateAccount::new(&[234u8; 32]).unwrap();

            Self {
                public: PublicCircuitInputs {
                    funding_amount: 0,
                    nullifier,
                    root_hash,
                    exit_account,
                },
                private: PrivateCircuitInputs {
                    secret: nullifier_preimage,
                    storage_proof: default_proof(),
                    funding_nonce: 0,
                    funding_account,
                    unspendable_account,
                },
            }
        }
    }
}
