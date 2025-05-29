#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::circuit::{C, D, F};
use crate::codec::FieldElementCodec;
use crate::nullifier::Nullifier;
use crate::substrate_account::SubstrateAccount;
use crate::unspendable_account::UnspendableAccount;
use crate::utils::{felts_to_bytes, felts_to_u128};
use anyhow::bail;
use plonky2::plonk::proof::ProofWithPublicInputs;

/// The total size of the public inputs field element vector.
const PUBLIC_INPUTS_FELTS_LEN: usize = 14;
#[allow(dead_code)]
const NULLIFIER_START_INDEX: usize = 0;
#[allow(dead_code)]
const NULLIFIER_END_INDEX: usize = 4;
const FUNDING_AMOUNT_START_INDEX: usize = 4;
const FUNDING_AMOUNT_END_INDEX: usize = 6;
const ROOT_HASH_START_INDEX: usize = 6;
const ROOT_HASH_END_INDEX: usize = 10;
const EXIT_ACCOUNT_START_INDEX: usize = 10;
const EXIT_ACCOUNT_END_INDEX: usize = 14;
pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_FUNDING_NONCE: u32 = 0;
pub const DEFAULT_FUNDING_ACCOUNT: &[u8] = &[10u8; 32];

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

/// All of the private inputs required for the circuit.
#[derive(Debug)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
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

impl TryFrom<ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        let public_inputs = proof.public_inputs;

        // Public inputs are ordered as follows:
        // Nullifier.hash: 4 felts
        // StorageProof.funding_amount: 2 felts
        // StorageProof.root_hash: 4 felts
        // ExitAccount.address: 4 felts
        if public_inputs.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                public_inputs.len()
            )
        }

        // TODO: fix this
        // let nullifier = Nullifier::from_field_elements(&public_inputs[idx0..idx1])?;
        let nullifier = Nullifier::new(
            DEFAULT_SECRET.as_ref(),
            DEFAULT_FUNDING_NONCE,
            DEFAULT_FUNDING_ACCOUNT,
        );
        let funding_amount = felts_to_u128(<[F; 2]>::try_from(
            &public_inputs[FUNDING_AMOUNT_START_INDEX..FUNDING_AMOUNT_END_INDEX],
        )?);
        let root_hash: [u8; 32] =
            felts_to_bytes(&public_inputs[ROOT_HASH_START_INDEX..ROOT_HASH_END_INDEX])
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!("failed to deserialize root hash from public inputs")
                })?;

        let exit_account = SubstrateAccount::from_field_elements(
            &public_inputs[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX],
        )?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}
