#![allow(clippy::new_without_default)]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::ops::Deref;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::storage_proof::ProcessedStorageProof;
use anyhow::{anyhow, bail, Context};
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{felts_to_bytes, felts_to_u128, fixed_felts_to_bytes, Digest};

/// The total size of the public inputs field element vector.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 14;
pub const NULLIFIER_START_INDEX: usize = 0;
pub const NULLIFIER_END_INDEX: usize = 4;
pub const FUNDING_AMOUNT_START_INDEX: usize = 4;
pub const FUNDING_AMOUNT_END_INDEX: usize = 6;
pub const ROOT_HASH_START_INDEX: usize = 6;
pub const ROOT_HASH_END_INDEX: usize = 10;
pub const EXIT_ACCOUNT_START_INDEX: usize = 10;
pub const EXIT_ACCOUNT_END_INDEX: usize = 14;

/// A bytes digest containing various helpful methods for converting between
/// field element digests and byte digests.
#[derive(Default, Debug, Clone, Copy)]
pub struct BytesDigest([u8; 32]);

impl From<[u8; 32]> for BytesDigest {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for BytesDigest {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = value.try_into().map_err(|_| {
            anyhow!(
                "failed to deserialize bytes digest from byte vector. Expected length 32, got {}",
                value.len()
            )
        })?;
        Ok(Self(bytes))
    }
}

impl From<Digest> for BytesDigest {
    fn from(value: Digest) -> Self {
        let bytes = fixed_felts_to_bytes(value);
        Self(bytes)
    }
}

impl TryFrom<&[F]> for BytesDigest {
    type Error = anyhow::Error;

    fn try_from(value: &[F]) -> Result<Self, Self::Error> {
        let bytes = felts_to_bytes(value).try_into().map_err(|_| {
            anyhow!(
                "failed to deserialize bytes digest from field elements. Expected length 4, got {}",
                value.len()
            )
        })?;
        Ok(Self(bytes))
    }
}

impl Deref for BytesDigest {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: BytesDigest,
    /// The root hash of the storage trie.
    pub root_hash: BytesDigest,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// All of the private inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: ProcessedStorageProof,
    pub transfer_count: u64,
    pub funding_account: BytesDigest,
    /// The unspendable account hash.
    pub unspendable_account: BytesDigest,
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

        let nullifier =
            BytesDigest::try_from(&public_inputs[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
                .context("failed to deserialize nullifier hash")?;
        let funding_amount = felts_to_u128(
            <[F; 2]>::try_from(
                &public_inputs[FUNDING_AMOUNT_START_INDEX..FUNDING_AMOUNT_END_INDEX],
            )
            .context("failed to deserialize funding amount")?,
        );
        let root_hash =
            BytesDigest::try_from(&public_inputs[ROOT_HASH_START_INDEX..ROOT_HASH_END_INDEX])
                .context("failed to deserialize root hash")?;

        let exit_account =
            BytesDigest::try_from(&public_inputs[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX])
                .context("failed to deserialize exit account")?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}
