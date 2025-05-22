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

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::{Nullifier, NullifierInputs};

    pub const SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
    pub const FUNDING_NONCE: u32 = 0;
    pub const FUNDING_ACCOUNT: &[u8] = &[10u8; 32];
    impl Default for Nullifier {
        fn default() -> Self {
            let secret = hex::decode(SECRET).unwrap();
            Self::new(secret.as_slice(), FUNDING_NONCE, FUNDING_ACCOUNT)
        }
    }

    impl Default for NullifierInputs {
        fn default() -> Self {
            let secret = hex::decode(SECRET).unwrap();
            Self::new(&secret, FUNDING_NONCE, FUNDING_ACCOUNT)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};

    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use crate::nullifier::test_helpers::{FUNDING_ACCOUNT, FUNDING_NONCE, SECRET};

    use super::*;

    fn run_test(
        nullifier: &Nullifier,
        inputs: NullifierInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = NullifierTargets::new(&mut builder);
        Nullifier::circuit(&targets, &mut builder);

        nullifier.fill_targets(&mut pw, targets, inputs)?;
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_nullifier_proof() {
        let nullifier = Nullifier::default();
        let inputs = NullifierInputs::default();
        run_test(&nullifier, inputs).unwrap();
    }

    #[test]
    fn invalid_secret_fails_proof() {
        let valid_nullifier = Nullifier::default();

        // Flip the first byte of the preimage.
        let mut invalid_bytes = hex::decode(SECRET).unwrap();
        invalid_bytes[0] ^= 0xFF;

        let bad_inputs = NullifierInputs::new(&invalid_bytes, FUNDING_NONCE, FUNDING_ACCOUNT);

        let res = run_test(&valid_nullifier, bad_inputs);
        assert!(res.is_err());
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let nonce = 0;
        let funder = [0u8; 32];
        let nullifier = Nullifier::new(&preimage_bytes, nonce, &funder);
        assert!(!nullifier.hash.to_vec().iter().all(Field::is_zero));
    }

    #[test]
    fn nullifier_codec() {
        let nullifier = Nullifier {
            hash: [
                F::from_noncanonical_u64(1),
                F::from_noncanonical_u64(2),
                F::from_noncanonical_u64(3),
                F::from_noncanonical_u64(4),
            ],
        };

        // Encode the account as field elements and compare.
        let field_elements = nullifier.to_field_elements();
        assert_eq!(field_elements.len(), 4);
        assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
        assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
        assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
        assert_eq!(field_elements[3], F::from_noncanonical_u64(4));

        // Decode the field elements back into an UnspendableAccount
        let recovered_nullifier = Nullifier::from_field_elements(&field_elements).unwrap();
        assert_eq!(nullifier, recovered_nullifier);
    }

    #[test]
    fn codec_invalid_length() {
        let invalid_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
        let recovered_nullifier_result = Nullifier::from_field_elements(&invalid_elements);

        assert!(recovered_nullifier_result.is_err());
        assert_eq!(
            recovered_nullifier_result.unwrap_err().to_string(),
            "Expected 4 field elements for Nullifier, got: 2"
        );
    }

    #[test]
    fn codec_empty_elements() {
        let empty_elements: Vec<F> = vec![];
        let recovered_nullifier_result = Nullifier::from_field_elements(&empty_elements);

        assert!(recovered_nullifier_result.is_err());
        assert_eq!(
            recovered_nullifier_result.unwrap_err().to_string(),
            "Expected 4 field elements for Nullifier, got: 0"
        );
    }
}
