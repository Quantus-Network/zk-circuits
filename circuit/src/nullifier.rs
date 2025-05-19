use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{
    circuit::{field_elements_to_bytes, slice_to_field_elements, CircuitFragment, Digest, D, F},
    codec::FieldElementCodec,
};
use crate::{codec::ByteCodec, inputs::CircuitInputs};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nullifier {
    hash: Digest,
}

impl Nullifier {
    pub fn new(preimage: &[u8]) -> Self {
        let preimage = slice_to_field_elements(preimage);
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let hash = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { hash }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        field_elements_to_bytes(&self.hash)
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let hash = slice_to_field_elements(slice)
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
    preimage: Vec<Target>,
}

#[derive(Debug)]
pub struct NullifierInputs {
    preimage: Vec<F>,
}

impl NullifierInputs {
    pub fn new(preimage: &[u8]) -> Self {
        let preimage = slice_to_field_elements(preimage);
        Self { preimage }
    }
}

impl CircuitFragment for Nullifier {
    type PrivateInputs = NullifierInputs;
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let hash = builder.add_virtual_hash_public_input();
        let preimage = builder.add_virtual_targets(PREIMAGE_NUM_TARGETS);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);

        NullifierTargets { hash, preimage }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_target_arr(&targets.preimage, &inputs.preimage)?;

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::{Nullifier, NullifierInputs};

    pub const PREIMAGE: &str =
        "776f726d686f6c650908804f8983b91253f3b2e4d49b71afc8e2c707608d9ae456990fb21591037f";

    impl Default for Nullifier {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGE).unwrap();
            Self::new(&preimage)
        }
    }

    impl Default for NullifierInputs {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGE).unwrap();
            Self::new(&preimage)
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
    use crate::nullifier::test_helpers::PREIMAGE;

    use super::*;

    fn run_test(
        nullifier: &Nullifier,
        inputs: NullifierInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = Nullifier::circuit(&mut builder);

        nullifier.fill_targets(&mut pw, targets, inputs).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let nullifier = Nullifier::default();
        let inputs = NullifierInputs::default();
        run_test(&nullifier, inputs).unwrap();
    }

    #[test]
    fn invalid_preimage_fails_proof() {
        let valid_nullifier = Nullifier::default();

        // Flip the first byte of the preimage.
        let mut invalid_bytes = hex::decode(PREIMAGE).unwrap();
        invalid_bytes[0] ^= 0xFF;

        let bad_inputs = NullifierInputs::new(&invalid_bytes);

        let res = run_test(&valid_nullifier, bad_inputs);
        assert!(res.is_err(),);
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let nullifier = Nullifier::new(&preimage_bytes);
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
