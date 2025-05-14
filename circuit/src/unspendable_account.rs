use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::circuit::{slice_to_field_elements, CircuitFragment, Digest, D, F};
use crate::inputs::CircuitInputs;

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;

pub type AccountId = Digest;

#[derive(Debug)]
pub struct UnspendableAccount {
    account_id: AccountId,
}

impl UnspendableAccount {
    pub fn new(preimage: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let preimage = slice_to_field_elements(preimage);

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let account_id = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { account_id }
    }
}

impl From<&CircuitInputs> for UnspendableAccount {
    fn from(value: &CircuitInputs) -> Self {
        Self::new(&value.unspendable_account_preimage)
    }
}

#[derive(Debug, Clone)]
pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    preimage: Vec<Target>,
}

#[derive(Debug)]
pub struct UnspendableAccountInputs {
    preimage: Vec<F>,
}

impl UnspendableAccountInputs {
    pub fn new(preimage: &[u8]) -> Self {
        let preimage = slice_to_field_elements(preimage);
        Self { preimage }
    }
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let account_id = builder.add_virtual_hash_public_input();
        let preimage = builder.add_virtual_targets(PREIMAGE_NUM_TARGETS);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);

        UnspendableAccountTargets {
            account_id,
            preimage,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        for (i, element) in inputs.preimage.into_iter().enumerate() {
            pw.set_target(targets.preimage[i], element)?;
        }

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::{UnspendableAccount, UnspendableAccountInputs};

    /// An array of preimages generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    pub const PREIMAGES: [&str; 5] = [
        "776f726d686f6c650908804f8983b91253f3b2e4d49b71afc8e2c707608d9ae456990fb21591037f",
        "776f726d686f6c65dc907058e510a6b2994569eead6bd4f91ad8b3b6052409a7bdddd9e704ba3192",
        "776f726d686f6c6563c2f38d8f60300633eb0322ce9638e4a3019d43bae1d5fd49da7270893d2c54",
        "776f726d686f6c6514f29ed6fa954a9fb82155cfb89d4531a8abc7b5dff92e98e1f1979a8a376bc8",
        "776f726d686f6c65858cfd1777d7e0374eb846e106df95d3d53f17c6e6db83674d2545d21fef4e11",
    ];

    /// An array of addresses generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    #[allow(dead_code)]
    pub const ADRESSES: [&str; 5] = [
        "7b434935e653afd2b20726488d155cd183114a3cc70fed3c120ef885a0e2145c",
        "c5ed765c4039d6e48fcf26c79165ee1d14d7bfcfa6e4ce6ac4352ab62e6f9cd5",
        "1e233db6f8797d35b34fcf5c419f77720a859492131803345f60f94ac3cd0964",
        "3842abc3876d47de27b2b0acb4da50ff13a3b24a08a5813afcb5135efaa5025a",
        "ecf980dda3fb801e29300dc86eece519f345b8e56edc0a9ae8c5598c82626ffa",
    ];

    impl Default for UnspendableAccount {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGES[0]).unwrap();
            Self::new(&preimage)
        }
    }

    impl Default for UnspendableAccountInputs {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGES[0]).unwrap();
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

    use super::{
        test_helpers::{ADRESSES, PREIMAGES},
        *,
    };

    fn run_test(
        unspendable_account: &UnspendableAccount,
        inputs: UnspendableAccountInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = UnspendableAccount::circuit(&mut builder);

        unspendable_account
            .fill_targets(&mut pw, targets, inputs)
            .unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let unspendable_account = UnspendableAccount::default();
        let inputs = UnspendableAccountInputs::default();
        run_test(&unspendable_account, inputs).unwrap();
    }

    #[test]
    fn preimage_matches_right_address() {
        for (preimage, address) in PREIMAGES.iter().zip(ADRESSES) {
            let decoded_preimage = hex::decode(preimage).unwrap();
            let unspendable_account = UnspendableAccount::new(&decoded_preimage);
            let inputs = UnspendableAccountInputs::new(&decoded_preimage);

            let address = slice_to_field_elements(&hex::decode(address).unwrap());
            assert_eq!(unspendable_account.account_id.to_vec(), address);

            run_test(&unspendable_account, inputs).unwrap();
        }
    }

    #[test]
    fn preimage_does_not_match_wrong_address() {
        let (preimage, wrong_address) = (PREIMAGES[0], ADRESSES[1]);
        let decoded_preimage = hex::decode(preimage).unwrap();
        let mut unspendable_account = UnspendableAccount::new(&decoded_preimage);

        // Override the correct hash with the wrong one.
        let wrong_hash = slice_to_field_elements(&hex::decode(wrong_address).unwrap());
        unspendable_account.account_id = wrong_hash.try_into().unwrap();

        let inputs = UnspendableAccountInputs::new(&decoded_preimage);

        let result = run_test(&unspendable_account, inputs);
        assert!(result.is_err());
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let account = UnspendableAccount::new(&preimage_bytes);
        assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
    }
}
