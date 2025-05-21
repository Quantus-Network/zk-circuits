use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{codec::ByteCodec, inputs::CircuitInputs};
use crate::{
    circuit::{CircuitFragment, Digest, D, F},
    codec::FieldElementCodec,
};
use crate::utils::{felts_to_bytes, bytes_to_felts, string_to_felt};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;
pub const UNSPENDABLE_SALT: &str = "wormhole";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UnspendableAccount {
    account_id: Digest,
}

impl UnspendableAccount {
    pub fn new(secret: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let mut preimage = Vec::new();
        preimage.push(string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(bytes_to_felts(&secret));
        println!("preimage: {:?}", preimage);

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let inner_bytes = felts_to_bytes(&inner_hash);
        println!("inner_bytes: {:?}", inner_bytes);
        println!("inner_hash: {:?}", hex::encode(inner_bytes));
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
    secret: Vec<Target>,
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
    secret: Vec<F>,
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
        for (i, element) in inputs.secret.into_iter().enumerate() {
            pw.set_target(targets.secret[i], element)?;
        }

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::{UnspendableAccount, UnspendableAccountInputs};

    /// An array of secrets generated from the Resonance Node with `./resonance-node key resonance --scheme wormhole`.
    pub const SECRETS: [&str; 5] = [
        "cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229",
        "4d787f5685d9b0d5af1746441f7fdd5a6d189b5c257033f2509dda7754a4e381",
        "12c1f6b87e9fd64ed87e408a6beb4561aaa35114f0884e095470bc2d67be625e",
        "c109956a9e99d7927c75a28546c6b9ffcd71ddc868082b3c2828cf255a256f4e",
        "f27ae056a192551a2966c99e2b60976658221d78560a285dba0a3fe27871f86c",
    ];

    /// An array of addresses generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    #[allow(dead_code)]
    pub const ADDRESSES: [&str; 5] = [
        "c7334fbc8d75054ba3dd33b97db841c1031075ab9a26485fffe46bb519ccf25e",
        "75707beb4aa2afbeb9b8a283e562ad6378f66aa039c09b9dc99c8376a7f9ce46",
        "fdc010595da8653ff6629ad9a0ac5855080dc2b2cd94e70b8c68b24dfe5d28c2",
        "ffc1f415adb8f3b3489a1669cf7153a3f6ade3f58bb49debc0be99204409fb11",
        "2c7c2cb96e72f99d7e959d68b13e95017a3683e72cdd7db5809b780113edd117",
    ];

    impl Default for UnspendableAccount {
        fn default() -> Self {
            let preimage = hex::decode(SECRETS[0]).unwrap();
            Self::new(&preimage)
        }
    }

    impl Default for UnspendableAccountInputs {
        fn default() -> Self {
            let preimage = hex::decode(SECRETS[0]).unwrap();
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
        test_helpers::{ADDRESSES, SECRETS},
        *,
    };

    fn run_test(
        unspendable_account: &UnspendableAccount,
        inputs: UnspendableAccountInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = UnspendableAccountTargets::new(&mut builder);
        UnspendableAccount::circuit(&targets, &mut builder);

        unspendable_account
            .fill_targets(&mut pw, targets, inputs)?;
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
        for (secret, address) in SECRETS.iter().zip(ADDRESSES) {
            let decoded_secret = hex::decode(secret).unwrap();
            let decoded_address = hex::decode(address).unwrap();
            let unspendable_account = UnspendableAccount::new(&decoded_secret);
            let inputs = UnspendableAccountInputs::new(&decoded_secret);

            let address = bytes_to_felts(&decoded_address);
            assert_eq!(unspendable_account.account_id.to_vec(), address);

            let result = run_test(&unspendable_account, inputs);
            match result {
                Ok(_) => {},
                Err(e) => {
                    println!("run_test failed: {:?}", e);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn preimage_does_not_match_wrong_address() {
        let (secret, wrong_address) = (SECRETS[0], ADDRESSES[1]);
        let decoded_secret = hex::decode(secret).unwrap();
        let mut unspendable_account = UnspendableAccount::new(&decoded_secret);

        // Override the correct hash with the wrong one.
        let wrong_hash = bytes_to_felts(&hex::decode(wrong_address).unwrap());
        unspendable_account.account_id = wrong_hash.try_into().unwrap();

        let inputs = UnspendableAccountInputs::new(&decoded_secret);

        let result = run_test(&unspendable_account, inputs);
        assert!(result.is_err());
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let account = UnspendableAccount::new(&preimage_bytes);
        assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
    }

    #[test]
    fn unspendable_account_codec() {
        let account = UnspendableAccount {
            account_id: [
                F::from_noncanonical_u64(1),
                F::from_noncanonical_u64(2),
                F::from_noncanonical_u64(3),
                F::from_noncanonical_u64(4),
            ],
        };

        // Encode the account as field elements and compare.
        let field_elements = account.to_field_elements();
        assert_eq!(field_elements.len(), 4);
        assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
        assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
        assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
        assert_eq!(field_elements[3], F::from_noncanonical_u64(4));

        // Decode the field elements back into an UnspendableAccount
        let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
        assert_eq!(account, recovered_account);
    }

    #[test]
    fn codec_invalid_length() {
        let invalid_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
        let recovered_account_result = UnspendableAccount::from_field_elements(&invalid_elements);

        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for Unspendable Account, got: 2"
        );
    }

    #[test]
    fn codec_empty_elements() {
        let empty_elements: Vec<F> = vec![];
        let recovered_account_result = UnspendableAccount::from_field_elements(&empty_elements);

        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for Unspendable Account, got: 0"
        );
    }
}
