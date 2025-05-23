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
    account_id: Digest,
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

pub mod test_helpers {
    use super::{UnspendableAccount, UnspendableAccountInputs};

    /// An array of secrets generated from the Resonance Node with `./resonance-node key resonance --scheme wormhole`.
    pub const SECRETS: [&str; 5] = [
        "cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229",
        "8b680b2421968a0c1d3cff6f3408e9d780157ae725724a78c3bc0998d1ac8194",
        "87f5fc11df0d12f332ccfeb92ddd8995e6c11709501a8b59c2aaf9eefee63ec1",
        "ef69da4e3aa2a6f15b3a9eec5e481f17260ac812faf1e685e450713327c3ab1c",
        "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7",
    ];

    /// An array of addresses generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    #[allow(dead_code)]
    pub const ADDRESSES: [&str; 5] = [
        "c7334fbc8d75054ba3dd33b97db841c1031075ab9a26485fffe46bb519ccf25e",
        "f904e475a317a4f45541492d86ec79ef0b5f3ef3ff1a022db1c461f1ec7e623c",
        "e6060566ae1301253936d754ef21be71a02b00d59a40e265f25318f2359f7b3d",
        "49499c5d8a14b300b6ceb5459f31a7c2887b03dd5ebfef788abe067c7a84ab5f",
        "39fe23f1e26aa62001144e6b3250b753f5aabb4b5ecd5a86b8c4a7302744597e",
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

    use super::{
        test_helpers::{ADDRESSES, SECRETS},
        UnspendableAccount, UnspendableAccountInputs, UnspendableAccountTargets,
    };
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        CircuitFragment, C, D, F,
    };
    use crate::codec::FieldElementCodec;
    use crate::utils::bytes_to_felts;

    fn run_test(
        unspendable_account: &UnspendableAccount,
        inputs: UnspendableAccountInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness(false);
        let targets = UnspendableAccountTargets::new(&mut builder);
        UnspendableAccount::circuit(&targets, &mut builder);

        unspendable_account.fill_targets(&mut pw, targets, inputs)?;
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_unspendable_account_proof() {
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
            assert!(result.is_ok());
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
