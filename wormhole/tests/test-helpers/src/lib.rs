use crate::storage_proof::{DEFAULT_ROOT_HASH, TestInputs};
use wormhole_circuit::{
    inputs::{BytesDigest, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};

pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_TRANSFER_COUNT: u64 = 0;
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    223, 23, 232, 59, 97, 108, 223, 113, 2, 89, 54, 39, 126, 65, 248, 106, 156, 219, 7, 123, 213,
    197, 228, 118, 177, 81, 61, 77, 23, 89, 200, 80,
];
pub const DEFAULT_FUNDING_AMOUNT: u128 =
    u128::from_le_bytes([0, 202, 154, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const DEFAULT_TO_ACCOUNT: [u8; 32] = [
    52, 254, 26, 185, 68, 221, 41, 114, 64, 157, 10, 31, 184, 69, 131, 12, 251, 91, 184, 107, 145,
    79, 182, 30, 173, 18, 214, 38, 123, 184, 36, 10,
];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET.trim()).unwrap();
        let root_hash = hex::decode(DEFAULT_ROOT_HASH.trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::from(DEFAULT_FUNDING_ACCOUNT);
        let nullifier = Nullifier::from_preimage(&secret, DEFAULT_TRANSFER_COUNT)
            .hash
            .into();
        let unspendable_account = UnspendableAccount::from_secret(&secret).account_id.into();
        let exit_account = BytesDigest::from(DEFAULT_TO_ACCOUNT);

        let storage_proof = ProcessedStorageProof::test_inputs();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNT,
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNT,
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNT, DEFAULT_TO_ACCOUNT, DEFAULT_TRANSFER_COUNT,
    };
    use wormhole_circuit::{
        inputs::BytesDigest,
        storage_proof::{ProcessedStorageProof, StorageProof, leaf::LeafInputs},
    };

    pub const DEFAULT_ROOT_HASH: &str =
        "61175128712fdcd548898e1c679b7c85613e723e95b0952561dc2fcce2d28c85";

    pub const DEFAULT_STORAGE_PROOF: [&str; 5] = [
        "0000000000000020ffb500000000000020000000000000005512948e1970a2a12f7997d1577b42ed5f8fbdb4cb7628ca6d57531e5c528b7d2000000000000000edd59ebeff677ecfe1c8fafc95727021bae23b668b10d78f0543c6e864f204352000000000000000c6c5c47a11ab79f7e12df8cb208839ba9c5c8b0cabd3b1a64a57242511a4db0420000000000000006e639e34a01ce58b095641eb95a84448806df1fa94841dd365f405a9e49c5f4220000000000000007d94ffd4c023b5a7d2066b32e18a5f3a8674f11f285082830ee3ec2a428d26542000000000000000e6bab3a9d2604f0d6c40b56677b32da888c908080f584a7839df7ee455dd0718200000000000000029c9e3b778e92b5808bf909fafa633f2209474c52772141aea1e2291b5bfd1992000000000000000f091ec227825c42634526d70555d2fc1e80e924bf6782ab1ab3cf8125b075e7f2000000000000000afa80e2cf5f01ebffe4ff45cc7f4bb71b832841d8c09628a046acd851911b036200000000000000029d8efc9ae1c8e89e7690ab091aac5acf5df43523a4dde9ce2fc740b957e7ad22000000000000000e8a3325aa80c4babbac4c33f33dae9348870db804d5559cd94c59e9079759c172000000000000000aa5945549d1edf8590c7e3eec578af18bd58d174d237c3c70079fd83e200722920000000000000004d62a86d38d0b89adef77255a984c6a1198412a4832acf97d6080680e1b294c3",
        "000000000000002004100000000000002000000000000000c05330711ede2009f1aaf5dd7f3d9a8e004840099cdb564c1bba98267e3202d920000000000000005cafbcda37d33f77f102307bdd12c70aa342e14a57133c26904102921cd98bdf",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f00308000000000000020000000000000005dad18320f0d4f59a3b5766ad0df16416a59a1fb9ee26ecb1f26d4fc4489ab582000000000000000a9ad3b1f88b2d0031ecb965969a1d075459d45ab0cafae88b831944caebbfc6d2000000000000000009658d905d4fa1092dcd907be8f437a601bb9d00ff17449a7c09451a1dd9daa",
        "00000000000000208400000000000000200000000000000098de61cf6807b70c5a6897c6724b261a62ad5cce7048378b0e212ca591566fef2000000000000000336dec865a03855d351a04cf742e2afcc00d52f8c49f455f3e4919a8056d3bdf",
        "5e0000000000003000857e7ea49e785c4e3e1f77a710cfc2418a2722a89abc7b79b7aa9b10e7996cd3da609c389a2866c0ed0574b9c8cea90000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 5] = [848, 48, 160, 48, 48];

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES.to_vec();
            Self::new(proof, indices).unwrap()
        }
    }

    impl TestInputs for LeafInputs {
        fn test_inputs() -> Self {
            let funding_account = BytesDigest::from(DEFAULT_FUNDING_ACCOUNT);
            let to_account = BytesDigest::from(DEFAULT_TO_ACCOUNT);
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNT,
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNT,
            )
            .unwrap()
        }
    }

    impl TestInputs for StorageProof {
        fn test_inputs() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs(),
                default_root_hash(),
                LeafInputs::test_inputs(),
            )
        }
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(DEFAULT_ROOT_HASH).unwrap().try_into().unwrap()
    }
}

pub mod nullifier {
    use crate::DEFAULT_TRANSFER_COUNT;

    use super::DEFAULT_SECRET;
    use wormhole_circuit::nullifier::Nullifier;

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::from_preimage(secret.as_slice(), DEFAULT_TRANSFER_COUNT)
        }
    }
}
