use crate::storage_proof::{DEFAULT_ROOT_HASH, TestInputs};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    substrate_account::SubstrateAccount,
    unspendable_account::UnspendableAccount,
};

pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    223, 23, 232, 59, 97, 108, 223, 113, 2, 89, 54, 39, 126, 65, 248, 106, 156, 219, 7, 123, 213,
    197, 228, 118, 177, 81, 61, 77, 23, 89, 200, 80,
];
pub const DEFAULT_FUNDING_NONCE: u32 = 1;
pub const DEFAULT_FUNDING_AMOUNT: u128 =
    u128::from_le_bytes([0, 202, 154, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const DEFAULT_TO_ACCOUNT: [u8; 32] = [
    52, 254, 26, 185, 68, 221, 41, 114, 64, 157, 10, 31, 184, 69, 131, 12, 251, 91, 184, 107, 145,
    79, 182, 30, 173, 18, 214, 38, 123, 184, 36, 10,
];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET.trim()).unwrap();
        let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH.trim())
            .unwrap()
            .try_into()
            .unwrap();

        let funding_account = SubstrateAccount::new(&DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::new(&secret, DEFAULT_FUNDING_NONCE, &DEFAULT_FUNDING_ACCOUNT);
        let unspendable_account = UnspendableAccount::new(&secret);
        let exit_account = SubstrateAccount::new(&DEFAULT_TO_ACCOUNT).unwrap();
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
                funding_nonce: DEFAULT_FUNDING_NONCE,
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use wormhole_circuit::{
        storage_proof::{ProcessedStorageProof, StorageProof, leaf::LeafInputs},
        substrate_account::SubstrateAccount,
    };

    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNT, DEFAULT_FUNDING_NONCE, DEFAULT_TO_ACCOUNT,
    };

    pub const DEFAULT_ROOT_HASH: &str =
        "1e39dafda925a445da8b4fd82eb55e6cb186f813750dc547c77b45b64cc4b427";

    pub const DEFAULT_STORAGE_PROOF: [&str; 5] = [
        "0000000000000020bfb500000000000020000000000000005512948e1970a2a12f7997d1577b42ed5f8fbdb4cb7628ca6d57531e5c528b7d2000000000000000edd59ebeff677ecfe1c8fafc95727021bae23b668b10d78f0543c6e864f204352000000000000000c7f71105779c21e20022ad958ddc5710b48707de5e97c52e2cd53b3c1c65c40b200000000000000031abf41c315061571cb33e708e46ec6503a01fd53f42964540d9673a1acef73c20000000000000007d94ffd4c023b5a7d2066b32e18a5f3a8674f11f285082830ee3ec2a428d26542000000000000000e6bab3a9d2604f0d6c40b56677b32da888c908080f584a7839df7ee455dd071820000000000000006b1c040f655ad156d0d5804b48313c57b953a232173d5610cd6f471f370f35782000000000000000afa80e2cf5f01ebffe4ff45cc7f4bb71b832841d8c09628a046acd851911b036200000000000000029d8efc9ae1c8e89e7690ab091aac5acf5df43523a4dde9ce2fc740b957e7ad2200000000000000054ef16624cb91ff7813c518f1388024d99a2be830d6e564a074fbc164d1bc6e92000000000000000aa5945549d1edf8590c7e3eec578af18bd58d174d237c3c70079fd83e20072292000000000000000da955b9f78b1a6a1a2db2f8a81c2544677220344df609f2887e10d6f519f771a",
        "000000000000002004100000000000002000000000000000704eb94fbf543588121b972cab01301b1885187312985e0641ca8821baceae3320000000000000005cafbcda37d33f77f102307bdd12c70aa342e14a57133c26904102921cd98bdf",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f00320000000000000020000000000000006ea079a4162374bfebd0f3f5740da3d51c6e911ad32fe913452db43bd2d3157320000000000000005dad18320f0d4f59a3b5766ad0df16416a59a1fb9ee26ecb1f26d4fc4489ab5820000000000000003b44c2d33359933749b88130b7a3b168eb0c669701f03eb90b8bd4cf33bd1b11",
        "0000000000000020840000000000000020000000000000006aa4913b675da55a48a0efbee744955fe92165a6231086a7709c6e75078e56862000000000000000cb0d31d287d3e9bef71fed9101757ee24b31d0612ed4e3d27c2261dbd026dad6",
        "5e0000000000003000857e7ea49e785c4e3e1f77a710cfc2a9c5e38745047f31603f79b5a7c2d3ef6aef4dbf8dbe318fcb5610d474f374b70000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 5] = [768, 48, 240, 48, 48];

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
            let funding_account = SubstrateAccount::new(&DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = SubstrateAccount::new(&DEFAULT_TO_ACCOUNT).unwrap();
            LeafInputs::new(
                DEFAULT_FUNDING_NONCE,
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNT,
            )
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
    use wormhole_circuit::nullifier::Nullifier;

    use super::{DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_NONCE, DEFAULT_SECRET};

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::new(
                secret.as_slice(),
                DEFAULT_FUNDING_NONCE,
                &DEFAULT_FUNDING_ACCOUNT,
            )
        }
    }
}
