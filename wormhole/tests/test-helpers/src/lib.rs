use crate::storage_proof::{DEFAULT_ROOT_HASH, TestInputs, default_storage_proof};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    substrate_account::SubstrateAccount,
    unspendable_account::UnspendableAccount,
};

pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_FUNDING_NONCE: u32 = 0;
pub const DEFAULT_FUNDING_ACCOUNT: &[u8] = &[10u8; 32];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET.trim()).unwrap();
        let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH.trim())
            .unwrap()
            .try_into()
            .unwrap();

        let funding_account = SubstrateAccount::new(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::new(&secret, DEFAULT_FUNDING_NONCE, DEFAULT_FUNDING_ACCOUNT);
        let unspendable_account = UnspendableAccount::new(&secret);
        let exit_account = SubstrateAccount::new(&[254u8; 32]).unwrap();
        let storage_proof = default_storage_proof();
        Self {
            public: PublicCircuitInputs {
                funding_amount: 0,
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                funding_nonce: 0,
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use wormhole_circuit::storage_proof::StorageProof;

    #[allow(dead_code)]
    pub const DEFAULT_FUNDING_AMOUNT: u128 = 1000;
    pub const DEFAULT_ROOT_HASH: &str =
        "77eb9d80cd12acfd902b459eb3b8876f05f31ef6a17ed5fdb060ee0e86dd8139";

    pub const DEFAULT_STORAGE_PROOF: [&str; 5] = [
        "0000000000000020bfb500000000000020000000000000005512948e1970a2a12f7997d1577b42ed5f8fbdb4cb7628ca6d57531e5c528b7d2000000000000000edd59ebeff677ecfe1c8fafc95727021bae23b668b10d78f0543c6e864f2043520000000000000006cc67a176173197066bb41e0a821f5f722c2cf289cdbfb9de84d96051f758a3520000000000000001c8698032657950b1195fad5beac86f2111e366545a6601fe04617c4ce3cba4c20000000000000007d94ffd4c023b5a7d2066b32e18a5f3a8674f11f285082830ee3ec2a428d26542000000000000000e6bab3a9d2604f0d6c40b56677b32da888c908080f584a7839df7ee455dd071820000000000000006c607e8932a22c07fc47015df09500659b39f99ca0bf70d63b43792b0d0b64542000000000000000afa80e2cf5f01ebffe4ff45cc7f4bb71b832841d8c09628a046acd851911b036200000000000000029d8efc9ae1c8e89e7690ab091aac5acf5df43523a4dde9ce2fc740b957e7ad2200000000000000039a2abe179ce3629e2ec92f1b90307f55f235c6234710d16204afe0edf952d452000000000000000aa5945549d1edf8590c7e3eec578af18bd58d174d237c3c70079fd83e200722920000000000000009b41a71b2d085cd3aa3664dc7b1c0dcb5ed4a237a08659af75b9b464efbd0554",
        "00000000000000200410000000000000200000000000000074ec2625fc6e2bd5267e2c93a982399632cfb42bc12e7b266e62bc368960a24120000000000000005cafbcda37d33f77f102307bdd12c70aa342e14a57133c26904102921cd98bdf",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f00320000000000000020000000000000007e62fa9f0ceadb450d57334a8270a3382462748a22a60cf37227a096f986d02220000000000000005dad18320f0d4f59a3b5766ad0df16416a59a1fb9ee26ecb1f26d4fc4489ab58200000000000000008818a991d0d2ff2d5c0d73da52d5934ae05c9f64b8e82bbdbea729afd529bde",
        "0000000000000020840000000000000020000000000000006aa4913b675da55a48a0efbee744955fe92165a6231086a7709c6e75078e568620000000000000002e10cad1f4881bc5eb128d4ea5521481f80620f5a933ea84460bbd8b221a3ed6",
        "5e0000000000003000857e7ea49e785c4e3e1f77a710cfc2a9c5e38745047f31603f79b5a7c2d3ef6aef4dbf8dbe318fcb5610d474f374b70000000000000000",
    ];

    // TODO: Proof hash indices.

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for StorageProof {
        fn test_inputs() -> Self {
            StorageProof::new(
                &default_storage_proof(),
                default_root_hash(),
                DEFAULT_FUNDING_AMOUNT,
            )
        }
    }

    pub fn default_storage_proof() -> Vec<Vec<u8>> {
        DEFAULT_STORAGE_PROOF
            .map(|node| hex::decode(node).unwrap())
            .to_vec()
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
                DEFAULT_FUNDING_ACCOUNT,
            )
        }
    }
}
