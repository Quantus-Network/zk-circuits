use crate::storage_proof::{DEFAULT_ROOT_HASH, TestInputs};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
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
        let storage_proof = ProcessedStorageProof::test_inputs();
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
    use wormhole_circuit::storage_proof::{ProcessedStorageProof, StorageProof};

    #[allow(dead_code)]
    pub const DEFAULT_FUNDING_AMOUNT: u128 = 1000;
    pub const DEFAULT_ROOT_HASH: &str =
        "278fe2da00f88e3405610d3ec33b6753420ea133858e270996db564ac733f559";

    pub const DEFAULT_STORAGE_PROOF: [&str; 6] = [
        "00000000005512948e1970a2a12f7997d1577b42ed5f8fbdb4cb7628ca6d57531e5c528b7d2000000000000000edd59ebeff677ecfe1c8fafc95727021bae23b668b10d78f0543c6e864f204352000000000000000cafc2a6ae592be93ca8b62f4cf36d32f17a467ecb57fc03d298126dfde77965620000000000000001c8698032657950b1195fad5beac86f2111e366545a6601fe04617c4ce3cba4c20000000000000007d94ffd4c023b5a7d2066b32e18a5f3a8674f11f285082830ee3ec2a428d26542000000000000000e6bab3a9d2604f0d6c40b56677b32da888c908080f584a7839df7ee455dd0718200000000000000068fc6d502fa55a60efd7db04e9825cfca130233128d3ed1b73f19256f3df4ed02000000000000000afa80e2cf5f01ebffe4ff45cc7f4bb71b832841d8c09628a046acd851911b036200000000000000029d8efc9ae1c8e89e7690ab091aac5acf5df43523a4dde9ce2fc740b957e7ad220000000000000007c6a0b692213240cc03919a8fcdd1da30c407ff65ad5e9b94a23212d4bc63d7a2000000000000000aa5945549d1edf8590c7e3eec578af18bd58d174d237c3c70079fd83e200722920000000000000009a6d212131aa8b5c49ca84d598428d3cabac7267f08b0a9a57cc992c3ccfb8cf",
        "0000000000000020041000000000000020000000000000008871e77928e982db70e3ad0011ab05734d04dfae40e862cb3686e1a052d6608f20000000000000005cafbcda37d33f77f102307bdd12c70aa342e14a57133c26904102921cd98bdf",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032000000000000002000000000000000dad1ff4cc5f6765876675693861740b0710129a45edb4acf1fceb694db0c30d920000000000000005dad18320f0d4f59a3b5766ad0df16416a59a1fb9ee26ecb1f26d4fc4489ab5820000000000000005043ad59b21df3d6397127bc624909848dd62f59d4e35f9130c608d522090fe9",
        "0000000000000020840000000000000020000000000000003d5dfc7cfcd82d6b6f1ebe081b04ef7abf5fe42f30c9a043126a31ccb1b92aab2000000000000000764f75e8cf0d89026c7cdeb6fb52c7ee4ce93ddd7482e50183b5ed1e79ab0c56",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc2000404000000000000200000000000000084287ede78cc23165cc753e73dbf709f0546b7518292fe89a9bc3d215b6a539720000000000000009bdcf0a2f6f45ba875d1d4dfc15c4e09ab02b739da2d72b5741708276a684e3a",
        "3f000000000000300a489352a9979bafa22e19baf9d110b76cfbef6ff0b6a8580609db307c3cf3a70000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 5] = [768, 48, 240, 48, 240];

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES.to_vec();
            Self { proof, indices }
        }
    }

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for StorageProof {
        fn test_inputs() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs(),
                default_root_hash(),
                DEFAULT_FUNDING_AMOUNT,
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
                DEFAULT_FUNDING_ACCOUNT,
            )
        }
    }
}
