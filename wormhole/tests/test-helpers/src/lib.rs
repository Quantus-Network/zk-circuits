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
        "0000000000000020bfb500000000000020000000000000005512948e1970a2a12f7997d1577b42ed5f8fbdb4cb7628ca6d57531e5c528b7d2000000000000000edd59ebeff677ecfe1c8fafc95727021bae23b668b10d78f0543c6e864f2043520000000000000008b0dc630c1b426a9bebcdd0bca27eaf77180fceb880f91e553ac27d0c5c4592320000000000000001c8698032657950b1195fad5beac86f2111e366545a6601fe04617c4ce3cba4c20000000000000007d94ffd4c023b5a7d2066b32e18a5f3a8674f11f285082830ee3ec2a428d26542000000000000000e6bab3a9d2604f0d6c40b56677b32da888c908080f584a7839df7ee455dd071820000000000000003814bc915cb2813f424852ba8f517460984a87c6cb7659debc0aa160f26fa2922000000000000000afa80e2cf5f01ebffe4ff45cc7f4bb71b832841d8c09628a046acd851911b036200000000000000029d8efc9ae1c8e89e7690ab091aac5acf5df43523a4dde9ce2fc740b957e7ad2200000000000000086d1e418e7230995f28898fd6addcabda5c57cd8f121571816891fb8377039ba2000000000000000aa5945549d1edf8590c7e3eec578af18bd58d174d237c3c70079fd83e20072292000000000000000d37e1e43882c60139b26c547b675039261ee16415d2777482735658190a5dcac",
        "0000000000000020041000000000000020000000000000006753808959c4a62c30b8a4ad1ee28266fb7ec4e4455409400aea057a9b6f342820000000000000005cafbcda37d33f77f102307bdd12c70aa342e14a57133c26904102921cd98bdf",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032000000000000002000000000000000e4119913a3251ddde85ea4df732c503eac173d339257dfc80515eb4c2e3e63c220000000000000005dad18320f0d4f59a3b5766ad0df16416a59a1fb9ee26ecb1f26d4fc4489ab5820000000000000002295880108a64203a15959952cae3a27edbf5c94536f81615c5f704d82b4c3d7",
        "00000000000000208400000000000000200000000000000009bbf570b32563c66b298cfa81c6a2d5d098e409d69ab1d0b859494eacd1ccc12000000000000000f1ae51a1275b493eb28f397906abbb015d37c42ff0e5e681427ddad06094505f",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200040c000000000000200000000000000084287ede78cc23165cc753e73dbf709f0546b7518292fe89a9bc3d215b6a539720000000000000009bdcf0a2f6f45ba875d1d4dfc15c4e09ab02b739da2d72b5741708276a684e3a2000000000000000887cf6d628e06c1244e00d5c2577b2a832ee365e1e9433dc4309eebd9f25f3cf",
        "3f0000000000003004d3fe8902e1cfdb817fa7cc51db348c8899c9f21ff1babde9815cd57ade2ce50000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 5] = [768, 48, 240, 48, 240];

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES.to_vec();
            Self::new(proof, indices).unwrap()
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
