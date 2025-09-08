use crate::storage_proof::{DEFAULT_ROOT_HASHES, TestInputs};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::utils::BytesDigest;

pub const DEFAULT_SECRETS: [&str; 2] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
];
pub const DEFAULT_TRANSFER_COUNTS: [u64; 2] = [4, 98];
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133, 181,
    154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
];
pub const DEFAULT_FUNDING_AMOUNTS: [u128; 2] = [
    u128::from_le_bytes([0, 16, 165, 212, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    3_000_000_000_000,
];
pub const DEFAULT_TO_ACCOUNTS: [[u8; 32]; 2] = [
    [
        162, 77, 187, 9, 249, 178, 185, 87, 194, 50, 198, 98, 179, 134, 179, 126, 123, 21, 247, 44,
        50, 216, 140, 243, 97, 177, 13, 94, 26, 255, 19, 170,
    ],
    [
        98, 181, 60, 135, 201, 171, 130, 47, 89, 74, 83, 165, 31, 102, 224, 231, 42, 230, 12, 3,
        90, 164, 151, 144, 89, 246, 227, 0, 72, 3, 177, 43,
    ],
];

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRETS[0].trim()).unwrap();
        let root_hash = hex::decode(DEFAULT_ROOT_HASHES[0].trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::from_preimage(&secret, DEFAULT_TRANSFER_COUNTS[0])
            .hash
            .into();
        let secret: [u8; 32] = secret.try_into().expect("Expected 32 bytes for secret");
        let unspendable_account = UnspendableAccount::from_secret(&secret).account_id.into();
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNTS[0],
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNTS, DEFAULT_TO_ACCOUNTS,
        DEFAULT_TRANSFER_COUNTS,
    };
    use wormhole_circuit::storage_proof::{ProcessedStorageProof, StorageProof, leaf::LeafInputs};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_ROOT_HASHES: [&str; 2] = [
        "5ffa2ab5b0db9883b22b1e5810932ea9d9eab1840730fd39ace71c26bb8d082d",
        "b77a6ff3b31c1e6c77a5078b605369e653e94a850a47be13d184fd6f7bece5ef",
    ];

    pub const DEFAULT_STORAGE_PROOF_A: [&str; 7] = [
        "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000805a0b660043743ecac1396810e2c3664e5f6bd54890cfc4eb04d914a38a32ba2000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
        "000000000000002004100000000000002000000000000000508b02bea5f6ec0560cb2cbfda44d44ee4ea671f5f3cbb5d27b90e6afcafa1f32000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000b5e25bb2727a369c7a991e657eb15e8a578a30b89088ba5cf5c588deaee3a9f5200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
        "000000000000002084000000000000002000000000000000c58635f106880ea6ac74b554a030a74e08587a15fe9cca1117415c1f086613e62000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e42000000000000000baf5a768ed92d1ac1cead4bcee891151641cfb6b109c9b6075952a36e5808dfc20000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
        "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a2000000000000000797b157cc18a8d60054cf9e008630ef8642b335fe0869a9796b5feb0f464ff4b",
        "3e0000000000003000e339aa4f999f6414fef6d1a1eae663e1cbc7ba7fe5fd365ea504b46241cddf0000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_B: [&str; 8] = [
        "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000ac6a84a91bbac6f4032f313867bad3934278d0a48577048b8d518449b523f6e42000000000000000a5d2b1dbcb9f9ff1ff5a45098e12a9df809321f01ead6a080bc4d964261ea2da200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000ce0ca8addb19134bcb10e995fdb9cc7bddf31d369b99e2d0c0a6f7a9ea8743f8200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb20000000000000006385950ee61b429626b43dde841f3f83954616ba547a49a618fb31ddd9b213d82000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000009e15f4976458fbee3d53572af38975d14d8fcddfe85eaf1331f32eafc186dbad",
        "000000000000002004100000000000002000000000000000c0abc936a675a27e502f5b140790f7a2d7b9ca4e68a631f2ba001dd6ca84aace2000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032800000000000002000000000000000d39670f2339789b1a1e5181d4b84088f1ad8aaf6d246f395205e9558d0d3229720000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b20000000000000007b70f539c4ae2eaed2875badc2de73e6febb8863c9ea7da92ee53b37565bfb652000000000000000450156a96af132f41fc3d7b50fc98bd68f02c3979ea5b71fe103a393550b69b4",
        "000000000000002084000000000000002000000000000000c6620c69e83c8d92a5742356fd64e8240209478ecc930145ad4e4f6e91e0cb5e200000000000000028eebda41303bbdd9f64f5a36e1ce338b6bacdaee99fb13ee344c067365459b3",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200ffff00000000000020000000000000004b88ce02ac1faba5b2fd624470a1c203c067f62de849f246e5039ce075e96cf22000000000000000e032dabc0f09448816726abb7f43ec45ec58f25599f5c2ba2e0dd5c49f12e2122000000000000000bd851a33bca19404ae47af9d6bcfb2189df8b56cc4e684f64820c9fae630f64f20000000000000009a56ffb735efe652461b349f58fb68e7792f20ff317ef50b9546c54750d4afe220000000000000007bca02ac7ad442b52521659481cb71150937d3a1b373812d93c42ba6f61d08b620000000000000001bb0a9f1463b2c4bd4f5fd931ff8b60582c2292e13b3bd6bf7137b747c4d047a2000000000000000214da76aa1acd14dfc7ac65578fbf91976a5a8cbcbaa11dcb9f5f7f00cfaf77e200000000000000040040912f654e112126648d3e4a84493366462f4c09ddc74a9ef015a23ca51f32000000000000000b1cb9bedade0d19f93ff5a589a02c97237ab688a2c169eeaff05c8487a595abf20000000000000002ae11224ba1283fdf9cbe452ae96a8ad0d11a1548d1ab78c6280dd352f78340120000000000000009ced4f70bb27fa9a3139877096890c18564cc07c898c8df1e642e8a26bf6b17d20000000000000009a55e008e99a91d3c46127b8eb8a20b8f5ba929d77609123f8c34d5c01bad5f220000000000000002eb7037b85ebc0785d624f6ea715873e5660cda1952be86e1e8bb7d4fa64895620000000000000007ca0c44a771641ec63db9247b1da22c8f71e85ed2c9ceefd62586b0c3d0324bf20000000000000008acbdc0d2caaf91c1b7e4c9b4a3622e67b567635dca84c45ec8f3b8affeae15a2000000000000000215d046226927d7e48fdbdbecdb8d7a6f40ac25b40c1b60cf42e340452a2ad30",
        "0000000000000020aa300000000000002000000000000000a32275e334089f36b9250a40fd7669e84ae704ad376a6dc5829790756632398320000000000000000ac8aa5f0b702b72f3a5bb23828d8ea8aa9534ce4a93e116e12f3a7ee53c979e2000000000000000cd491ea089d3fc273f536ed0444ee448a2e5a844c620953b7dae0a977be1da4f2000000000000000c0aa97c647e36ae9cfea24ead22a17aa4d0076fe5e98d8da3c88e373714271a1200000000000000094eb14a0f08d4705e1d0c647cef48a3abe9ca205d6e6dfbdd172220b2cef3e8c20000000000000005dad1fc1252b3886d4e118576149a3446db182ea07106d3f32633549f8b1fe6e",
        "000000000000002040800000000000002000000000000000654b53136e8d0a1420bae92c69c452dfcc753703c303bbfad279bfacb6e598c320000000000000007ef6c95f5ccf1ee1834e5c7123ee918d619b05e1f26e53d50f6cc5d34ca7c06b",
        "3d00000000000030000f8df093c358ebc61e80824fe5e0e498344ffca3e6c363cd951294cdcf89fa0000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_A: [usize; 7] = [768, 48, 240, 48, 160, 128, 16];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_B: [usize; 8] = [768, 48, 240, 48, 720, 288, 48, 16];

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF_A
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES_A.to_vec();
            Self::new(proof, indices).unwrap()
        }
    }

    impl TestInputs for LeafInputs {
        fn test_inputs() -> Self {
            let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = BytesDigest::try_from(DEFAULT_TO_ACCOUNTS[0]).unwrap();
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNTS[0],
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
        hex::decode(DEFAULT_ROOT_HASHES[0])
            .unwrap()
            .try_into()
            .unwrap()
    }
}

pub mod nullifier {
    use crate::DEFAULT_TRANSFER_COUNTS;

    use super::DEFAULT_SECRETS;
    use wormhole_circuit::nullifier::Nullifier;

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRETS[0]).unwrap();
            Self::from_preimage(secret.as_slice(), DEFAULT_TRANSFER_COUNTS[0])
        }
    }
}
