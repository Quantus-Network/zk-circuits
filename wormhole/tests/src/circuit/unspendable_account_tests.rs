use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::{
    codec::FieldElementCodec,
    unspendable_account::{UnspendableAccount, UnspendableAccountTargets},
};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

#[cfg(test)]
const SECRETS: [&str; 5] = [
    "cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229",
    "8b680b2421968a0c1d3cff6f3408e9d780157ae725724a78c3bc0998d1ac8194",
    "87f5fc11df0d12f332ccfeb92ddd8995e6c11709501a8b59c2aaf9eefee63ec1",
    "ef69da4e3aa2a6f15b3a9eec5e481f17260ac812faf1e685e450713327c3ab1c",
    "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7",
];

#[cfg(test)]
const ADDRESSES: [&str; 5] = [
    "c7334fbc8d75054ba3dd33b97db841c1031075ab9a26485fffe46bb519ccf25e",
    "f904e475a317a4f45541492d86ec79ef0b5f3ef3ff1a022db1c461f1ec7e623c",
    "e6060566ae1301253936d754ef21be71a02b00d59a40e265f25318f2359f7b3d",
    "49499c5d8a14b300b6ceb5459f31a7c2887b03dd5ebfef788abe067c7a84ab5f",
    "39fe23f1e26aa62001144e6b3250b753f5aabb4b5ecd5a86b8c4a7302744597e",
];

#[cfg(test)]
fn run_test(
    unspendable_account: &UnspendableAccount,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = UnspendableAccountTargets::new(&mut builder);
    UnspendableAccount::circuit(&targets, &mut builder);

    unspendable_account.fill_targets(&mut pw, targets)?;
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_unspendable_account_proof() {
    let unspendable_account = UnspendableAccount::default();
    run_test(&unspendable_account).unwrap();
}

#[test]
fn preimage_matches_right_address() {
    for (secret, address) in SECRETS.iter().zip(ADDRESSES) {
        let decoded_secret = hex::decode(secret).unwrap();
        let decoded_address = hex::decode(address).unwrap();
        let unspendable_account = UnspendableAccount::new(&decoded_secret);

        let address = zk_circuits_common::utils::bytes_to_felts(&decoded_address);
        assert_eq!(unspendable_account.account_id.to_vec(), address);
        let result = run_test(&unspendable_account);
        assert!(result.is_ok());
    }
}

#[test]
fn preimage_does_not_match_wrong_address() {
    let (secret, wrong_address) = (SECRETS[0], ADDRESSES[1]);
    let decoded_secret = hex::decode(secret).unwrap();
    let mut unspendable_account = UnspendableAccount::new(&decoded_secret);

    // Override the correct hash with the wrong one.
    let wrong_hash =
        zk_circuits_common::utils::bytes_to_felts(&hex::decode(wrong_address).unwrap());
    unspendable_account.account_id = wrong_hash.try_into().unwrap();

    let result = run_test(&unspendable_account);
    assert!(result.is_err());
}

#[test]
fn all_zero_preimage_is_valid_and_hashes() {
    let preimage_bytes = vec![0u8; 32];
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
        secret: vec![
            F::from_noncanonical_u64(5),
            F::from_noncanonical_u64(6),
            F::from_noncanonical_u64(7),
            F::from_noncanonical_u64(8),
        ],
    };

    // Encode the account as field elements and compare.
    let field_elements = account.to_field_elements();
    assert_eq!(field_elements.len(), 8);
    assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
    assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
    assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
    assert_eq!(field_elements[3], F::from_noncanonical_u64(4));
    assert_eq!(field_elements[4], F::from_noncanonical_u64(5));
    assert_eq!(field_elements[5], F::from_noncanonical_u64(6));
    assert_eq!(field_elements[6], F::from_noncanonical_u64(7));
    assert_eq!(field_elements[7], F::from_noncanonical_u64(8));

    // Decode the field elements back into an UnspendableAccount
    let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
    assert_eq!(account, recovered_account);
}
