use crate::circuit::{slice_to_field_elements, CircuitFragment, D, F};
use crate::fcodec::FieldElementCodec;
use crate::inputs::CircuitInputs;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ExitAccount(pub [u8; 32]);

impl ExitAccount {
    pub fn new(address: [u8; 32]) -> Self {
        Self(address)
    }
}

impl FieldElementCodec for ExitAccount {
    /// Encode [u8; 32] into Vec<F> (4 field elements, 8 bytes each)
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::with_capacity(4);
        for i in 0..4 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.0[i * 8..(i + 1) * 8]);
            let value = u64::from_le_bytes(bytes);
            elements.push(F::from_noncanonical_u64(value));
        }
        elements
    }

    /// Decode [u8; 32] from Vec<F> (expects 4 field elements)
    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for ExitAccount address"
            ));
        }
        let mut address = [0u8; 32];
        for i in 0..4 {
            let value = elements[i].to_noncanonical_u64();
            let bytes = value.to_le_bytes();
            address[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        Ok(ExitAccount::new(address))
    }
}

impl From<&CircuitInputs> for ExitAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(inputs.public.exit_account)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: HashOutTarget,
}

impl CircuitFragment for ExitAccount {
    type PrivateInputs = ();
    type Targets = ExitAccountTargets;

    /// Builds a dummy circuit to include the exit account as a public input.
    fn circuit(builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let address = builder.add_virtual_hash_public_input();
        ExitAccountTargets { address }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        _inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        let address = HashOut::from_partial(&slice_to_field_elements(&self.0));
        pw.set_hash_target(targets.address, address)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use plonky2::field::types::Field64;

    use super::*;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    fn run_test(exit_account: &ExitAccount) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = ExitAccount::circuit(&mut builder);

        exit_account.fill_targets(&mut pw, targets, ()).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn run_circuit() {
        let exit_account = ExitAccount::default();
        run_test(&exit_account).unwrap();
    }

    #[test]
    fn test_exit_account_round_trip() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([42u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        let decoded = ExitAccount::from_field_elements(&elements)?;
        assert_eq!(exit_account, decoded, "Round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_zero_address() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([0u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        assert_eq!(
            elements,
            vec![F::ZERO; 4],
            "Zero address should encode to zero elements"
        );
        let decoded = ExitAccount::from_field_elements(&elements)?;
        assert_eq!(exit_account, decoded, "Zero address round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_max_address() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([255u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        // Each element should be u64::MAX (0xFFFFFFFFFFFFFFFF)
        let expected_value = F::from_noncanonical_u64(u64::MAX);
        assert_eq!(
            elements,
            vec![expected_value; 4],
            "Max address encoding incorrect"
        );
        let decoded = ExitAccount::from_field_elements(&elements)?;
        assert_eq!(exit_account, decoded, "Max address round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_insufficient_elements() {
        let elements = vec![F::ZERO; 3]; // Too few elements
        let result = ExitAccount::from_field_elements(&elements);
        assert!(
            result.is_err(),
            "Decoding with insufficient elements should fail"
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "Expected 4 field elements for ExitAccount address"
        );
    }

    #[test]
    fn test_exit_account_specific_address() -> anyhow::Result<()> {
        let mut address = [0u8; 32];
        address[0] = 1;
        address[31] = 255; // Non-zero first and last bytes
        let exit_account = ExitAccount::new(address);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        // First element: 0x0000000000000001 (little-endian)
        // Last element: 0xFF00000000000000
        let expected_first = F::from_canonical_u64(1);
        let expected_last = F::from_canonical_u64((255u64 << 56) % F::ORDER);
        assert_eq!(elements[0], expected_first, "First element incorrect");
        assert_eq!(elements[3], expected_last, "Last element incorrect");
        let decoded = ExitAccount::from_field_elements(&elements)?;
        assert_eq!(exit_account, decoded, "Specific address round-trip failed");
        Ok(())
    }

    #[test]
    fn exit_account_codec() {
        let address_bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let account = ExitAccount::new(address_bytes);

        // Encode the account's address into field elements.
        let field_elements = account.to_field_elements();
        assert_eq!(field_elements.len(), 4);

        // Reconstruct the original bytes from the field elements.
        let mut expected_elements = Vec::new();
        for i in 0..4 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&address_bytes[i * 8..(i + 1) * 8]);
            let value = u64::from_le_bytes(bytes);
            expected_elements.push(F::from_noncanonical_u64(value));
        }
        assert_eq!(field_elements, expected_elements);

        // Decode the field elements back into an ExitAccount.
        let recovered_account = ExitAccount::from_field_elements(&field_elements).unwrap();
        assert_eq!(account, recovered_account);
    }

    #[test]
    fn codec_invalid_length() {
        let short_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
        let recovered_account_result = ExitAccount::from_field_elements(&short_elements);

        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for ExitAccount address"
        );

        let long_elements = vec![
            F::from_noncanonical_u64(1),
            F::from_noncanonical_u64(2),
            F::from_noncanonical_u64(3),
            F::from_noncanonical_u64(4),
            F::from_noncanonical_u64(5),
        ];

        let recovered_account_result = ExitAccount::from_field_elements(&long_elements);
        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for ExitAccount address"
        );
    }

    #[test]
    fn codec_empty_elements() {
        let empty_elements: Vec<F> = vec![];
        let recovered_account_result = ExitAccount::from_field_elements(&empty_elements);
        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for ExitAccount address"
        );
    }

    #[test]
    fn codec_different_byte_patterns() {
        // Test with all zeros.
        let zero_address = [0u8; 32];
        let account_zero = ExitAccount::new(zero_address);
        let field_elements_zero = account_zero.to_field_elements();
        let recovered_zero = ExitAccount::from_field_elements(&field_elements_zero).unwrap();
        assert_eq!(account_zero, recovered_zero);

        // Test with all ones.
        let one_address = [1u8; 32];
        let account_one = ExitAccount::new(one_address);
        let field_elements_one = account_one.to_field_elements();
        let recovered_one = ExitAccount::from_field_elements(&field_elements_one).unwrap();
        assert_eq!(account_one, recovered_one);

        // Test with a more varied pattern.
        let varied_address = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB,
            0xE1, 0xF0, 0x34, 0x56,
        ];
        let account_varied = ExitAccount::new(varied_address);
        let field_elements_varied = account_varied.to_field_elements();
        let recovered_varied = ExitAccount::from_field_elements(&field_elements_varied).unwrap();
        assert_eq!(account_varied, recovered_varied);
    }
}
