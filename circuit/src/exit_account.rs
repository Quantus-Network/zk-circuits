use crate::circuit::{CircuitFragment, D, F};
use crate::inputs::CircuitInputs;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use crate::utils::slice_to_field_elements;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ExitAccount([u8; 32]);

impl ExitAccount {
    pub fn new(address: [u8; 32]) -> Self {
        Self(address)
    }

    /// Encode [u8; 32] into Vec<F> (4 field elements, 8 bytes each)
    pub fn to_field_elements(&self) -> Vec<F> {
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
    pub fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() < 4 {
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
    fn from(value: &CircuitInputs) -> Self {
        Self::new(value.exit_account)
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
}
