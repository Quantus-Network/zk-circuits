use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, Field64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::circuit::{Digest, F};

pub fn u128_to_felt(num: u128) -> Vec<F> {
    let mut amount_felts: Vec<F> = Vec::with_capacity(2);
    let amount_high = F::from_noncanonical_u64((num >> 64) as u64 % F::ORDER);
    let amount_low =  F::from_noncanonical_u64(num as u64 % F::ORDER);
    amount_felts.push(amount_high);
    amount_felts.push(amount_low);
    amount_felts
}

/// Converts a given slice into its field element representation.
pub fn slice_to_field_elements(input: &[u8]) -> Vec<F> {
    const BYTES_PER_ELEMENT: usize = 8;

    let mut field_elements: Vec<F> = Vec::new();
    for chunk in input.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u64::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value);
        field_elements.push(field_element);
    }

    field_elements
}

pub fn slice_to_digest(input: &[u8; 32]) -> Digest {
    // Split the 32 bytes into four 8-byte chunks
    let mut result = [F::ZERO; 4];
    for i in 0..4 {
        // Take 8 bytes at a time (little-endian)
        let chunk = &input[i * 8..(i + 1) * 8];
        // Convert 8 bytes to u64 (little-endian)
        let value = u64::from_le_bytes(chunk.try_into().expect("Slice length is 8"));
        // Convert u64 to field element
        result[i] = F::from_noncanonical_u64(value);
    }
    result
}

// Function to encode a string into a single field element
pub fn string_to_felt(
    input: &str,
) -> F {
    // Convert string to UTF-8 bytes
    let bytes = input.as_bytes();

    let mut arr = [0u8; 8];
    arr[..bytes.len()].copy_from_slice(bytes);

    let num = u64::from_le_bytes(arr);
    F::from_noncanonical_u64(num)
}
