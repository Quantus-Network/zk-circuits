#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::circuit::F;
use plonky2::field::types::{Field, PrimeField64};

pub const FELTS_PER_U128: usize = 2;
pub type Digest = [F; 4];

pub fn u128_to_felts(num: u128) -> [F; FELTS_PER_U128] {
    let amount_high = F::from_noncanonical_u64((num >> 64) as u64);
    let amount_low = F::from_noncanonical_u64(num as u64);
    [amount_high, amount_low]
}

pub fn felts_to_u128(felts: [F; 2]) -> u128 {
    let amount_high: u128 = felts[0].0 as u128;
    let amount_low: u128 = felts[1].0 as u128;
    (amount_high << 64) | amount_low
}

// Encodes an 8-byte string into a single field element
pub fn string_to_felt(input: &str) -> F {
    // Convert string to UTF-8 bytes
    let bytes = input.as_bytes();

    let mut arr = [0u8; 8];
    arr[..bytes.len()].copy_from_slice(bytes);

    let num = u64::from_le_bytes(arr);
    F::from_noncanonical_u64(num)
}

/// Converts a given slice into its field element representation.
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
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

/// Converts a given field element slice into its byte representation.
pub fn felts_to_bytes(input: &[F]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    for field_element in input {
        let value = field_element.to_noncanonical_u64();
        let value_bytes = value.to_le_bytes();
        bytes.extend_from_slice(&value_bytes);
    }

    bytes
}
