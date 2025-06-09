#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use zk_circuits_common::circuit::F;

pub trait FieldElementCodec: Sized {
    fn to_field_elements(&self) -> Vec<F>;
    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self>;
}

pub trait ByteCodec: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self>;
}
