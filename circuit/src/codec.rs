use crate::circuit::F;

pub trait FieldElementCodec: Sized {
    fn to_field_elements(&self) -> Vec<F>;
    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self>;
}
