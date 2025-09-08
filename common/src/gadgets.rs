use alloc::vec::Vec;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

/// Compares a constant integer `left` with a variable `right` in a circuit, and returns whether
/// or not `left < right`.
///
/// # Returns
/// - `BoolTarget`: True if `left < right`, false otherwise.
pub fn is_const_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    right: Target,
    n_log: usize,
) -> BoolTarget {
    let right_bits = builder.split_le(right, n_log);
    let left_bits: Vec<bool> = (0..n_log).map(|i| ((left >> i) & 1) != 0).collect();

    let mut lt = builder._false();
    let mut eq = builder._true();

    for i in (0..n_log).rev() {
        let a = builder.constant_bool(left_bits[i]);
        let b = right_bits[i];

        let not_a = builder.not(a);
        let not_a_and_b = builder.and(not_a, b);
        let this_lt = builder.and(not_a_and_b, eq);
        lt = builder.or(lt, this_lt);

        let a_xor_b = xor(builder, a, b);
        let not_xor = builder.not(a_xor_b);
        eq = builder.and(eq, not_xor);
    }

    lt
}

/// Computes the XOR of two boolean values in a circuit.
///
/// The following mathematical expression is used:
///
/// ```text
/// a XOR b = a + b - 2ab
/// ```
///
/// # Returns
/// - `BoolTarget`: The value given by XORing `a` and `b`.
pub fn xor<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    b: BoolTarget,
) -> BoolTarget {
    let a_t = a.target;
    let b_t = b.target;
    let ab = builder.mul(a_t, b_t);
    let two_ab = builder.mul_const(F::from_canonical_u32(2), ab);
    let a_plus_b = builder.add(a_t, b_t);
    let xor = builder.sub(a_plus_b, two_ab);
    BoolTarget::new_unsafe(xor)
}

#[inline]
pub fn range32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
) {
    // Constrain x < 2^32
    b.range_check(x, 32);
}

#[inline]
pub fn bytes_digest_eq<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    a: [Target; 4],
    c: [Target; 4],
) -> BoolTarget {
    let e0 = b.sub(a[0], c[0]);
    let e1 = b.sub(a[1], c[1]);
    let e2 = b.sub(a[2], c[2]);
    let e3 = b.sub(a[3], c[3]);
    // add all equals
    let sum = b.add_many(&[e0, e1, e2, e3]);
    let zero = b.zero();
    b.is_equal(sum, zero)
}

/// a,b are 4x32-bit limbs little-endian (limb0 = least significant).
/// Returns (sum_limbs, overflow_top) with constraints:
///  - each limb < 2^32
///  - carry_i ∈ {0,1}
///  - top carry must be 0 (TODO: enforce error if not)
pub fn add_u128_base2_32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    a: [Target; 4],
    c: [Target; 4],
) -> ([Target; 4], BoolTarget) {
    // Ensure inputs are 32-bit limbs
    for limb in a.iter().chain(c.iter()) {
        range32(b, *limb);
    }

    let mut sum = [b.zero(); 4];
    // carry booleans
    let mut carry_prev = b._false();

    let two_32 = b.constant(F::from_canonical_u64(1u64 << 32));

    for i in 0..4 {
        // s_raw = a + c + carry_prev
        let s1 = b.add(a[i], c[i]);
        let carry_prev_fe = carry_prev.target;
        let s_raw = b.add(s1, carry_prev_fe);

        // Introduce carry_i ∈ {0,1} and sum_i < 2^32 such that:
        // s_raw = sum_i + carry_i * 2^32
        let carry_i = b.add_virtual_bool_target_safe();
        let carry_i_fe = carry_i.target;
        let shifted = b.mul(two_32, carry_i_fe);
        let sum_i = b.sub(s_raw, shifted);

        range32(b, sum_i);

        sum[i] = sum_i;
        carry_prev = carry_i;
    }

    (sum, carry_prev)
}

#[inline]
pub fn digest4<F: RichField + Extendable<D>, const D: usize>(
    v: &Vec<Target>,
    i: usize,
) -> [Target; 4] {
    [v[i], v[i + 1], v[i + 2], v[i + 3]]
}

#[inline]
pub fn is_nonzero_digest<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    d: [Target; 4],
) -> BoolTarget {
    let z = b.zero();
    let eq0 = b.is_equal(d[0], z);
    let nz0 = b.not(eq0);
    let eq1 = b.is_equal(d[1], z);
    let nz1 = b.not(eq1);
    let eq2 = b.is_equal(d[2], z);
    let nz2 = b.not(eq2);
    let eq3 = b.is_equal(d[3], z);
    let nz3 = b.not(eq3);
    // OR of all four: (((nz0 OR nz1) OR nz2) OR nz3)
    let t01 = b.or(nz0, nz1);
    let t012 = b.or(t01, nz2);
    b.or(t012, nz3)
}

#[inline]
pub fn is_nonzero_u32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
) -> BoolTarget {
    let zero = b.zero();
    let eq = b.is_equal(x, zero);
    b.not(eq)
}

/// Select between two digests elementwise by a BoolTarget.
#[inline]
pub fn select_digest<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    a: [Target; 4],
    c: [Target; 4],
) -> [Target; 4] {
    [
        b.select(cond, a[0], c[0]),
        b.select(cond, a[1], c[1]),
        b.select(cond, a[2], c[2]),
        b.select(cond, a[3], c[3]),
    ]
}
