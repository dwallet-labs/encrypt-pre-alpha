// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::types::{FheOperation, FheType};

/// Metadata associated with a ciphertext, used in off-chain digest computation.
///
/// Kept here so the struct definition is shared across on-chain and off-chain
/// code. The actual `compute_ciphertext_digest` function lives in the
/// executor/SDK crate (requires Keccak-256).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CiphertextMetadata {
    pub fhe_type: FheType,
    pub level: u8,
    pub version: u8,
}

// ── Mock-mode helpers ──
//
// Mock layout (32 bytes):
//   bytes  0..16: zero (reserved + padding)
//   bytes 16..32: plaintext value as u128 big-endian

/// Bit-mask for the plaintext range of an [`FheType`] within a `u128`.
/// Types wider than 128 bits are clamped to `u128::MAX`.
fn type_bit_mask(fhe_type: FheType) -> u128 {
    match fhe_type {
        FheType::EBool => 1,
        FheType::EUint8 => u8::MAX as u128,
        FheType::EUint16 => u16::MAX as u128,
        FheType::EUint32 => u32::MAX as u128,
        FheType::EUint64 => u64::MAX as u128,
        _ => u128::MAX,
    }
}

/// Mock mode: encode a plaintext value into a 32-byte digest.
///
/// The value is masked to the type's bit width before encoding.
pub fn encode_mock_digest(fhe_type: FheType, plaintext: u128) -> [u8; 32] {
    let masked = plaintext & type_bit_mask(fhe_type);
    let mut result = [0u8; 32];
    result[16..32].copy_from_slice(&masked.to_be_bytes());
    result
}

/// Mock mode: extract the plaintext `u128` from a 32-byte digest.
pub fn decode_mock_identifier(identifier: &[u8; 32]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&identifier[16..32]);
    u128::from_be_bytes(bytes)
}

/// Mock mode: compute a binary FHE operation on two mock digests.
///
/// Supports all arithmetic, boolean, shift, and comparison operations.
/// Returns a zero digest for operations that are not binary.
pub fn mock_binary_compute(
    op: FheOperation,
    lhs: &[u8; 32],
    rhs: &[u8; 32],
    fhe_type: FheType,
) -> [u8; 32] {
    let a = decode_mock_identifier(lhs);
    let b = decode_mock_identifier(rhs);
    let result = mock_binary_compute_value(op, a, b, fhe_type);
    encode_mock_digest(fhe_type, result)
}

/// Mock mode: compute a binary FHE operation on plaintext values.
///
/// Returns the result value (not encoded as a digest).
pub fn mock_binary_compute_value(
    op: FheOperation,
    a: u128,
    b: u128,
    fhe_type: FheType,
) -> u128 {
    let mask = type_bit_mask(fhe_type);

    match op {
        FheOperation::Add | FheOperation::AddScalar => a.wrapping_add(b) & mask,
        FheOperation::Multiply | FheOperation::MultiplyScalar => a.wrapping_mul(b) & mask,
        FheOperation::Subtract | FheOperation::SubtractScalar => a.wrapping_sub(b) & mask,
        FheOperation::Divide | FheOperation::DivideScalar => {
            if b == 0 { 0 } else { (a / b) & mask }
        }
        FheOperation::Modulo | FheOperation::ModuloScalar => {
            if b == 0 { 0 } else { (a % b) & mask }
        }
        FheOperation::Min | FheOperation::MinScalar => if a < b { a } else { b },
        FheOperation::Max | FheOperation::MaxScalar => if a > b { a } else { b },
        FheOperation::Blend => a,
        FheOperation::Xor | FheOperation::XorScalar => (a ^ b) & mask,
        FheOperation::And | FheOperation::AndScalar => (a & b) & mask,
        FheOperation::Or | FheOperation::OrScalar => (a | b) & mask,
        FheOperation::Nor => (!(a | b)) & mask,
        FheOperation::Nand => (!(a & b)) & mask,
        FheOperation::ShiftLeft => {
            let bits = type_bit_count(fhe_type);
            if (b as usize) >= bits { 0 } else { a.wrapping_shl(b as u32) & mask }
        }
        FheOperation::ShiftRight => {
            let bits = type_bit_count(fhe_type);
            if (b as usize) >= bits { 0 } else { a.wrapping_shr(b as u32) & mask }
        }
        FheOperation::RotateLeft => rotate(a, b, fhe_type, true) & mask,
        FheOperation::RotateRight => rotate(a, b, fhe_type, false) & mask,
        FheOperation::IsLessThan | FheOperation::IsLessThanScalar => (a < b) as u128,
        FheOperation::IsEqual | FheOperation::IsEqualScalar => (a == b) as u128,
        FheOperation::IsNotEqual | FheOperation::IsNotEqualScalar => (a != b) as u128,
        FheOperation::IsGreaterThan | FheOperation::IsGreaterThanScalar => (a > b) as u128,
        FheOperation::IsGreaterOrEqual | FheOperation::IsGreaterOrEqualScalar => (a >= b) as u128,
        FheOperation::IsLessOrEqual | FheOperation::IsLessOrEqualScalar => (a <= b) as u128,
        _ => 0,
    }
}

/// Mock mode: compute a unary FHE operation on a plaintext value.
pub fn mock_unary_compute_value(op: FheOperation, a: u128, fhe_type: FheType) -> u128 {
    let mask = type_bit_mask(fhe_type);

    match op {
        FheOperation::Negate => a.wrapping_neg() & mask,
        FheOperation::Not => (!a) & mask,
        FheOperation::ToBoolean => if a != 0 { 1 } else { 0 },
        FheOperation::Bootstrap | FheOperation::ThinBootstrap => a & mask,
        FheOperation::ExtractLsbs => a & 1,
        FheOperation::ExtractMsbs => {
            let bits = type_bit_count(fhe_type);
            if bits == 0 { 0 } else { (a >> (bits - 1)) & 1 }
        }
        FheOperation::Into => a & mask,
        _ => 0,
    }
}

/// Mock mode: conditional select on plaintext values.
///
/// Returns `(result_value, result_fhe_type)`.
/// The fhe_type is assumed to be `EUint64` since select preserves the branch type.
pub fn mock_select_value(cond: u128, if_true: u128, if_false: u128) -> (u128, FheType) {
    let result = if cond != 0 { if_true } else { if_false };
    (result, FheType::EUint64)
}

/// Mock mode: compute a unary FHE operation on a mock digest.
pub fn mock_unary_compute(op: FheOperation, operand: &[u8; 32], fhe_type: FheType) -> [u8; 32] {
    let a = decode_mock_identifier(operand);
    encode_mock_digest(fhe_type, mock_unary_compute_value(op, a, fhe_type))
}

/// Mock mode: conditional select on mock digests.
pub fn mock_select(condition: &[u8; 32], if_true: &[u8; 32], if_false: &[u8; 32]) -> [u8; 32] {
    let cond = decode_mock_identifier(condition);
    if cond != 0 {
        *if_true
    } else {
        *if_false
    }
}

// ── Internal helpers ──

/// Effective bit count for rotation / shift bounds (clamped to 128).
fn type_bit_count(fhe_type: FheType) -> usize {
    let bytes = fhe_type.byte_width();
    let bits = bytes * 8;
    if bits > 128 {
        128
    } else {
        bits
    }
}

/// Rotate `value` left or right within the type's bit width.
fn rotate(value: u128, amount: u128, fhe_type: FheType, left: bool) -> u128 {
    let bits = type_bit_count(fhe_type) as u32;
    if bits == 0 {
        return value;
    }
    let shift = (amount as u32) % bits;
    if shift == 0 {
        return value;
    }
    if left {
        (value.wrapping_shl(shift)) | (value.wrapping_shr(bits - shift))
    } else {
        (value.wrapping_shr(shift)) | (value.wrapping_shl(bits - shift))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock encode / decode ──

    #[test]
    fn mock_encode_decode_round_trip() {
        let id = encode_mock_digest(FheType::EUint32, 42);
        assert_eq!(decode_mock_identifier(&id), 42);
    }

    #[test]
    fn mock_encode_reserves_bytes() {
        let id = encode_mock_digest(FheType::EUint64, 1);
        assert!(id[..16].iter().all(|&b| b == 0));
    }

    #[test]
    fn mock_encode_masks_type() {
        let id = encode_mock_digest(FheType::EUint8, 300);
        assert_eq!(decode_mock_identifier(&id), 44);
    }

    #[test]
    fn mock_encode_bool_masks() {
        assert_eq!(
            decode_mock_identifier(&encode_mock_digest(FheType::EBool, 5)),
            1
        );
        assert_eq!(
            decode_mock_identifier(&encode_mock_digest(FheType::EBool, 0)),
            0
        );
    }

    // ── Mock arithmetic ──

    #[test]
    fn mock_add() {
        let a = encode_mock_digest(FheType::EUint32, 10);
        let b = encode_mock_digest(FheType::EUint32, 32);
        let r = mock_binary_compute(FheOperation::Add, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 42);
    }

    #[test]
    fn mock_add_wrapping() {
        let a = encode_mock_digest(FheType::EUint8, 200);
        let b = encode_mock_digest(FheType::EUint8, 100);
        let r = mock_binary_compute(FheOperation::Add, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 44);
    }

    #[test]
    fn mock_multiply() {
        let a = encode_mock_digest(FheType::EUint32, 6);
        let b = encode_mock_digest(FheType::EUint32, 7);
        let r = mock_binary_compute(FheOperation::Multiply, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 42);
    }

    #[test]
    fn mock_subtract() {
        let a = encode_mock_digest(FheType::EUint32, 50);
        let b = encode_mock_digest(FheType::EUint32, 8);
        let r = mock_binary_compute(FheOperation::Subtract, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 42);
    }

    #[test]
    fn mock_divide() {
        let a = encode_mock_digest(FheType::EUint32, 84);
        let b = encode_mock_digest(FheType::EUint32, 2);
        let r = mock_binary_compute(FheOperation::Divide, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 42);
    }

    #[test]
    fn mock_divide_by_zero() {
        let a = encode_mock_digest(FheType::EUint32, 42);
        let b = encode_mock_digest(FheType::EUint32, 0);
        let r = mock_binary_compute(FheOperation::Divide, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 0);
    }

    #[test]
    fn mock_modulo() {
        let a = encode_mock_digest(FheType::EUint32, 47);
        let b = encode_mock_digest(FheType::EUint32, 5);
        let r = mock_binary_compute(FheOperation::Modulo, &a, &b, FheType::EUint32);
        assert_eq!(decode_mock_identifier(&r), 2);
    }

    #[test]
    fn mock_min_max() {
        let a = encode_mock_digest(FheType::EUint32, 10);
        let b = encode_mock_digest(FheType::EUint32, 20);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::Min,
                &a,
                &b,
                FheType::EUint32
            )),
            10
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::Max,
                &a,
                &b,
                FheType::EUint32
            )),
            20
        );
    }

    // ── Mock boolean ──

    #[test]
    fn mock_xor() {
        let a = encode_mock_digest(FheType::EUint8, 0b1100);
        let b = encode_mock_digest(FheType::EUint8, 0b1010);
        let r = mock_binary_compute(FheOperation::Xor, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 0b0110);
    }

    #[test]
    fn mock_and_or() {
        let a = encode_mock_digest(FheType::EUint8, 0b1100);
        let b = encode_mock_digest(FheType::EUint8, 0b1010);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::And,
                &a,
                &b,
                FheType::EUint8
            )),
            0b1000
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::Or,
                &a,
                &b,
                FheType::EUint8
            )),
            0b1110
        );
    }

    #[test]
    fn mock_nor_nand() {
        let a = encode_mock_digest(FheType::EUint8, 0b1100);
        let b = encode_mock_digest(FheType::EUint8, 0b1010);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::Nor,
                &a,
                &b,
                FheType::EUint8
            )),
            (!0b1110u128) & 0xFF
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::Nand,
                &a,
                &b,
                FheType::EUint8
            )),
            (!0b1000u128) & 0xFF
        );
    }

    // ── Mock shifts ──

    #[test]
    fn mock_shift_left() {
        let a = encode_mock_digest(FheType::EUint8, 1);
        let b = encode_mock_digest(FheType::EUint8, 4);
        let r = mock_binary_compute(FheOperation::ShiftLeft, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 16);
    }

    #[test]
    fn mock_shift_right() {
        let a = encode_mock_digest(FheType::EUint8, 128);
        let b = encode_mock_digest(FheType::EUint8, 3);
        let r = mock_binary_compute(FheOperation::ShiftRight, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 16);
    }

    #[test]
    fn mock_shift_overflow_zeros() {
        let a = encode_mock_digest(FheType::EUint8, 0xFF);
        let b = encode_mock_digest(FheType::EUint8, 8);
        let r = mock_binary_compute(FheOperation::ShiftLeft, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 0);
    }

    #[test]
    fn mock_rotate_left() {
        let a = encode_mock_digest(FheType::EUint8, 0b10000001);
        let b = encode_mock_digest(FheType::EUint8, 1);
        let r = mock_binary_compute(FheOperation::RotateLeft, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 0b00000011);
    }

    #[test]
    fn mock_rotate_right() {
        let a = encode_mock_digest(FheType::EUint8, 0b10000001);
        let b = encode_mock_digest(FheType::EUint8, 1);
        let r = mock_binary_compute(FheOperation::RotateRight, &a, &b, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 0b11000000);
    }

    // ── Mock comparisons ──

    #[test]
    fn mock_is_less_than() {
        let a = encode_mock_digest(FheType::EUint32, 5);
        let b = encode_mock_digest(FheType::EUint32, 10);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::IsLessThan,
                &a,
                &b,
                FheType::EUint32
            )),
            1
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::IsLessThan,
                &b,
                &a,
                FheType::EUint32
            )),
            0
        );
    }

    #[test]
    fn mock_is_equal() {
        let a = encode_mock_digest(FheType::EUint32, 42);
        let b = encode_mock_digest(FheType::EUint32, 42);
        let c = encode_mock_digest(FheType::EUint32, 43);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::IsEqual,
                &a,
                &b,
                FheType::EUint32
            )),
            1
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::IsEqual,
                &a,
                &c,
                FheType::EUint32
            )),
            0
        );
    }

    #[test]
    fn mock_all_comparison_ops() {
        let a = encode_mock_digest(FheType::EUint32, 10);
        let b = encode_mock_digest(FheType::EUint32, 20);
        let eq = encode_mock_digest(FheType::EUint32, 10);

        let check = |op, lhs: &[u8; 32], rhs: &[u8; 32]| -> u128 {
            decode_mock_identifier(&mock_binary_compute(op, lhs, rhs, FheType::EUint32))
        };

        assert_eq!(check(FheOperation::IsLessThan, &a, &b), 1);
        assert_eq!(check(FheOperation::IsGreaterThan, &a, &b), 0);
        assert_eq!(check(FheOperation::IsGreaterOrEqual, &a, &eq), 1);
        assert_eq!(check(FheOperation::IsLessOrEqual, &a, &eq), 1);
        assert_eq!(check(FheOperation::IsNotEqual, &a, &b), 1);
        assert_eq!(check(FheOperation::IsNotEqual, &a, &eq), 0);
    }

    #[test]
    fn mock_comparison_returns_0_or_1() {
        let a = encode_mock_digest(FheType::EUint64, 100);
        let b = encode_mock_digest(FheType::EUint64, 200);
        let r = mock_binary_compute(FheOperation::IsGreaterThan, &a, &b, FheType::EUint64);
        let val = decode_mock_identifier(&r);
        assert!(val == 0 || val == 1);
    }

    // ── Mock unary ──

    #[test]
    fn mock_negate() {
        let a = encode_mock_digest(FheType::EUint8, 1);
        let r = mock_unary_compute(FheOperation::Negate, &a, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 255);
    }

    #[test]
    fn mock_not() {
        let a = encode_mock_digest(FheType::EUint8, 0b10101010);
        let r = mock_unary_compute(FheOperation::Not, &a, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 0b01010101);
    }

    #[test]
    fn mock_to_boolean() {
        let nonzero = encode_mock_digest(FheType::EUint32, 42);
        let zero = encode_mock_digest(FheType::EUint32, 0);
        assert_eq!(
            decode_mock_identifier(&mock_unary_compute(
                FheOperation::ToBoolean,
                &nonzero,
                FheType::EUint32
            )),
            1
        );
        assert_eq!(
            decode_mock_identifier(&mock_unary_compute(
                FheOperation::ToBoolean,
                &zero,
                FheType::EUint32
            )),
            0
        );
    }

    #[test]
    fn mock_extract_lsbs() {
        let a = encode_mock_digest(FheType::EUint8, 0b10110101);
        let r = mock_unary_compute(FheOperation::ExtractLsbs, &a, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 1);
    }

    #[test]
    fn mock_extract_msbs() {
        let a = encode_mock_digest(FheType::EUint8, 0b10110101);
        let r = mock_unary_compute(FheOperation::ExtractMsbs, &a, FheType::EUint8);
        assert_eq!(decode_mock_identifier(&r), 1);
    }

    // ── Mock select ──

    #[test]
    fn mock_select_true() {
        let cond = encode_mock_digest(FheType::EBool, 1);
        let t = encode_mock_digest(FheType::EUint32, 100);
        let f = encode_mock_digest(FheType::EUint32, 200);
        let r = mock_select(&cond, &t, &f);
        assert_eq!(decode_mock_identifier(&r), 100);
    }

    #[test]
    fn mock_select_false() {
        let cond = encode_mock_digest(FheType::EBool, 0);
        let t = encode_mock_digest(FheType::EUint32, 100);
        let f = encode_mock_digest(FheType::EUint32, 200);
        let r = mock_select(&cond, &t, &f);
        assert_eq!(decode_mock_identifier(&r), 200);
    }

    // ── Scalar variants ──

    #[test]
    fn mock_scalar_ops() {
        let a = encode_mock_digest(FheType::EUint32, 10);
        let b = encode_mock_digest(FheType::EUint32, 5);
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::AddScalar,
                &a,
                &b,
                FheType::EUint32
            )),
            15
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::SubtractScalar,
                &a,
                &b,
                FheType::EUint32
            )),
            5
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::MultiplyScalar,
                &a,
                &b,
                FheType::EUint32
            )),
            50
        );
        assert_eq!(
            decode_mock_identifier(&mock_binary_compute(
                FheOperation::IsLessThanScalar,
                &a,
                &b,
                FheType::EUint32
            )),
            0
        );
    }

    // ── u128 / u64 types ──

    #[test]
    fn mock_u64_operations() {
        let a = encode_mock_digest(FheType::EUint64, u64::MAX as u128);
        let b = encode_mock_digest(FheType::EUint64, 1);
        let r = mock_binary_compute(FheOperation::Add, &a, &b, FheType::EUint64);
        assert_eq!(decode_mock_identifier(&r), 0);
    }

    #[test]
    fn mock_u128_large_values() {
        let big = u128::MAX / 2;
        let a = encode_mock_digest(FheType::EUint128, big);
        assert_eq!(decode_mock_identifier(&a), big);
    }
}
