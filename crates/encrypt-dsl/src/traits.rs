// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::types::*;

// ── Core Traits ──

/// Arithmetic operations on encrypted values.
pub trait Arithmetic: Sized {
    fn add(&self, other: &Self) -> Self;
    fn multiply(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn subtract(&self, other: &Self) -> Self;
    fn divide(&self, other: &Self) -> Self;
    fn modulo(&self, other: &Self) -> Self;
    fn min(&self, other: &Self) -> Self;
    fn max(&self, other: &Self) -> Self;
    fn blend(&self, a: &Self, b: &Self) -> Self;
}

/// Boolean / bitwise operations.
pub trait Boolean: Sized {
    fn xor(&self, other: &Self) -> Self;
    fn and(&self, other: &Self) -> Self;
    fn not(&self) -> Self;
    fn or(&self, other: &Self) -> Self;
    fn nor(&self, other: &Self) -> Self;
    fn nand(&self, other: &Self) -> Self;
    fn shift_left(&self, n: &Self) -> Self;
    fn shift_right(&self, n: &Self) -> Self;
    fn rotate_left(&self, n: &Self) -> Self;
    fn rotate_right(&self, n: &Self) -> Self;
}

/// Comparison operations — return same type with 0/1 value.
pub trait Comparison: Sized {
    fn is_less_than(&self, other: &Self) -> Self;
    fn is_equal(&self, other: &Self) -> Self;
    fn is_not_equal(&self, other: &Self) -> Self;
    fn is_greater_than(&self, other: &Self) -> Self;
    fn is_greater_or_equal(&self, other: &Self) -> Self;
    fn is_less_or_equal(&self, other: &Self) -> Self;
}

/// Conditional select.
pub trait Conditional: Sized {
    fn select<V: Sized>(&self, if_true: &V, if_false: &V) -> V;
}

/// Conversion operations.
pub trait Conversion: Sized {
    fn to_boolean(&self) -> EBool;
    fn bootstrap(&self) -> Self;
    fn pack_into(&self) -> Self;
}

/// Vector-specific operations.
pub trait VectorOps: Sized {
    fn gather(&self, indices: &Self) -> Self;
    fn scatter(&self, indices: &Self) -> Self;
    fn assign(&self, indices: &Self, values: &Self) -> Self;
    fn copy(&self, src: &Self) -> Self;
    fn get(&self, indices: &Self) -> Self;
}

// ── Blanket impls for Encrypted<T> ──

macro_rules! panic_stub {
    () => {
        panic!("DSL trait called outside #[encrypt_fn_graph] / #[encrypt_fn]")
    };
}

impl<T: EncryptedType> Arithmetic for Encrypted<T> {
    fn add(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn multiply(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn negate(&self) -> Self {
        panic_stub!()
    }
    fn subtract(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn divide(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn modulo(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn min(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn max(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn blend(&self, _: &Self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<T: EncryptedType> Boolean for Encrypted<T> {
    fn xor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn and(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn not(&self) -> Self {
        panic_stub!()
    }
    fn or(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nand(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<T: EncryptedType> Comparison for Encrypted<T> {
    fn is_less_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_not_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_less_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl Conditional for Encrypted<Bool> {
    fn select<V: Sized>(&self, _: &V, _: &V) -> V {
        panic_stub!()
    }
}

impl<T: EncryptedType> Conversion for Encrypted<T> {
    fn to_boolean(&self) -> EBool {
        panic_stub!()
    }
    fn bootstrap(&self) -> Self {
        panic_stub!()
    }
    fn pack_into(&self) -> Self {
        panic_stub!()
    }
}

// ── Blanket impls for EncryptedVector<FHE_TYPE, T, SIZE> ──

impl<const F: u8, T: EncryptedType, const N: usize> Arithmetic for EncryptedVector<F, T, N> {
    fn add(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn multiply(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn negate(&self) -> Self {
        panic_stub!()
    }
    fn subtract(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn divide(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn modulo(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn min(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn max(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn blend(&self, _: &Self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<const F: u8, T: EncryptedType, const N: usize> Boolean for EncryptedVector<F, T, N> {
    fn xor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn and(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn not(&self) -> Self {
        panic_stub!()
    }
    fn or(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nand(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<const F: u8, T: EncryptedType, const N: usize> Comparison for EncryptedVector<F, T, N> {
    fn is_less_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_not_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_less_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<const F: u8, T: EncryptedType, const N: usize> Conversion for EncryptedVector<F, T, N> {
    fn to_boolean(&self) -> EBool {
        panic_stub!()
    }
    fn bootstrap(&self) -> Self {
        panic_stub!()
    }
    fn pack_into(&self) -> Self {
        panic_stub!()
    }
}

impl<const F: u8, T: EncryptedType, const N: usize> VectorOps for EncryptedVector<F, T, N> {
    fn gather(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn scatter(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn assign(&self, _: &Self, _: &Self) -> Self {
        panic_stub!()
    }
    fn copy(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn get(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

// ── Blanket impls for Plaintext<T, SIZE> ──
// Plaintext values participate in graph operations identically to encrypted values.
// The macro replaces the function body, so these stubs just satisfy the type checker.

impl<T: EncryptedType, const SIZE: usize> Arithmetic for Plaintext<T, SIZE> {
    fn add(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn multiply(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn negate(&self) -> Self {
        panic_stub!()
    }
    fn subtract(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn divide(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn modulo(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn min(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn max(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn blend(&self, _: &Self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<T: EncryptedType, const SIZE: usize> Boolean for Plaintext<T, SIZE> {
    fn xor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn and(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn not(&self) -> Self {
        panic_stub!()
    }
    fn or(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nor(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn nand(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn shift_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_left(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn rotate_right(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<T: EncryptedType, const SIZE: usize> Comparison for Plaintext<T, SIZE> {
    fn is_less_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_not_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_than(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_greater_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
    fn is_less_or_equal(&self, _: &Self) -> Self {
        panic_stub!()
    }
}

impl<T: EncryptedType, const SIZE: usize> Conversion for Plaintext<T, SIZE> {
    fn to_boolean(&self) -> EBool {
        panic_stub!()
    }
    fn bootstrap(&self) -> Self {
        panic_stub!()
    }
    fn pack_into(&self) -> Self {
        panic_stub!()
    }
}
