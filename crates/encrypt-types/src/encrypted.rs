// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Runtime `Encrypted<T>` handle types for on-chain storage.
//!
//! Each handle is an 8-byte ID stored directly in program accounts.
//! The phantom type parameter `T` carries the FHE type at compile time
//! while the runtime representation is always a u64 ID.

use core::marker::PhantomData;

/// Marker trait for FHE-capable scalar types.
///
/// Each marker carries its FHE type ID, plaintext byte width, and the
/// native Rust type that represents a decrypted value.
///
/// `from_plaintext_bytes` returns a zero-copy reference into account data.
/// This is safe on Solana because account data is 8-byte aligned.
pub trait EncryptedType: Sized + Clone + Copy {
    /// The FHE type discriminant (0–15 for scalars).
    const FHE_TYPE_ID: u8;
    /// The human-readable name (e.g., "EUint64").
    const TYPE_NAME: &'static str;
    /// Plaintext byte width (e.g., 8 for u64, 4 for u32, 1 for bool).
    const BYTE_WIDTH: usize;
    /// The native Rust type for the decrypted plaintext value.
    type DecryptedValue: ?Sized;

    /// Zero-copy reference to the decrypted plaintext value in account data.
    ///
    /// `bytes` must be exactly `BYTE_WIDTH` long and properly aligned
    /// (guaranteed by Solana runtime for account data).
    ///
    /// # Safety
    /// Caller must ensure `bytes` points into Solana account data (8-byte aligned).
    fn from_plaintext_bytes(bytes: &[u8]) -> &Self::DecryptedValue;
}

macro_rules! define_fhe_type_primitive {
    ($name:ident, $id:expr, $label:expr, $width:expr, $decrypted:ty) => {
        #[derive(Clone, Copy)]
        pub struct $name;
        impl EncryptedType for $name {
            const FHE_TYPE_ID: u8 = $id;
            const TYPE_NAME: &'static str = $label;
            const BYTE_WIDTH: usize = $width;
            type DecryptedValue = $decrypted;

            #[inline(always)]
            fn from_plaintext_bytes(bytes: &[u8]) -> &$decrypted {
                unsafe { &*(bytes.as_ptr() as *const $decrypted) }
            }
        }
    };
}

macro_rules! define_fhe_type_bytes {
    ($name:ident, $id:expr, $label:expr, $width:expr) => {
        #[derive(Clone, Copy)]
        pub struct $name;
        impl EncryptedType for $name {
            const FHE_TYPE_ID: u8 = $id;
            const TYPE_NAME: &'static str = $label;
            const BYTE_WIDTH: usize = $width;
            type DecryptedValue = [u8; $width];

            #[inline(always)]
            fn from_plaintext_bytes(bytes: &[u8]) -> &[u8; $width] {
                bytes.try_into().unwrap()
            }
        }
    };
}

// ── Scalar markers (0–15) ──
// Primitives (≤16 bytes): zero-copy pointer cast to &bool, &u8, ..., &u128.
// Large types (>16 bytes): zero-copy &[u8; N] reference.
define_fhe_type_primitive!(Bool, 0, "EBool", 1, bool);
define_fhe_type_primitive!(Uint8, 1, "EUint8", 1, u8);
define_fhe_type_primitive!(Uint16, 2, "EUint16", 2, u16);
define_fhe_type_primitive!(Uint32, 3, "EUint32", 4, u32);
define_fhe_type_primitive!(Uint64, 4, "EUint64", 8, u64);
define_fhe_type_primitive!(Uint128, 5, "EUint128", 16, u128);
define_fhe_type_bytes!(Uint256, 6, "EUint256", 32);
define_fhe_type_bytes!(Addr, 7, "EAddress", 32);
define_fhe_type_bytes!(Uint512, 8, "EUint512", 64);
define_fhe_type_bytes!(Uint1024, 9, "EUint1024", 128);
define_fhe_type_bytes!(Uint2048, 10, "EUint2048", 256);
define_fhe_type_bytes!(Uint4096, 11, "EUint4096", 512);
define_fhe_type_bytes!(Uint8192, 12, "EUint8192", 1024);
define_fhe_type_bytes!(Uint16384, 13, "EUint16384", 2048);
define_fhe_type_bytes!(Uint32768, 14, "EUint32768", 4096);
define_fhe_type_bytes!(Uint65536, 15, "EUint65536", 8192);

/// Trait for types that carry an FHE type ID at compile time.
/// Used by the `#[encrypt_fn]` macro for runtime type verification.
pub trait HasFheTypeId {
    const FHE_TYPE_ID: u8;
}

/// Runtime encrypted scalar handle — 32-byte on-chain representation.
///
/// Stores a client-provided 32-byte unique ID referencing an off-chain
/// ciphertext in the executor index. The phantom type `T` carries
/// the FHE type at compile time.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Encrypted<T: EncryptedType> {
    id: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: EncryptedType> Encrypted<T> {
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn set_id(&mut self, id: [u8; 32]) {
        self.id = id;
    }

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self {
            id: bytes,
            _marker: PhantomData,
        }
    }

    /// The plaintext byte width for this encrypted type.
    pub const fn byte_width() -> usize {
        T::BYTE_WIDTH
    }

    /// Zero-copy reference to the decrypted plaintext value.
    ///
    /// `plaintext_bytes` must be exactly `T::BYTE_WIDTH` long and
    /// point into Solana account data (8-byte aligned).
    ///
    /// ```ignore
    /// let result = accounts::decryption_result(request_data)?;
    /// let value: &u64 = my_euint64.read_decrypted(result);
    /// ```
    pub fn read_decrypted<'a>(&self, plaintext_bytes: &'a [u8]) -> &'a T::DecryptedValue {
        T::from_plaintext_bytes(plaintext_bytes)
    }
}

impl<T: EncryptedType> HasFheTypeId for Encrypted<T> {
    const FHE_TYPE_ID: u8 = T::FHE_TYPE_ID;
}

/// Zero-copy reference to a decrypted plaintext value for a given FHE type marker.
///
/// ```ignore
/// let value: &u64 = read_decrypted::<Uint64>(result_bytes);
/// ```
pub fn read_decrypted<'a, T: EncryptedType>(plaintext_bytes: &'a [u8]) -> &'a T::DecryptedValue {
    T::from_plaintext_bytes(plaintext_bytes)
}

/// Runtime encrypted vector handle — 32-byte on-chain representation.
///
/// - `FHE_TYPE`: The FHE type discriminant (16–31 for bit vectors, 32–44 for arithmetic vectors).
/// - `T`: The scalar element type (e.g., `Uint8` for arithmetic, `Bool` for bit vectors).
/// - `SIZE`: Number of elements in the vector.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct EncryptedVector<const FHE_TYPE: u8, T: EncryptedType, const SIZE: usize> {
    id: [u8; 32],
    _marker: PhantomData<T>,
}

impl<const FHE_TYPE: u8, T: EncryptedType, const SIZE: usize> EncryptedVector<FHE_TYPE, T, SIZE> {
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn set_id(&mut self, id: [u8; 32]) {
        self.id = id;
    }

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self {
            id: bytes,
            _marker: PhantomData,
        }
    }
}

/// Runtime plaintext value — holds raw bytes for a plaintext FHE input.
///
/// - `T`: The scalar element type (same marker as the corresponding `Encrypted<T>`).
/// - `SIZE`: Byte width of the plaintext data.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Plaintext<T: EncryptedType, const SIZE: usize> {
    data: [u8; SIZE],
    _marker: PhantomData<T>,
}

impl<T: EncryptedType, const SIZE: usize> Plaintext<T, SIZE> {
    pub fn new(data: [u8; SIZE]) -> Self {
        Self {
            data,
            _marker: PhantomData,
        }
    }

    pub fn from_le_bytes(data: [u8; SIZE]) -> Self {
        Self::new(data)
    }

    pub fn data(&self) -> &[u8; SIZE] {
        &self.data
    }
}

macro_rules! impl_plaintext_from {
    ($native:ty, $marker:ty, $size:literal) => {
        impl From<$native> for Plaintext<$marker, $size> {
            fn from(val: $native) -> Self {
                Self {
                    data: val.to_le_bytes(),
                    _marker: PhantomData,
                }
            }
        }
    };
}

impl From<bool> for Plaintext<Bool, 1> {
    fn from(val: bool) -> Self {
        Self {
            data: [val as u8],
            _marker: PhantomData,
        }
    }
}

impl_plaintext_from!(u8, Uint8, 1);
impl_plaintext_from!(u16, Uint16, 2);
impl_plaintext_from!(u32, Uint32, 4);
impl_plaintext_from!(u64, Uint64, 8);
impl_plaintext_from!(u128, Uint128, 16);

// ── Scalar type aliases ──
pub type EBool = Encrypted<Bool>;
pub type EUint8 = Encrypted<Uint8>;
pub type EUint16 = Encrypted<Uint16>;
pub type EUint32 = Encrypted<Uint32>;
pub type EUint64 = Encrypted<Uint64>;
pub type EUint128 = Encrypted<Uint128>;
pub type EUint256 = Encrypted<Uint256>;
pub type EAddress = Encrypted<Addr>;
pub type EUint512 = Encrypted<Uint512>;
pub type EUint1024 = Encrypted<Uint1024>;
pub type EUint2048 = Encrypted<Uint2048>;
pub type EUint4096 = Encrypted<Uint4096>;
pub type EUint8192 = Encrypted<Uint8192>;
pub type EUint16384 = Encrypted<Uint16384>;
pub type EUint32768 = Encrypted<Uint32768>;
pub type EUint65536 = Encrypted<Uint65536>;

// ── Bit vector type aliases (vectors of Bool, FHE IDs 16–31) ──
pub type E2BitVector = EncryptedVector<16, Bool, 2>;
pub type E4BitVector = EncryptedVector<17, Bool, 4>;
pub type E8BitVector = EncryptedVector<18, Bool, 8>;
pub type E16BitVector = EncryptedVector<19, Bool, 16>;
pub type E32BitVector = EncryptedVector<20, Bool, 32>;
pub type E64BitVector = EncryptedVector<21, Bool, 64>;
pub type E128BitVector = EncryptedVector<22, Bool, 128>;
pub type E256BitVector = EncryptedVector<23, Bool, 256>;
pub type E512BitVector = EncryptedVector<24, Bool, 512>;
pub type E1024BitVector = EncryptedVector<25, Bool, 1024>;
pub type E2048BitVector = EncryptedVector<26, Bool, 2048>;
pub type E4096BitVector = EncryptedVector<27, Bool, 4096>;
pub type E8192BitVector = EncryptedVector<28, Bool, 8192>;
pub type E16384BitVector = EncryptedVector<29, Bool, 16384>;
pub type E32768BitVector = EncryptedVector<30, Bool, 32768>;
pub type E65536BitVector = EncryptedVector<31, Bool, 65536>;

// ── Arithmetic vector type aliases (FHE IDs 32–44, all 8192 bytes total) ──
pub type EUint8Vector = EncryptedVector<32, Uint8, 8192>;
pub type EUint16Vector = EncryptedVector<33, Uint16, 4096>;
pub type EUint32Vector = EncryptedVector<34, Uint32, 2048>;
pub type EUint64Vector = EncryptedVector<35, Uint64, 1024>;
pub type EUint128Vector = EncryptedVector<36, Uint128, 512>;
pub type EUint256Vector = EncryptedVector<37, Uint256, 256>;
pub type EUint512Vector = EncryptedVector<38, Uint512, 128>;
pub type EUint1024Vector = EncryptedVector<39, Uint1024, 64>;
pub type EUint2048Vector = EncryptedVector<40, Uint2048, 32>;
pub type EUint4096Vector = EncryptedVector<41, Uint4096, 16>;
pub type EUint8192Vector = EncryptedVector<42, Uint8192, 8>;
pub type EUint16384Vector = EncryptedVector<43, Uint16384, 4>;
pub type EUint32768Vector = EncryptedVector<44, Uint32768, 2>;

// ── Plaintext scalar type aliases ──
pub type PBool = Plaintext<Bool, 1>;
pub type PUint8 = Plaintext<Uint8, 1>;
pub type PUint16 = Plaintext<Uint16, 2>;
pub type PUint32 = Plaintext<Uint32, 4>;
pub type PUint64 = Plaintext<Uint64, 8>;
pub type PUint128 = Plaintext<Uint128, 16>;
pub type PUint256 = Plaintext<Uint256, 32>;
pub type PAddress = Plaintext<Addr, 32>;
pub type PUint512 = Plaintext<Uint512, 64>;
pub type PUint1024 = Plaintext<Uint1024, 128>;
pub type PUint2048 = Plaintext<Uint2048, 256>;
pub type PUint4096 = Plaintext<Uint4096, 512>;
pub type PUint8192 = Plaintext<Uint8192, 1024>;
pub type PUint16384 = Plaintext<Uint16384, 2048>;
pub type PUint32768 = Plaintext<Uint32768, 4096>;
pub type PUint65536 = Plaintext<Uint65536, 8192>;

// ── Plaintext bit vector type aliases (SIZE = ceil(elements / 8)) ──
pub type P2BitVector = Plaintext<Bool, 1>;
pub type P4BitVector = Plaintext<Bool, 1>;
pub type P8BitVector = Plaintext<Bool, 1>;
pub type P16BitVector = Plaintext<Bool, 2>;
pub type P32BitVector = Plaintext<Bool, 4>;
pub type P64BitVector = Plaintext<Bool, 8>;
pub type P128BitVector = Plaintext<Bool, 16>;
pub type P256BitVector = Plaintext<Bool, 32>;
pub type P512BitVector = Plaintext<Bool, 64>;
pub type P1024BitVector = Plaintext<Bool, 128>;
pub type P2048BitVector = Plaintext<Bool, 256>;
pub type P4096BitVector = Plaintext<Bool, 512>;
pub type P8192BitVector = Plaintext<Bool, 1024>;
pub type P16384BitVector = Plaintext<Bool, 2048>;
pub type P32768BitVector = Plaintext<Bool, 4096>;
pub type P65536BitVector = Plaintext<Bool, 8192>;

// ── Plaintext arithmetic vector type aliases (SIZE = always 8192 bytes) ──
pub type PUint8Vector = Plaintext<Uint8, 8192>;
pub type PUint16Vector = Plaintext<Uint16, 8192>;
pub type PUint32Vector = Plaintext<Uint32, 8192>;
pub type PUint64Vector = Plaintext<Uint64, 8192>;
pub type PUint128Vector = Plaintext<Uint128, 8192>;
pub type PUint256Vector = Plaintext<Uint256, 8192>;
pub type PUint512Vector = Plaintext<Uint512, 8192>;
pub type PUint1024Vector = Plaintext<Uint1024, 8192>;
pub type PUint2048Vector = Plaintext<Uint2048, 8192>;
pub type PUint4096Vector = Plaintext<Uint4096, 8192>;
pub type PUint8192Vector = Plaintext<Uint8192, 8192>;
pub type PUint16384Vector = Plaintext<Uint16384, 8192>;
pub type PUint32768Vector = Plaintext<Uint32768, 8192>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_size_is_32_bytes() {
        assert_eq!(core::mem::size_of::<Encrypted<Uint64>>(), 32);
        assert_eq!(core::mem::size_of::<EUint32Vector>(), 32);
        assert_eq!(core::mem::size_of::<E8BitVector>(), 32);
    }

    #[test]
    fn encrypted_roundtrip() {
        let id = [42u8; 32];
        let e = Encrypted::<Uint64>::new(id);
        assert_eq!(*e.id(), id);
    }

    #[test]
    fn encrypted_from_le_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&12345u64.to_le_bytes());
        let e = Encrypted::<Uint32>::from_le_bytes(bytes);
        assert_eq!(*e.id(), bytes);
    }

    #[test]
    fn encrypted_set_id() {
        let mut e = Encrypted::<Bool>::new([0u8; 32]);
        let new_id = [0xAB; 32];
        e.set_id(new_id);
        assert_eq!(*e.id(), new_id);
    }

    #[test]
    fn marker_type_ids() {
        assert_eq!(Bool::FHE_TYPE_ID, 0);
        assert_eq!(Uint64::FHE_TYPE_ID, 4);
        assert_eq!(Addr::FHE_TYPE_ID, 7);
        assert_eq!(Uint32768::FHE_TYPE_ID, 14);
    }

    #[test]
    fn vector_types_share_scalar_marker() {
        let id = [1u8; 32];
        // Arithmetic vector uses same marker as scalar
        let _v: EncryptedVector<32, Uint8, 8192> = EncryptedVector::new(id);
        // Bit vector uses Bool marker
        let _b: EncryptedVector<18, Bool, 8> = EncryptedVector::new([2u8; 32]);
    }
}
