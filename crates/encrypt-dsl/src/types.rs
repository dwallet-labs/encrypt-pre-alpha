// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Re-export scalar marker types and trait from encrypt-types (single source of truth).
// Only 16 scalar markers — vector/bitvec markers eliminated.
pub use encrypt_types::encrypted::{
    Addr, Bool, EncryptedType, Uint1024, Uint128, Uint16, Uint16384, Uint2048, Uint256, Uint32,
    Uint32768, Uint4096, Uint512, Uint64, Uint65536, Uint8, Uint8192,
};

use core::marker::PhantomData;

/// Compile-time encrypted scalar (graph node reference).
///
/// This is the DSL representation used during graph compilation.
/// Different from the on-chain `encrypt_types::encrypted::Encrypted<T>` (8-byte ID).
#[derive(Clone, Copy)]
pub struct Encrypted<T: EncryptedType> {
    #[allow(dead_code)]
    pub(crate) node_id: u16,
    pub(crate) _marker: PhantomData<T>,
}

/// Compile-time encrypted vector (graph node reference).
///
/// - `FHE_TYPE`: FHE type discriminant (16–31 for bit vectors, 32–44 for arithmetic).
/// - `T`: Scalar element type (e.g., `Uint8` for arithmetic, `Bool` for bit vectors).
/// - `SIZE`: Number of elements.
#[derive(Clone, Copy)]
pub struct EncryptedVector<const FHE_TYPE: u8, T: EncryptedType, const SIZE: usize> {
    #[allow(dead_code)]
    pub(crate) node_id: u16,
    pub(crate) _marker: PhantomData<T>,
}

// ── Developer-facing scalar type aliases ──
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

/// Compile-time plaintext value (graph node reference).
///
/// Used in `#[encrypt_fn_graph]` / `#[encrypt_fn]` parameters for runtime plaintext inputs.
/// The executor applies trivial encryption (`from()`) automatically.
#[derive(Clone, Copy)]
pub struct Plaintext<T: EncryptedType, const SIZE: usize> {
    #[allow(dead_code)]
    pub(crate) node_id: u16,
    pub(crate) _marker: PhantomData<T>,
}

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

// ── Plaintext bit vector type aliases ──
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

// ── Plaintext arithmetic vector type aliases ──
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
