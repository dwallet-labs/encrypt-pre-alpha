// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// FHE encrypted type identifiers.
///
/// 45 types total: 16 scalars + 16 boolean vectors + 13 arithmetic vectors.
/// All arithmetic vectors contain exactly 65,536 total bits (8,192 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum FheType {
    // ── Scalars (0–15) ──
    EBool = 0,
    EUint8 = 1,
    EUint16 = 2,
    EUint32 = 3,
    EUint64 = 4,
    EUint128 = 5,
    EUint256 = 6,
    EAddress = 7,
    EUint512 = 8,
    EUint1024 = 9,
    EUint2048 = 10,
    EUint4096 = 11,
    EUint8192 = 12,
    EUint16384 = 13,
    EUint32768 = 14,
    EUint65536 = 15,
    // ── Boolean vectors (16–31) ──
    EBitVector2 = 16,
    EBitVector4 = 17,
    EBitVector8 = 18,
    EBitVector16 = 19,
    EBitVector32 = 20,
    EBitVector64 = 21,
    EBitVector128 = 22,
    EBitVector256 = 23,
    EBitVector512 = 24,
    EBitVector1024 = 25,
    EBitVector2048 = 26,
    EBitVector4096 = 27,
    EBitVector8192 = 28,
    EBitVector16384 = 29,
    EBitVector32768 = 30,
    EBitVector65536 = 31,
    // ── Arithmetic vectors (32–44), each 8,192 bytes total ──
    EVectorU8 = 32,
    EVectorU16 = 33,
    EVectorU32 = 34,
    EVectorU64 = 35,
    EVectorU128 = 36,
    EVectorU256 = 37,
    EVectorU512 = 38,
    EVectorU1024 = 39,
    EVectorU2048 = 40,
    EVectorU4096 = 41,
    EVectorU8192 = 42,
    EVectorU16384 = 43,
    EVectorU32768 = 44,
}

impl FheType {
    /// Plaintext byte width of this type.
    ///
    /// - Scalars: `ceil(bits / 8)` (EBool = 1 byte).
    /// - Boolean vectors: `ceil(element_count / 8)`.
    /// - Arithmetic vectors: always 8,192 bytes (65,536 bits).
    pub fn byte_width(&self) -> usize {
        match self {
            // Scalars
            Self::EBool => 1,
            Self::EUint8 => 1,
            Self::EUint16 => 2,
            Self::EUint32 => 4,
            Self::EUint64 => 8,
            Self::EUint128 => 16,
            Self::EUint256 | Self::EAddress => 32,
            Self::EUint512 => 64,
            Self::EUint1024 => 128,
            Self::EUint2048 => 256,
            Self::EUint4096 => 512,
            Self::EUint8192 => 1024,
            Self::EUint16384 => 2048,
            Self::EUint32768 => 4096,
            Self::EUint65536 => 8192,
            // Boolean vectors: ceil(n / 8)
            Self::EBitVector2 | Self::EBitVector4 | Self::EBitVector8 => 1,
            Self::EBitVector16 => 2,
            Self::EBitVector32 => 4,
            Self::EBitVector64 => 8,
            Self::EBitVector128 => 16,
            Self::EBitVector256 => 32,
            Self::EBitVector512 => 64,
            Self::EBitVector1024 => 128,
            Self::EBitVector2048 => 256,
            Self::EBitVector4096 => 512,
            Self::EBitVector8192 => 1024,
            Self::EBitVector16384 => 2048,
            Self::EBitVector32768 => 4096,
            Self::EBitVector65536 => 8192,
            // Arithmetic vectors: all 8,192 bytes
            Self::EVectorU8
            | Self::EVectorU16
            | Self::EVectorU32
            | Self::EVectorU64
            | Self::EVectorU128
            | Self::EVectorU256
            | Self::EVectorU512
            | Self::EVectorU1024
            | Self::EVectorU2048
            | Self::EVectorU4096
            | Self::EVectorU8192
            | Self::EVectorU16384
            | Self::EVectorU32768 => 8192,
        }
    }

    /// Returns `true` for any vector type (boolean or arithmetic).
    pub fn is_vector(&self) -> bool {
        matches!(
            self,
            Self::EBitVector2 | Self::EBitVector4 | Self::EBitVector8
            | Self::EBitVector16 | Self::EBitVector32 | Self::EBitVector64
            | Self::EBitVector128 | Self::EBitVector256 | Self::EBitVector512
            | Self::EBitVector1024 | Self::EBitVector2048 | Self::EBitVector4096
            | Self::EBitVector8192 | Self::EBitVector16384 | Self::EBitVector32768
            | Self::EBitVector65536
            | Self::EVectorU8 | Self::EVectorU16 | Self::EVectorU32
            | Self::EVectorU64 | Self::EVectorU128 | Self::EVectorU256
            | Self::EVectorU512 | Self::EVectorU1024 | Self::EVectorU2048
            | Self::EVectorU4096 | Self::EVectorU8192 | Self::EVectorU16384
            | Self::EVectorU32768
        )
    }

    /// Returns `true` for arithmetic vectors (discriminants 32–44).
    pub fn is_arithmetic_vector(&self) -> bool {
        matches!(
            self,
            Self::EVectorU8 | Self::EVectorU16 | Self::EVectorU32
            | Self::EVectorU64 | Self::EVectorU128 | Self::EVectorU256
            | Self::EVectorU512 | Self::EVectorU1024 | Self::EVectorU2048
            | Self::EVectorU4096 | Self::EVectorU8192 | Self::EVectorU16384
            | Self::EVectorU32768
        )
    }

    /// Returns `true` for boolean vectors (discriminants 16–31).
    pub fn is_bit_vector(&self) -> bool {
        matches!(
            self,
            Self::EBitVector2 | Self::EBitVector4 | Self::EBitVector8
            | Self::EBitVector16 | Self::EBitVector32 | Self::EBitVector64
            | Self::EBitVector128 | Self::EBitVector256 | Self::EBitVector512
            | Self::EBitVector1024 | Self::EBitVector2048 | Self::EBitVector4096
            | Self::EBitVector8192 | Self::EBitVector16384 | Self::EBitVector32768
            | Self::EBitVector65536
        )
    }

    /// Map a vector type to its scalar element type.
    /// Scalars return themselves.
    pub fn scalar_element_type(&self) -> FheType {
        match self {
            Self::EVectorU8 => Self::EUint8,
            Self::EVectorU16 => Self::EUint16,
            Self::EVectorU32 => Self::EUint32,
            Self::EVectorU64 => Self::EUint64,
            Self::EVectorU128 => Self::EUint128,
            Self::EVectorU256 => Self::EUint256,
            Self::EVectorU512 => Self::EUint512,
            Self::EVectorU1024 => Self::EUint1024,
            Self::EVectorU2048 => Self::EUint2048,
            Self::EVectorU4096 => Self::EUint4096,
            Self::EVectorU8192 => Self::EUint8192,
            Self::EVectorU16384 => Self::EUint16384,
            Self::EVectorU32768 => Self::EUint32768,
            Self::EBitVector2 | Self::EBitVector4 | Self::EBitVector8
            | Self::EBitVector16 | Self::EBitVector32 | Self::EBitVector64
            | Self::EBitVector128 | Self::EBitVector256 | Self::EBitVector512
            | Self::EBitVector1024 | Self::EBitVector2048 | Self::EBitVector4096
            | Self::EBitVector8192 | Self::EBitVector16384 | Self::EBitVector32768
            | Self::EBitVector65536 => Self::EBool,
            other => *other,
        }
    }

    /// Byte width of a single element. For scalars, same as `byte_width()`.
    /// For arithmetic vectors, the element size (e.g., 4 for EVectorU32).
    /// For bit vectors, returns 1 (packed byte operations).
    pub fn element_byte_width(&self) -> usize {
        self.scalar_element_type().byte_width()
    }

    /// Number of elements. Scalars return 1.
    /// Arithmetic vectors: `8192 / element_byte_width()`.
    /// Bit vectors: the element count from the type name.
    pub fn element_count(&self) -> usize {
        if self.is_arithmetic_vector() {
            8192 / self.element_byte_width()
        } else if self.is_bit_vector() {
            match self {
                Self::EBitVector2 => 2,
                Self::EBitVector4 => 4,
                Self::EBitVector8 => 8,
                Self::EBitVector16 => 16,
                Self::EBitVector32 => 32,
                Self::EBitVector64 => 64,
                Self::EBitVector128 => 128,
                Self::EBitVector256 => 256,
                Self::EBitVector512 => 512,
                Self::EBitVector1024 => 1024,
                Self::EBitVector2048 => 2048,
                Self::EBitVector4096 => 4096,
                Self::EBitVector8192 => 8192,
                Self::EBitVector16384 => 16384,
                Self::EBitVector32768 => 32768,
                Self::EBitVector65536 => 65536,
                _ => unreachable!(),
            }
        } else {
            1
        }
    }

    /// Convert a raw discriminant to [`FheType`].
    /// Returns `None` for values outside `0..=44`.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::EBool),
            1 => Some(Self::EUint8),
            2 => Some(Self::EUint16),
            3 => Some(Self::EUint32),
            4 => Some(Self::EUint64),
            5 => Some(Self::EUint128),
            6 => Some(Self::EUint256),
            7 => Some(Self::EAddress),
            8 => Some(Self::EUint512),
            9 => Some(Self::EUint1024),
            10 => Some(Self::EUint2048),
            11 => Some(Self::EUint4096),
            12 => Some(Self::EUint8192),
            13 => Some(Self::EUint16384),
            14 => Some(Self::EUint32768),
            15 => Some(Self::EUint65536),
            16 => Some(Self::EBitVector2),
            17 => Some(Self::EBitVector4),
            18 => Some(Self::EBitVector8),
            19 => Some(Self::EBitVector16),
            20 => Some(Self::EBitVector32),
            21 => Some(Self::EBitVector64),
            22 => Some(Self::EBitVector128),
            23 => Some(Self::EBitVector256),
            24 => Some(Self::EBitVector512),
            25 => Some(Self::EBitVector1024),
            26 => Some(Self::EBitVector2048),
            27 => Some(Self::EBitVector4096),
            28 => Some(Self::EBitVector8192),
            29 => Some(Self::EBitVector16384),
            30 => Some(Self::EBitVector32768),
            31 => Some(Self::EBitVector65536),
            32 => Some(Self::EVectorU8),
            33 => Some(Self::EVectorU16),
            34 => Some(Self::EVectorU32),
            35 => Some(Self::EVectorU64),
            36 => Some(Self::EVectorU128),
            37 => Some(Self::EVectorU256),
            38 => Some(Self::EVectorU512),
            39 => Some(Self::EVectorU1024),
            40 => Some(Self::EVectorU2048),
            41 => Some(Self::EVectorU4096),
            42 => Some(Self::EVectorU8192),
            43 => Some(Self::EVectorU16384),
            44 => Some(Self::EVectorU32768),
            _ => None,
        }
    }
}

/// FHE operation identifiers.
///
/// Discriminant ranges: arithmetic 0–15, boolean 20–32, comparison 40–51,
/// conditional 60–61, random 70–71, conversion 80–86, cross-entry 90–99,
/// key management 100–104, reductions 110–114.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum FheOperation {
    // ── Arithmetic — Core ──
    Add = 0,
    Multiply = 1,
    // ── Arithmetic — Convenience ──
    Negate = 2,
    Subtract = 3,
    Divide = 4,
    Modulo = 5,
    Min = 6,
    Max = 7,
    Blend = 8,
    // ── Arithmetic scalar — Convenience ──
    AddScalar = 9,
    MultiplyScalar = 10,
    SubtractScalar = 11,
    DivideScalar = 12,
    ModuloScalar = 13,
    MinScalar = 14,
    MaxScalar = 15,
    // ── Boolean — Core ──
    Xor = 20,
    And = 21,
    // ── Boolean — Convenience ──
    Not = 22,
    Or = 23,
    Nor = 24,
    Nand = 25,
    ShiftLeft = 26,
    ShiftRight = 27,
    RotateLeft = 28,
    RotateRight = 29,
    // ── Boolean scalar — Convenience ──
    AndScalar = 30,
    OrScalar = 31,
    XorScalar = 32,
    // ── Comparison — Core (returns E with 0/1, not EBool) ──
    IsLessThan = 40,
    // ── Comparison — Convenience ──
    IsEqual = 41,
    IsNotEqual = 42,
    IsGreaterThan = 43,
    IsGreaterOrEqual = 44,
    IsLessOrEqual = 45,
    // ── Comparison scalar — Convenience ──
    IsLessThanScalar = 46,
    IsEqualScalar = 47,
    IsNotEqualScalar = 48,
    IsGreaterThanScalar = 49,
    IsGreaterOrEqualScalar = 50,
    IsLessOrEqualScalar = 51,
    // ── Conditional — Core ──
    Select = 60,
    // ── Conditional — Convenience ──
    SelectScalar = 61,
    // ── Random — Core ──
    Random = 70,
    RandomRange = 71,
    // ── Conversion — Core ──
    ExtractLsbs = 80,
    PackInto = 81,
    Into = 82,
    // ── Conversion — Convenience ──
    ToBoolean = 83,
    ExtractMsbs = 84,
    Bootstrap = 85,
    ThinBootstrap = 86,
    // ── Cross-Entry — Core ──
    Gather = 90,
    RotateEntries = 96,
    LinearTransform = 97,
    // ── Cross-Entry — Convenience ──
    Scatter = 91,
    Assign = 92,
    AssignScalars = 93,
    Copy = 94,
    Get = 95,
    LinearTransformPlaintext = 98,
    LinearTransformBand = 99,
    // ── Key Management — Core ──
    From = 100,
    Encrypt = 101,
    Decrypt = 102,
    KeySwitch = 103,
    ReEncrypt = 104,
    // ── Reductions — Core ──
    ReduceAdd = 110,
    // ── Reductions — Convenience ──
    ReduceMin = 111,
    ReduceMax = 112,
    ReduceAny = 113,
    ReduceAll = 114,
}

impl FheOperation {
    /// Returns `true` for comparison operations (discriminants 40–51).
    /// Comparisons return the same encrypted type with value 0 (false) or 1 (true).
    pub fn is_comparison(&self) -> bool {
        let d = *self as u8;
        (40..=51).contains(&d)
    }

    /// Returns `true` for operations that take exactly one ciphertext operand.
    pub fn is_unary(&self) -> bool {
        matches!(
            self,
            Self::Negate
                | Self::Not
                | Self::ExtractLsbs
                | Self::ExtractMsbs
                | Self::Into
                | Self::ToBoolean
                | Self::Bootstrap
                | Self::ThinBootstrap
                | Self::ReduceAdd
                | Self::ReduceMin
                | Self::ReduceMax
                | Self::ReduceAny
                | Self::ReduceAll
        )
    }

    /// Returns `true` for reduction operations (discriminants 110–114).
    pub fn is_reduction(&self) -> bool {
        let d = *self as u8;
        (110..=114).contains(&d)
    }

    /// Infer the result [`FheType`] from the input type.
    ///
    /// Most operations preserve the input type.
    /// `ToBoolean` always returns `EBool`.
    /// `ReduceAdd/Min/Max` collapse a vector to its scalar element type.
    /// `ReduceAny/All` always return `EBool`.
    /// Operations like `Into` depend on an external target type; this method
    /// returns `input_type` as a conservative default.
    pub fn result_type(&self, input_type: FheType) -> FheType {
        match self {
            Self::ToBoolean | Self::ReduceAny | Self::ReduceAll => FheType::EBool,
            Self::ReduceAdd | Self::ReduceMin | Self::ReduceMax => {
                input_type.scalar_element_type()
            }
            _ => input_type,
        }
    }
}

/// Status of a decryption or seal request.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum DecryptionStatus {
    Pending = 0,
    Completed = 1,
    Failed = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_round_trip() {
        for v in 0..=44u8 {
            let t = FheType::from_u8(v).expect("valid discriminant");
            assert_eq!(t as u8, v);
        }
        assert!(FheType::from_u8(45).is_none());
        assert!(FheType::from_u8(255).is_none());
    }

    #[test]
    fn byte_width_scalars() {
        assert_eq!(FheType::EBool.byte_width(), 1);
        assert_eq!(FheType::EUint8.byte_width(), 1);
        assert_eq!(FheType::EUint16.byte_width(), 2);
        assert_eq!(FheType::EUint32.byte_width(), 4);
        assert_eq!(FheType::EUint64.byte_width(), 8);
        assert_eq!(FheType::EUint128.byte_width(), 16);
        assert_eq!(FheType::EUint256.byte_width(), 32);
        assert_eq!(FheType::EAddress.byte_width(), 32);
        assert_eq!(FheType::EUint512.byte_width(), 64);
        assert_eq!(FheType::EUint65536.byte_width(), 8192);
    }

    #[test]
    fn byte_width_arithmetic_vectors_all_8192() {
        let arith_vectors = [
            FheType::EVectorU8,
            FheType::EVectorU16,
            FheType::EVectorU32,
            FheType::EVectorU64,
            FheType::EVectorU128,
            FheType::EVectorU256,
            FheType::EVectorU512,
            FheType::EVectorU1024,
            FheType::EVectorU2048,
            FheType::EVectorU4096,
            FheType::EVectorU8192,
            FheType::EVectorU16384,
            FheType::EVectorU32768,
        ];
        for t in arith_vectors {
            assert_eq!(t.byte_width(), 8192, "failed for {:?}", t);
        }
    }

    #[test]
    fn byte_width_bool_vectors() {
        assert_eq!(FheType::EBitVector2.byte_width(), 1);
        assert_eq!(FheType::EBitVector8.byte_width(), 1);
        assert_eq!(FheType::EBitVector16.byte_width(), 2);
        assert_eq!(FheType::EBitVector256.byte_width(), 32);
        assert_eq!(FheType::EBitVector65536.byte_width(), 8192);
    }

    #[test]
    fn is_comparison() {
        assert!(FheOperation::IsLessThan.is_comparison());
        assert!(FheOperation::IsEqual.is_comparison());
        assert!(FheOperation::IsLessOrEqualScalar.is_comparison());
        assert!(!FheOperation::Add.is_comparison());
        assert!(!FheOperation::Select.is_comparison());
    }

    #[test]
    fn is_unary() {
        assert!(FheOperation::Negate.is_unary());
        assert!(FheOperation::Not.is_unary());
        assert!(FheOperation::ToBoolean.is_unary());
        assert!(FheOperation::Bootstrap.is_unary());
        assert!(FheOperation::ReduceAdd.is_unary());
        assert!(FheOperation::ReduceAny.is_unary());
        assert!(!FheOperation::Add.is_unary());
        assert!(!FheOperation::Select.is_unary());
        assert!(!FheOperation::RotateEntries.is_unary());
    }

    #[test]
    fn is_reduction() {
        assert!(FheOperation::ReduceAdd.is_reduction());
        assert!(FheOperation::ReduceMin.is_reduction());
        assert!(FheOperation::ReduceAll.is_reduction());
        assert!(!FheOperation::Add.is_reduction());
        assert!(!FheOperation::Gather.is_reduction());
    }

    #[test]
    fn result_type_preserves_input() {
        assert_eq!(
            FheOperation::Add.result_type(FheType::EUint32),
            FheType::EUint32
        );
        assert_eq!(
            FheOperation::IsEqual.result_type(FheType::EUint64),
            FheType::EUint64
        );
        assert_eq!(
            FheOperation::RotateEntries.result_type(FheType::EVectorU64),
            FheType::EVectorU64
        );
    }

    #[test]
    fn result_type_to_boolean() {
        assert_eq!(
            FheOperation::ToBoolean.result_type(FheType::EUint128),
            FheType::EBool
        );
    }

    #[test]
    fn result_type_reductions() {
        assert_eq!(
            FheOperation::ReduceAdd.result_type(FheType::EVectorU32),
            FheType::EUint32
        );
        assert_eq!(
            FheOperation::ReduceMin.result_type(FheType::EVectorU64),
            FheType::EUint64
        );
        assert_eq!(
            FheOperation::ReduceAny.result_type(FheType::EVectorU32),
            FheType::EBool
        );
        assert_eq!(
            FheOperation::ReduceAll.result_type(FheType::EBitVector256),
            FheType::EBool
        );
    }

    #[test]
    fn is_vector_types() {
        assert!(!FheType::EBool.is_vector());
        assert!(!FheType::EUint64.is_vector());
        assert!(!FheType::EUint65536.is_vector());
        assert!(FheType::EBitVector2.is_vector());
        assert!(FheType::EBitVector65536.is_vector());
        assert!(FheType::EVectorU32.is_vector());
        assert!(FheType::EVectorU32768.is_vector());
    }

    #[test]
    fn is_arithmetic_vector_types() {
        assert!(!FheType::EUint64.is_arithmetic_vector());
        assert!(!FheType::EBitVector32.is_arithmetic_vector());
        assert!(FheType::EVectorU8.is_arithmetic_vector());
        assert!(FheType::EVectorU32.is_arithmetic_vector());
        assert!(FheType::EVectorU32768.is_arithmetic_vector());
    }

    #[test]
    fn scalar_element_type_mapping() {
        assert_eq!(FheType::EVectorU32.scalar_element_type(), FheType::EUint32);
        assert_eq!(FheType::EVectorU64.scalar_element_type(), FheType::EUint64);
        assert_eq!(FheType::EVectorU128.scalar_element_type(), FheType::EUint128);
        assert_eq!(FheType::EBitVector256.scalar_element_type(), FheType::EBool);
        assert_eq!(FheType::EUint64.scalar_element_type(), FheType::EUint64);
    }

    #[test]
    fn element_byte_width_values() {
        assert_eq!(FheType::EVectorU8.element_byte_width(), 1);
        assert_eq!(FheType::EVectorU32.element_byte_width(), 4);
        assert_eq!(FheType::EVectorU64.element_byte_width(), 8);
        assert_eq!(FheType::EVectorU128.element_byte_width(), 16);
        assert_eq!(FheType::EUint64.element_byte_width(), 8);
    }

    #[test]
    fn element_count_values() {
        assert_eq!(FheType::EVectorU8.element_count(), 8192);
        assert_eq!(FheType::EVectorU32.element_count(), 2048);
        assert_eq!(FheType::EVectorU64.element_count(), 1024);
        assert_eq!(FheType::EVectorU128.element_count(), 512);
        assert_eq!(FheType::EVectorU32768.element_count(), 2);
        assert_eq!(FheType::EBitVector256.element_count(), 256);
        assert_eq!(FheType::EUint64.element_count(), 1);
    }
}
