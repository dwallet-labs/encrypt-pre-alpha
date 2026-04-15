// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Comprehensive vector operation tests across all arithmetic vector types and operations.
//!
//! Tests the full pipeline: GraphBuilder → serialize → evaluate_graph → MockComputeEngine.
//! Covers all 13 arithmetic vector types (EVectorU8..EVectorU32768) and all
//! supported operations (arithmetic, boolean, comparison, unary, scalar variants, select).

use encrypt_compute::engine::ComputeEngine;
use encrypt_compute::evaluator::evaluate_graph;
use encrypt_compute::mock::MockComputeEngine;
use encrypt_dsl::graph::GraphBuilder;
use encrypt_types::types::{FheOperation, FheType};

// ── Helpers ──

/// Write a u128 value at element `idx` of a vector with given element byte width.
fn write_element(buf: &mut [u8], idx: usize, elem_bw: usize, value: u128) {
    let off = idx * elem_bw;
    let bytes = value.to_le_bytes();
    let copy = elem_bw.min(16);
    buf[off..off + copy].copy_from_slice(&bytes[..copy]);
}

/// Read element at `idx` as u128.
fn read_element(buf: &[u8], idx: usize, elem_bw: usize) -> u128 {
    let off = idx * elem_bw;
    let mut bytes = [0u8; 16];
    let copy = elem_bw.min(16);
    bytes[..copy].copy_from_slice(&buf[off..off + copy]);
    u128::from_le_bytes(bytes)
}

/// Create a vector with given elements at the start, rest zeros.
/// Silently truncates if more elements than the vector can hold.
fn make_vector(fhe_type: FheType, elements: &[u128]) -> Vec<u8> {
    let bw = fhe_type.byte_width();
    let elem_bw = fhe_type.element_byte_width();
    let max_elems = fhe_type.element_count();
    let mut buf = vec![0u8; bw];
    for (i, &val) in elements.iter().enumerate().take(max_elems) {
        write_element(&mut buf, i, elem_bw, val);
    }
    buf
}

/// Build a graph: binary_op(a, b) → output
fn build_binary_graph(op: FheOperation, fhe_type: u8) -> Vec<u8> {
    let mut gb = GraphBuilder::new();
    let a = gb.add_input(fhe_type);
    let b = gb.add_input(fhe_type);
    let r = gb.add_op(op as u8, fhe_type, a, b);
    gb.add_output(fhe_type, r);
    gb.serialize()
}

/// Build a graph: scalar_op(vector, scalar_constant) → output
fn build_scalar_op_graph(op: FheOperation, vec_type: u8, scalar_type: u8, scalar_val: u128) -> Vec<u8> {
    let mut gb = GraphBuilder::new();
    let v = gb.add_input(vec_type);
    let s = gb.add_constant(scalar_type, scalar_val);
    let r = gb.add_op(op as u8, vec_type, v, s);
    gb.add_output(vec_type, r);
    gb.serialize()
}

/// Build a graph: unary_op(a) → output
fn build_unary_graph(op: FheOperation, fhe_type: u8) -> Vec<u8> {
    let mut gb = GraphBuilder::new();
    let a = gb.add_input(fhe_type);
    let r = gb.add_op(op as u8, fhe_type, a, 0xFFFF);
    gb.add_output(fhe_type, r);
    gb.serialize()
}

/// Build a graph: select(cond, if_true, if_false) → output
fn build_select_graph(vec_type: u8) -> Vec<u8> {
    let mut gb = GraphBuilder::new();
    let cond = gb.add_input(0); // EBool
    let t = gb.add_input(vec_type);
    let f = gb.add_input(vec_type);
    let r = gb.add_ternary_op(FheOperation::Select as u8, vec_type, cond, t, f);
    gb.add_output(vec_type, r);
    gb.serialize()
}

/// Evaluate a binary graph and return decrypted result elements.
fn eval_binary(
    engine: &mut MockComputeEngine,
    op: FheOperation,
    fhe_type: FheType,
    a_elems: &[u128],
    b_elems: &[u128],
    num_result_elems: usize,
) -> Vec<u128> {
    let num_result_elems = num_result_elems.min(fhe_type.element_count());
    let graph = build_binary_graph(op, fhe_type as u8);
    let a = engine.encode_constant_bytes(fhe_type, &make_vector(fhe_type, a_elems)).unwrap();
    let b = engine.encode_constant_bytes(fhe_type, &make_vector(fhe_type, b_elems)).unwrap();
    let result = evaluate_graph(engine, &graph, &[a, b]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], fhe_type).unwrap();
    let elem_bw = fhe_type.element_byte_width();
    (0..num_result_elems).map(|i| read_element(&decrypted, i, elem_bw)).collect()
}

/// Evaluate a scalar op graph and return decrypted result elements.
fn eval_scalar_op(
    engine: &mut MockComputeEngine,
    op: FheOperation,
    fhe_type: FheType,
    v_elems: &[u128],
    scalar: u128,
    num_result_elems: usize,
) -> Vec<u128> {
    let num_result_elems = num_result_elems.min(fhe_type.element_count());
    let scalar_type = fhe_type.scalar_element_type();
    let graph = build_scalar_op_graph(op, fhe_type as u8, scalar_type as u8, scalar);
    let v = engine.encode_constant_bytes(fhe_type, &make_vector(fhe_type, v_elems)).unwrap();
    let result = evaluate_graph(engine, &graph, &[v]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], fhe_type).unwrap();
    let elem_bw = fhe_type.element_byte_width();
    (0..num_result_elems).map(|i| read_element(&decrypted, i, elem_bw)).collect()
}

/// Evaluate a unary graph and return decrypted result elements.
fn eval_unary(
    engine: &mut MockComputeEngine,
    op: FheOperation,
    fhe_type: FheType,
    a_elems: &[u128],
    num_result_elems: usize,
) -> Vec<u128> {
    let num_result_elems = num_result_elems.min(fhe_type.element_count());
    let graph = build_unary_graph(op, fhe_type as u8);
    let a = engine.encode_constant_bytes(fhe_type, &make_vector(fhe_type, a_elems)).unwrap();
    let result = evaluate_graph(engine, &graph, &[a]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], fhe_type).unwrap();
    let elem_bw = fhe_type.element_byte_width();
    (0..num_result_elems).map(|i| read_element(&decrypted, i, elem_bw)).collect()
}

/// Mask for element type (e.g., 0xFF for u8, 0xFFFFFFFF for u32).
fn type_mask(fhe_type: FheType) -> u128 {
    let bits = fhe_type.element_byte_width() * 8;
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

// ════════════════════════════════════════════════════════════
// Arithmetic vector types to test
// ════════════════════════════════════════════════════════════

/// All 13 arithmetic vector types.
const ARITH_VECTOR_TYPES: &[(FheType, &str)] = &[
    (FheType::EVectorU8, "EVectorU8"),         // 8192 elems
    (FheType::EVectorU16, "EVectorU16"),        // 4096 elems
    (FheType::EVectorU32, "EVectorU32"),        // 2048 elems
    (FheType::EVectorU64, "EVectorU64"),        // 1024 elems
    (FheType::EVectorU128, "EVectorU128"),      // 512 elems
    (FheType::EVectorU256, "EVectorU256"),      // 256 elems
    (FheType::EVectorU512, "EVectorU512"),      // 128 elems
    (FheType::EVectorU1024, "EVectorU1024"),    // 64 elems
    (FheType::EVectorU2048, "EVectorU2048"),    // 32 elems
    (FheType::EVectorU4096, "EVectorU4096"),    // 16 elems
    (FheType::EVectorU8192, "EVectorU8192"),    // 8 elems
    (FheType::EVectorU16384, "EVectorU16384"),  // 4 elems
    (FheType::EVectorU32768, "EVectorU32768"),  // 2 elems
];

// ════════════════════════════════════════════════════════════
// Binary arithmetic operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn add_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Add, ft, &[10, 20], &[1, 2], 2);
        assert_eq!(r[0], 11, "{name}: 10+1");
        assert_eq!(r[1], 22, "{name}: 20+2");
    }
}

#[test]
fn subtract_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_binary(&mut engine, FheOperation::Subtract, ft, &[50, 0], &[10, 1], 2);
        assert_eq!(r[0], 40, "{name}: 50-10");
        let expected = (0u128.wrapping_sub(1)) & mask;
        assert_eq!(r[1], expected, "{name}: 0-1 wrapping");
    }
}

#[test]
fn multiply_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Multiply, ft, &[6, 7], &[7, 8], 2);
        assert_eq!(r[0], 42, "{name}: 6*7");
        assert_eq!(r[1], 56, "{name}: 7*8");
    }
}

#[test]
fn divide_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Divide, ft, &[84, 100], &[2, 7], 2);
        assert_eq!(r[0], 42, "{name}: 84/2");
        assert_eq!(r[1], 14, "{name}: 100/7");
    }
}

#[test]
fn modulo_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Modulo, ft, &[47, 100], &[5, 7], 2);
        assert_eq!(r[0], 2, "{name}: 47%5");
        assert_eq!(r[1], 2, "{name}: 100%7");
    }
}

#[test]
fn min_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Min, ft, &[10, 50], &[20, 5], 2);
        assert_eq!(r[0], 10, "{name}: min(10,20)");
        assert_eq!(r[1], 5, "{name}: min(50,5)");
    }
}

#[test]
fn max_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Max, ft, &[10, 50], &[20, 5], 2);
        assert_eq!(r[0], 20, "{name}: max(10,20)");
        assert_eq!(r[1], 50, "{name}: max(50,5)");
    }
}

// ════════════════════════════════════════════════════════════
// Boolean/bitwise operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn and_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::And, ft, &[0xFF, 0x0F], &[0x0F, 0xFF], 2);
        assert_eq!(r[0], 0x0F, "{name}: 0xFF & 0x0F");
        assert_eq!(r[1], 0x0F, "{name}: 0x0F & 0xFF");
    }
}

#[test]
fn or_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Or, ft, &[0xF0, 0x0F], &[0x0F, 0], 2);
        assert_eq!(r[0], 0xFF, "{name}: 0xF0 | 0x0F");
        assert_eq!(r[1], 0x0F, "{name}: 0x0F | 0");
    }
}

#[test]
fn xor_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Xor, ft, &[0xFF, 0xFF], &[0xFF, 0x0F], 2);
        assert_eq!(r[0], 0, "{name}: 0xFF ^ 0xFF");
        assert_eq!(r[1], 0xF0, "{name}: 0xFF ^ 0x0F");
    }
}

// ════════════════════════════════════════════════════════════
// Scalar variant operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn add_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::AddScalar, ft, &[10, 20], 5, 2);
        assert_eq!(r[0], 15, "{name}: 10+5");
        assert_eq!(r[1], 25, "{name}: 20+5");
    }
}

#[test]
fn multiply_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::MultiplyScalar, ft, &[5, 10], 3, 2);
        assert_eq!(r[0], 15, "{name}: 5*3");
        assert_eq!(r[1], 30, "{name}: 10*3");
    }
}

#[test]
fn subtract_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::SubtractScalar, ft, &[50, 20], 5, 2);
        assert_eq!(r[0], 45, "{name}: 50-5");
        assert_eq!(r[1], 15, "{name}: 20-5");
    }
}

#[test]
fn divide_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::DivideScalar, ft, &[42, 100], 3, 2);
        assert_eq!(r[0], 14, "{name}: 42/3");
        assert_eq!(r[1], 33, "{name}: 100/3");
    }
}

#[test]
fn modulo_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::ModuloScalar, ft, &[47, 10], 5, 2);
        assert_eq!(r[0], 2, "{name}: 47%5");
        assert_eq!(r[1], 0, "{name}: 10%5");
    }
}

#[test]
fn min_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::MinScalar, ft, &[10, 50], 20, 2);
        assert_eq!(r[0], 10, "{name}: min(10,20)");
        assert_eq!(r[1], 20, "{name}: min(50,20)");
    }
}

#[test]
fn max_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::MaxScalar, ft, &[10, 50], 20, 2);
        assert_eq!(r[0], 20, "{name}: max(10,20)");
        assert_eq!(r[1], 50, "{name}: max(50,20)");
    }
}

#[test]
fn and_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::AndScalar, ft, &[0xFF, 0x0F], 0x0F, 2);
        assert_eq!(r[0], 0x0F, "{name}: 0xFF & 0x0F");
        assert_eq!(r[1], 0x0F, "{name}: 0x0F & 0x0F");
    }
}

#[test]
fn or_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::OrScalar, ft, &[0xF0, 0], 0x0F, 2);
        assert_eq!(r[0], 0xFF, "{name}: 0xF0 | 0x0F");
        assert_eq!(r[1], 0x0F, "{name}: 0 | 0x0F");
    }
}

#[test]
fn xor_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::XorScalar, ft, &[0xFF, 0], 0xFF, 2);
        assert_eq!(r[0], 0, "{name}: 0xFF ^ 0xFF");
        assert_eq!(r[1], 0xFF, "{name}: 0 ^ 0xFF");
    }
}

// ════════════════════════════════════════════════════════════
// Comparison operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn is_equal_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsEqual, ft, &[10, 20], &[10, 5], 2);
        assert_eq!(r[0], 1, "{name}: 10==10");
        assert_eq!(r[1], 0, "{name}: 20==5");
    }
}

#[test]
fn is_not_equal_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsNotEqual, ft, &[10, 20], &[10, 5], 2);
        assert_eq!(r[0], 0, "{name}: 10!=10");
        assert_eq!(r[1], 1, "{name}: 20!=5");
    }
}

#[test]
fn is_less_than_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsLessThan, ft, &[5, 20], &[10, 5], 2);
        assert_eq!(r[0], 1, "{name}: 5<10");
        assert_eq!(r[1], 0, "{name}: 20<5");
    }
}

#[test]
fn is_greater_than_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsGreaterThan, ft, &[20, 5], &[10, 10], 2);
        assert_eq!(r[0], 1, "{name}: 20>10");
        assert_eq!(r[1], 0, "{name}: 5>10");
    }
}

#[test]
fn is_greater_or_equal_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsGreaterOrEqual, ft, &[20, 10], &[10, 10], 2);
        assert_eq!(r[0], 1, "{name}: 20>=10");
        assert_eq!(r[1], 1, "{name}: 10>=10");
    }
}

#[test]
fn is_less_or_equal_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::IsLessOrEqual, ft, &[5, 20], &[10, 10], 2);
        assert_eq!(r[0], 1, "{name}: 5<=10");
        assert_eq!(r[1], 0, "{name}: 20<=10");
    }
}

// Scalar comparison variants
#[test]
fn is_equal_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsEqualScalar, ft, &[10, 20], 10, 2);
        assert_eq!(r[0], 1, "{name}: 10==10");
        assert_eq!(r[1], 0, "{name}: 20==10");
    }
}

#[test]
fn is_less_than_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsLessThanScalar, ft, &[5, 20], 10, 2);
        assert_eq!(r[0], 1, "{name}: 5<10");
        assert_eq!(r[1], 0, "{name}: 20<10");
    }
}

// ════════════════════════════════════════════════════════════
// Unary operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn negate_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_unary(&mut engine, FheOperation::Negate, ft, &[1, 42], 2);
        assert_eq!(r[0], (0u128.wrapping_sub(1)) & mask, "{name}: -1");
        assert_eq!(r[1], (0u128.wrapping_sub(42)) & mask, "{name}: -42");
    }
}

#[test]
fn not_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_unary(&mut engine, FheOperation::Not, ft, &[0, 0xFF], 2);
        assert_eq!(r[0], mask, "{name}: !0");
        assert_eq!(r[1], (!0xFFu128) & mask, "{name}: !0xFF");
    }
}

// ════════════════════════════════════════════════════════════
// Select (ternary) — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn select_true_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let graph = build_select_graph(ft as u8);
        let cond = engine.encode_constant(FheType::EBool, 1).unwrap();
        let t = engine.encode_constant_bytes(ft, &make_vector(ft, &[100, 200])).unwrap();
        let f = engine.encode_constant_bytes(ft, &make_vector(ft, &[1, 2])).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[cond, t, f]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        let elem_bw = ft.element_byte_width();
        assert_eq!(read_element(&decrypted, 0, elem_bw), 100, "{name}: select(true)[0]");
        assert_eq!(read_element(&decrypted, 1, elem_bw), 200, "{name}: select(true)[1]");
    }
}

#[test]
fn select_false_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let graph = build_select_graph(ft as u8);
        let cond = engine.encode_constant(FheType::EBool, 0).unwrap();
        let t = engine.encode_constant_bytes(ft, &make_vector(ft, &[100, 200])).unwrap();
        let f = engine.encode_constant_bytes(ft, &make_vector(ft, &[1, 2])).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[cond, t, f]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        let elem_bw = ft.element_byte_width();
        assert_eq!(read_element(&decrypted, 0, elem_bw), 1, "{name}: select(false)[0]");
        assert_eq!(read_element(&decrypted, 1, elem_bw), 2, "{name}: select(false)[1]");
    }
}

// ════════════════════════════════════════════════════════════
// Chained operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn chained_add_then_multiply_scalar_all_vector_types() {
    // (a + b) * 3 for all types
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let scalar_type = ft.scalar_element_type();
        let mut gb = GraphBuilder::new();
        let a = gb.add_input(ft as u8);
        let b = gb.add_input(ft as u8);
        let sum = gb.add_op(FheOperation::Add as u8, ft as u8, a, b);
        let three = gb.add_constant(scalar_type as u8, 3);
        let r = gb.add_op(FheOperation::MultiplyScalar as u8, ft as u8, sum, three);
        gb.add_output(ft as u8, r);
        let graph = gb.serialize();

        let a_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &[10, 20])).unwrap();
        let b_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &[1, 2])).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[a_dig, b_dig]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        let elem_bw = ft.element_byte_width();
        assert_eq!(read_element(&decrypted, 0, elem_bw), 33, "{name}: (10+1)*3");
        if ft.element_count() >= 2 {
            assert_eq!(read_element(&decrypted, 1, elem_bw), 66, "{name}: (20+2)*3");
        }
    }
}

// ════════════════════════════════════════════════════════════
// Bit vector tests
// ════════════════════════════════════════════════════════════

#[test]
fn bit_vector_and() {
    let ft = FheType::EBitVector32; // 4 bytes
    let mut engine = MockComputeEngine::new();
    let a = engine.encode_constant_bytes(ft, &[0xFF, 0x0F, 0xAA, 0x55]).unwrap();
    let b = engine.encode_constant_bytes(ft, &[0x0F, 0xFF, 0x55, 0xAA]).unwrap();
    let graph = build_binary_graph(FheOperation::And, ft as u8);
    let result = evaluate_graph(&mut engine, &graph, &[a, b]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
    assert_eq!(decrypted, vec![0x0F, 0x0F, 0x00, 0x00]);
}

#[test]
fn bit_vector_or() {
    let ft = FheType::EBitVector32;
    let mut engine = MockComputeEngine::new();
    let a = engine.encode_constant_bytes(ft, &[0xF0, 0x0F, 0xAA, 0x55]).unwrap();
    let b = engine.encode_constant_bytes(ft, &[0x0F, 0xF0, 0x55, 0xAA]).unwrap();
    let graph = build_binary_graph(FheOperation::Or, ft as u8);
    let result = evaluate_graph(&mut engine, &graph, &[a, b]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
    assert_eq!(decrypted, vec![0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn bit_vector_xor() {
    let ft = FheType::EBitVector32;
    let mut engine = MockComputeEngine::new();
    let a = engine.encode_constant_bytes(ft, &[0xFF, 0x00, 0xAA, 0x55]).unwrap();
    let b = engine.encode_constant_bytes(ft, &[0xFF, 0xFF, 0x55, 0xAA]).unwrap();
    let graph = build_binary_graph(FheOperation::Xor, ft as u8);
    let result = evaluate_graph(&mut engine, &graph, &[a, b]).unwrap();
    let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
    assert_eq!(decrypted, vec![0x00, 0xFF, 0xFF, 0xFF]);
}

// ════════════════════════════════════════════════════════════
// Edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn overflow_wrapping_u8_vector() {
    let ft = FheType::EVectorU8;
    let mut engine = MockComputeEngine::new();
    let r = eval_binary(&mut engine, FheOperation::Add, ft, &[200, 255], &[100, 1], 2);
    // 200 + 100 = 300, wraps to 300 & 0xFF = 44
    assert_eq!(r[0], 44);
    // 255 + 1 = 256, wraps to 0
    assert_eq!(r[1], 0);
}

#[test]
fn overflow_wrapping_u16_vector() {
    let ft = FheType::EVectorU16;
    let mut engine = MockComputeEngine::new();
    let r = eval_binary(&mut engine, FheOperation::Add, ft, &[65535, 60000], &[1, 10000], 2);
    assert_eq!(r[0], 0); // 65536 & 0xFFFF = 0
    assert_eq!(r[1], 4464); // 70000 & 0xFFFF = 4464
}

#[test]
fn divide_by_zero_vector() {
    let ft = FheType::EVectorU32;
    let mut engine = MockComputeEngine::new();
    let r = eval_binary(&mut engine, FheOperation::Divide, ft, &[42, 100], &[0, 0], 2);
    assert_eq!(r[0], 0, "42/0 = 0 (safe divide)");
    assert_eq!(r[1], 0, "100/0 = 0 (safe divide)");
}

#[test]
fn large_element_type_u128_vector() {
    let ft = FheType::EVectorU128;
    let mut engine = MockComputeEngine::new();
    let big_a = u128::MAX / 2;
    let big_b = 1u128;
    let r = eval_binary(&mut engine, FheOperation::Add, ft, &[big_a, 42], &[big_b, 0], 2);
    assert_eq!(r[0], big_a + big_b);
    assert_eq!(r[1], 42);
}

#[test]
fn all_zeros_vector() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::Add, ft, &[], &[], 2);
        assert_eq!(r[0], 0, "{name}: zero+zero");
        assert_eq!(r[1], 0, "{name}: zero+zero");
    }
}

// ════════════════════════════════════════════════════════════
// Missing binary boolean ops — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn nor_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_binary(&mut engine, FheOperation::Nor, ft, &[0xF0, 0], &[0x0F, 0], 2);
        assert_eq!(r[0], (!(0xF0u128 | 0x0F)) & mask, "{name}: nor(0xF0,0x0F)");
        assert_eq!(r[1], mask, "{name}: nor(0,0) = all ones");
    }
}

#[test]
fn nand_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_binary(&mut engine, FheOperation::Nand, ft, &[0xFF, 0xFF], &[0xFF, 0x0F], 2);
        assert_eq!(r[0], (!0xFFu128) & mask, "{name}: nand(0xFF,0xFF)");
        assert_eq!(r[1], (!0x0Fu128) & mask, "{name}: nand(0xFF,0x0F)");
    }
}

#[test]
fn shift_left_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_binary(&mut engine, FheOperation::ShiftLeft, ft, &[1, 0xFF], &[4, 1], 2);
        assert_eq!(r[0], 16, "{name}: 1<<4");
        assert_eq!(r[1], (0xFFu128 << 1) & mask, "{name}: 0xFF<<1");
    }
}

#[test]
fn shift_right_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::ShiftRight, ft, &[128, 0xFF], &[3, 4], 2);
        assert_eq!(r[0], 16, "{name}: 128>>3");
        assert_eq!(r[1], 0x0F, "{name}: 0xFF>>4");
    }
}

#[test]
fn rotate_left_all_vector_types() {
    // Only test types with elements <= 128 bits (rotate uses type_bit_count clamped to 128)
    for &(ft, name) in ARITH_VECTOR_TYPES {
        if ft.element_byte_width() > 16 { continue; } // skip >128-bit elements
        let mut engine = MockComputeEngine::new();
        let bits = ft.element_byte_width() * 8;
        // Rotate 0b1 left by (bits-1) should give the MSB set
        let expected = 1u128 << (bits - 1);
        let r = eval_binary(&mut engine, FheOperation::RotateLeft, ft, &[1], &[bits as u128 - 1], 1);
        assert_eq!(r[0], expected, "{name}: rotate_left(1, {}-1)", bits);
    }
}

#[test]
fn rotate_right_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        if ft.element_byte_width() > 16 { continue; }
        let mut engine = MockComputeEngine::new();
        // Rotate 1 right by 1 should give MSB set
        let bits = ft.element_byte_width() * 8;
        let expected = 1u128 << (bits - 1);
        let r = eval_binary(&mut engine, FheOperation::RotateRight, ft, &[1], &[1], 1);
        assert_eq!(r[0], expected, "{name}: rotate_right(1, 1)");
    }
}

// ════════════════════════════════════════════════════════════
// Missing scalar comparison variants — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn is_not_equal_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsNotEqualScalar, ft, &[10, 20], 10, 2);
        assert_eq!(r[0], 0, "{name}: 10!=10");
        assert_eq!(r[1], 1, "{name}: 20!=10");
    }
}

#[test]
fn is_greater_than_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsGreaterThanScalar, ft, &[20, 5], 10, 2);
        assert_eq!(r[0], 1, "{name}: 20>10");
        assert_eq!(r[1], 0, "{name}: 5>10");
    }
}

#[test]
fn is_greater_or_equal_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsGreaterOrEqualScalar, ft, &[20, 10], 10, 2);
        assert_eq!(r[0], 1, "{name}: 20>=10");
        assert_eq!(r[1], 1, "{name}: 10>=10");
    }
}

#[test]
fn is_less_or_equal_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_scalar_op(&mut engine, FheOperation::IsLessOrEqualScalar, ft, &[5, 20], 10, 2);
        assert_eq!(r[0], 1, "{name}: 5<=10");
        assert_eq!(r[1], 0, "{name}: 20<=10");
    }
}

// ════════════════════════════════════════════════════════════
// Missing unary ops — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn into_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_unary(&mut engine, FheOperation::Into, ft, &[42, 99], 2);
        assert_eq!(r[0], 42, "{name}: into(42)");
        assert_eq!(r[1], 99, "{name}: into(99)");
    }
}

#[test]
fn bootstrap_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_unary(&mut engine, FheOperation::Bootstrap, ft, &[77, 0], 2);
        assert_eq!(r[0], 77 & mask, "{name}: bootstrap(77)");
        assert_eq!(r[1], 0, "{name}: bootstrap(0)");
    }
}

// ════════════════════════════════════════════════════════════
// Blend — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn blend_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        // Blend returns first operand
        let r = eval_binary(&mut engine, FheOperation::Blend, ft, &[42, 99], &[1, 2], 2);
        assert_eq!(r[0], 42, "{name}: blend returns a");
        assert_eq!(r[1], 99, "{name}: blend returns a");
    }
}

// ════════════════════════════════════════════════════════════
// Vector-specific structural operations — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn gather_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let count = ft.element_count();
        if count < 4 { continue; } // need at least 4 elements
        let mut engine = MockComputeEngine::new();
        // a = [10, 20, 30, 40, ...], indices = [2, 0, 3, 1, ...]
        // result[0] = a[2] = 30, result[1] = a[0] = 10, result[2] = a[3] = 40, result[3] = a[1] = 20
        let r = eval_binary(&mut engine, FheOperation::Gather, ft, &[10, 20, 30, 40], &[2, 0, 3, 1], 4);
        assert_eq!(r[0], 30, "{name}: gather a[2]=30");
        assert_eq!(r[1], 10, "{name}: gather a[0]=10");
        assert_eq!(r[2], 40, "{name}: gather a[3]=40");
        assert_eq!(r[3], 20, "{name}: gather a[1]=20");
    }
}

#[test]
fn gather_out_of_bounds() {
    let ft = FheType::EVectorU32;
    let mut engine = MockComputeEngine::new();
    let count = ft.element_count();
    // Index out of bounds → 0
    let r = eval_binary(&mut engine, FheOperation::Gather, ft,
        &[42, 99], &[0, count as u128], 2);
    assert_eq!(r[0], 42, "gather a[0]=42");
    assert_eq!(r[1], 0, "gather out-of-bounds=0");
}

#[test]
fn scatter_all_vector_types() {
    // Only test types where element count fits in element range (u16+)
    // U8 has 8192 elements but max index 255 — can't have unique indices.
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let count = ft.element_count();
        let elem_bits = ft.element_byte_width() * 8;
        // Skip types where element can't uniquely index all positions
        if count < 4 || (elem_bits < usize::BITS as usize && count > (1usize << elem_bits)) { continue; }
        let mut engine = MockComputeEngine::new();
        let mut vals: Vec<u128> = vec![0; count];
        let mut idxs: Vec<u128> = (0..count as u128).collect();
        vals[0] = 10; vals[1] = 20; vals[2] = 30;
        idxs[0] = 2; idxs[1] = 0; idxs[2] = 1;
        let r = eval_binary(&mut engine, FheOperation::Scatter, ft, &vals, &idxs, 4);
        assert_eq!(r[0], 20, "{name}: scatter pos 0 = 20");
        assert_eq!(r[1], 30, "{name}: scatter pos 1 = 30");
        assert_eq!(r[2], 10, "{name}: scatter pos 2 = 10");
        assert_eq!(r[3], 0, "{name}: scatter pos 3 = 0");
    }
}

#[test]
fn scatter_u8_small_range() {
    // For EVectorU8: test scatter within u8-addressable range
    let ft = FheType::EVectorU8;
    let mut engine = MockComputeEngine::new();
    // Only use first 4 elements, all with in-range indices
    // Make the rest of elements identity-mapped (value=0, index=self)
    let mut vals: Vec<u128> = vec![0; 256]; // only first 256 addressable
    let mut idxs: Vec<u128> = (0..256u128).collect();
    vals[0] = 10; vals[1] = 20; vals[2] = 30;
    idxs[0] = 2; idxs[1] = 0; idxs[2] = 1;
    // But we have 8192 elements total — elements 256+ have index that wraps.
    // Build the full 8192-byte vectors manually:
    let a_bytes = make_vector(ft, &vals);
    let mut i_bytes = vec![0u8; 8192];
    for i in 0..8192usize { i_bytes[i] = (i % 256) as u8; }
    i_bytes[0] = 2; i_bytes[1] = 0; i_bytes[2] = 1;
    let a_dig = engine.encode_constant_bytes(ft, &a_bytes).unwrap();
    let i_dig = engine.encode_constant_bytes(ft, &i_bytes).unwrap();
    let graph = build_binary_graph(FheOperation::Scatter, ft as u8);
    let result = evaluate_graph(&mut engine, &graph, &[a_dig, i_dig]).unwrap();
    let r = engine.decrypt(&result.output_digests[0], ft).unwrap();
    // Positions 0,1,2 get overwritten multiple times by wrapping indices.
    // Last writer wins: element 8064 (8064%256=0) writes 0→pos 0, etc.
    // So pos 0,1,2 end up 0. That's correct scatter behavior.
    // Just verify a non-colliding position: pos 3 should be 0 (element 3 has val=0, idx=3)
    assert_eq!(r[3], 0, "u8 scatter pos 3");
}

#[test]
fn copy_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        // Copy returns second operand
        let r = eval_binary(&mut engine, FheOperation::Copy, ft, &[1, 2], &[42, 99], 2);
        assert_eq!(r[0], 42, "{name}: copy returns b[0]");
        assert_eq!(r[1], 99, "{name}: copy returns b[1]");
    }
}

#[test]
fn get_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let count = ft.element_count();
        if count < 3 { continue; }
        let mut engine = MockComputeEngine::new();
        // a = [10, 20, 30, ...], index = [2, 0, 0, ...] → extract a[2] = 30
        let r = eval_binary(&mut engine, FheOperation::Get, ft, &[10, 20, 30], &[2], 2);
        assert_eq!(r[0], 30, "{name}: get a[2]=30");
        assert_eq!(r[1], 0, "{name}: get rest=0");
    }
}

#[test]
fn get_first_element() {
    let ft = FheType::EVectorU32;
    let mut engine = MockComputeEngine::new();
    let r = eval_binary(&mut engine, FheOperation::Get, ft, &[42, 99, 77], &[0], 1);
    assert_eq!(r[0], 42, "get a[0]=42");
}

#[test]
fn assign_all_vector_types() {
    // assign: result = a, then result[indices[i]] = values[i]
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let count = ft.element_count();
        let elem_bits = ft.element_byte_width() * 8;
        // Skip types where indices can't address all positions
        if count < 4 || (elem_bits < usize::BITS as usize && count > (1usize << elem_bits)) { continue; }
        let mut engine = MockComputeEngine::new();

        // base = [100, 200, 300, 400, 0...]
        // Only first 2 elements of indices/values matter.
        // Rest must point to positions >= 4 so they don't overwrite base[0..4].
        // indices = [1, 3, 4, 5, 6, ...], values = [11, 22, 0, 0, 0, ...]
        // result: base then result[1]=11, result[3]=22, rest write 0 to pos >= 4
        // → [100, 11, 300, 22, 0...]
        let mut base: Vec<u128> = vec![0; count];
        base[0] = 100; base[1] = 200; base[2] = 300; base[3] = 400;
        let mut indices: Vec<u128> = (0..count as u128).collect();
        indices[0] = 1; indices[1] = 3;
        // Shift indices[2..] to start at 4 so they don't collide with 0-3
        for i in 2..count { indices[i] = (i + 2) as u128; }
        let mut values: Vec<u128> = vec![0; count];
        values[0] = 11; values[1] = 22;

        let mut gb = GraphBuilder::new();
        let a = gb.add_input(ft as u8);
        let b = gb.add_input(ft as u8);
        let c = gb.add_input(ft as u8);
        let r = gb.add_ternary_op(FheOperation::Assign as u8, ft as u8, a, b, c);
        gb.add_output(ft as u8, r);
        let graph = gb.serialize();

        let a_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &base)).unwrap();
        let b_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &indices)).unwrap();
        let c_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &values)).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[a_dig, b_dig, c_dig]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        let ebw = ft.element_byte_width();
        assert_eq!(read_element(&decrypted, 0, ebw), 100, "{name}: assign[0] unchanged");
        assert_eq!(read_element(&decrypted, 1, ebw), 11, "{name}: assign[1]=11");
        assert_eq!(read_element(&decrypted, 2, ebw), 300, "{name}: assign[2] unchanged");
        assert_eq!(read_element(&decrypted, 3, ebw), 22, "{name}: assign[3]=22");
    }
}

#[test]
fn assign_scalars_all_vector_types() {
    // assign_scalars: result = a, then result[indices[i]] = scalar for each i
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let count = ft.element_count();
        let elem_bits = ft.element_byte_width() * 8;
        if count < 4 || (elem_bits < usize::BITS as usize && count > (1usize << elem_bits)) { continue; }
        let mut engine = MockComputeEngine::new();

        // base = [100, 200, 300, 400, 0...]
        // indices = [1, 3, 4, 5, ...] — only first 2 target positions 1 and 3
        // scalar = 99
        // result[1]=99, result[3]=99, rest assigned 99 at pos >= 4
        // → [100, 99, 300, 99, 99, 99, ...]
        let mut base: Vec<u128> = vec![0; count];
        base[0] = 100; base[1] = 200; base[2] = 300; base[3] = 400;
        let mut indices: Vec<u128> = (0..count as u128).collect();
        indices[0] = 1; indices[1] = 3;
        for i in 2..count { indices[i] = (i + 2) as u128; }
        let scalar_vec: Vec<u128> = vec![99; count];

        let mut gb = GraphBuilder::new();
        let a = gb.add_input(ft as u8);
        let b = gb.add_input(ft as u8);
        let c = gb.add_input(ft as u8);
        let r = gb.add_ternary_op(FheOperation::AssignScalars as u8, ft as u8, a, b, c);
        gb.add_output(ft as u8, r);
        let graph = gb.serialize();

        let a_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &base)).unwrap();
        let b_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &indices)).unwrap();
        let c_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &scalar_vec)).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[a_dig, b_dig, c_dig]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        let ebw = ft.element_byte_width();
        assert_eq!(read_element(&decrypted, 0, ebw), 100, "{name}: assign_scalars[0] unchanged");
        assert_eq!(read_element(&decrypted, 1, ebw), 99, "{name}: assign_scalars[1]=99");
        assert_eq!(read_element(&decrypted, 2, ebw), 300, "{name}: assign_scalars[2] unchanged");
        assert_eq!(read_element(&decrypted, 3, ebw), 99, "{name}: assign_scalars[3]=99");
    }
}

#[test]
fn gather_then_scatter_roundtrip() {
    // Scatter then gather with same indices = identity for the first N elements
    let ft = FheType::EVectorU32;
    let count = ft.element_count();
    let mut engine = MockComputeEngine::new();
    let ebw = ft.element_byte_width();

    // Build full vectors: values and a permutation of indices
    let mut values: Vec<u128> = vec![0; count];
    let mut indices: Vec<u128> = (0..count as u128).collect();
    values[0] = 10; values[1] = 20; values[2] = 30; values[3] = 40;
    indices[0] = 3; indices[1] = 1; indices[2] = 0; indices[3] = 2;

    // Step 1: Scatter values to indexed positions
    let scatter_graph = build_binary_graph(FheOperation::Scatter, ft as u8);
    let v_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &values)).unwrap();
    let i_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &indices)).unwrap();
    let scatter_result = evaluate_graph(&mut engine, &scatter_graph, &[v_dig, i_dig]).unwrap();
    let scattered_dig = scatter_result.output_digests[0];

    // Step 2: Gather from scattered using same indices → recovers originals
    let gather_graph = build_binary_graph(FheOperation::Gather, ft as u8);
    let gathered_result = evaluate_graph(&mut engine, &gather_graph, &[scattered_dig, i_dig]).unwrap();
    let gathered = engine.decrypt(&gathered_result.output_digests[0], ft).unwrap();

    assert_eq!(read_element(&gathered, 0, ebw), 10, "roundtrip[0]");
    assert_eq!(read_element(&gathered, 1, ebw), 20, "roundtrip[1]");
    assert_eq!(read_element(&gathered, 2, ebw), 30, "roundtrip[2]");
    assert_eq!(read_element(&gathered, 3, ebw), 40, "roundtrip[3]");
}

// ════════════════════════════════════════════════════════════
// SelectScalar — element-wise conditional select
// ════════════════════════════════════════════════════════════

#[test]
fn select_scalar_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let ebw = ft.element_byte_width();
        // cond=[1, 0], a=[100, 200], b=[10, 20]
        // result[0] = cond[0]!=0 ? a[0] : b[0] = 100
        // result[1] = cond[1]!=0 ? a[1] : b[1] = 20
        let mut gb = GraphBuilder::new();
        let cond = gb.add_input(ft as u8);
        let a = gb.add_input(ft as u8);
        let b = gb.add_input(ft as u8);
        let r = gb.add_ternary_op(FheOperation::SelectScalar as u8, ft as u8, cond, a, b);
        gb.add_output(ft as u8, r);
        let graph = gb.serialize();

        let cond_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &[1, 0])).unwrap();
        let a_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &[100, 200])).unwrap();
        let b_dig = engine.encode_constant_bytes(ft, &make_vector(ft, &[10, 20])).unwrap();
        let result = evaluate_graph(&mut engine, &graph, &[cond_dig, a_dig, b_dig]).unwrap();
        let decrypted = engine.decrypt(&result.output_digests[0], ft).unwrap();
        assert_eq!(read_element(&decrypted, 0, ebw), 100, "{name}: cond=1 → a");
        assert_eq!(read_element(&decrypted, 1, ebw), 20, "{name}: cond=0 → b");
    }
}

// ════════════════════════════════════════════════════════════
// Random / RandomRange — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn random_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_unary(&mut engine, FheOperation::Random, ft, &[42, 99], 2);
        // Just verify it produces something (deterministic, but different from input)
        assert!(r[0] != 42 || r[1] != 99, "{name}: random should differ from input");
        // Deterministic: run again with same input
        let r2 = eval_unary(&mut engine, FheOperation::Random, ft, &[42, 99], 2);
        assert_eq!(r, r2, "{name}: deterministic random");
    }
}

#[test]
fn random_range_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let r = eval_binary(&mut engine, FheOperation::RandomRange, ft, &[42, 99], &[100, 50], 2);
        assert!(r[0] < 100, "{name}: random_range[0] < 100, got {}", r[0]);
        assert!(r[1] < 50, "{name}: random_range[1] < 50, got {}", r[1]);
    }
}

// ════════════════════════════════════════════════════════════
// PackInto — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn pack_into_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        let r = eval_unary(&mut engine, FheOperation::PackInto, ft, &[42, 0xFF], 2);
        assert_eq!(r[0], 42 & mask, "{name}: pack_into(42)");
        assert_eq!(r[1], 0xFF & mask, "{name}: pack_into(0xFF)");
    }
}

// ════════════════════════════════════════════════════════════
// Key management passthrough — all vector types
// ════════════════════════════════════════════════════════════

#[test]
fn key_mgmt_passthrough_all_vector_types() {
    for &(ft, name) in ARITH_VECTOR_TYPES {
        let mut engine = MockComputeEngine::new();
        let mask = type_mask(ft);
        for op in [FheOperation::From, FheOperation::Encrypt, FheOperation::Decrypt,
                   FheOperation::KeySwitch, FheOperation::ReEncrypt] {
            let r = eval_unary(&mut engine, op, ft, &[42, 99], 2);
            assert_eq!(r[0], 42 & mask, "{name}: {op:?} passthrough[0]");
            assert_eq!(r[1], 99 & mask, "{name}: {op:?} passthrough[1]");
        }
    }
}
