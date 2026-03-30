// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;
use encrypt_types::graph::{get_constant_u128, get_node, parse_graph, GraphNodeKind, ParsedGraph};
use encrypt_types::types::FheType;

/// Read the constant u128 value for a Constant node.
fn const_val(pg: &ParsedGraph, node_idx: u16) -> u128 {
    let node = get_node(pg.node_bytes(), node_idx).unwrap();
    assert_eq!(node.kind(), GraphNodeKind::Constant as u8);
    let byte_width = FheType::from_u8(node.fhe_type())
        .map(|t| t.byte_width())
        .unwrap_or(16);
    get_constant_u128(pg.constants(), node.const_offset(), byte_width.min(16)).unwrap()
}

// ── Method syntax ──

#[encrypt_fn_graph]
fn transfer_method(from: EUint64, to: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let has_funds = from.is_greater_or_equal(&amount);
    let new_from = from.subtract(&amount);
    let new_to = to.add(&amount);
    let final_from = has_funds.select(&new_from, &from);
    let final_to = has_funds.select(&new_to, &to);
    (final_from, final_to)
}

#[test]
fn test_transfer_method_syntax() {
    let data = transfer_method();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 3); // from, to, amount
    assert_eq!(header.num_outputs(), 2); // final_from, final_to
    assert_eq!(header.num_ops(), 5); // >=, sub, add, select, select

    // Total: 3 inputs + 5 ops + 2 outputs = 10
    assert_eq!(header.num_nodes(), 10);

    // Verify input nodes
    let n0 = get_node(nodes, 0).unwrap();
    assert_eq!(n0.kind(), GraphNodeKind::Input as u8);
    assert_eq!(n0.fhe_type(), 4); // EUint64

    // Verify an op node (the first op: is_greater_or_equal at index 3)
    let n3 = get_node(nodes, 3).unwrap();
    assert_eq!(n3.kind(), GraphNodeKind::Op as u8);
    assert_eq!(n3.op_type(), 44); // IsGreaterOrEqual
    assert_eq!(n3.fhe_type(), 4); // EUint64
    assert_eq!(n3.input_a(), 0); // from
    assert_eq!(n3.input_b(), 2); // amount

    // Verify output nodes (last two)
    let n8 = get_node(nodes, 8).unwrap();
    assert_eq!(n8.kind(), GraphNodeKind::Output as u8);
    let n9 = get_node(nodes, 9).unwrap();
    assert_eq!(n9.kind(), GraphNodeKind::Output as u8);
}

// ── Operator syntax ──

#[encrypt_fn_graph]
fn transfer_ops(from: EUint64, to: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let has_funds = from >= amount;
    let final_from = if has_funds { from - amount } else { from };
    let final_to = if has_funds { to + amount } else { to };
    (final_from, final_to)
}

#[test]
fn test_transfer_operator_syntax() {
    let data = transfer_ops();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 3);
    assert_eq!(header.num_outputs(), 2);
    // >=, sub, select, add, select = 5 ops
    assert_eq!(header.num_ops(), 5);

    // First op: >= (IsGreaterOrEqual = 44)
    let n3 = get_node(nodes, 3).unwrap();
    assert_eq!(n3.op_type(), 44);

    // The if/else branches generate sub and select nodes
    // sub (from - amount) is at index 4
    let n4 = get_node(nodes, 4).unwrap();
    assert_eq!(n4.kind(), GraphNodeKind::Op as u8);
    assert_eq!(n4.op_type(), 3); // Subtract
}

// ── Simple arithmetic ──

#[encrypt_fn_graph]
fn add_two(a: EUint32, b: EUint32) -> EUint32 {
    a + b
}

#[test]
fn test_simple_add() {
    let data = add_two();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 2);
    assert_eq!(header.num_outputs(), 1);
    assert_eq!(header.num_ops(), 1);
    assert_eq!(header.num_nodes(), 4); // 2 inputs + 1 op + 1 output

    let op = get_node(nodes, 2).unwrap();
    assert_eq!(op.op_type(), 0); // Add
    assert_eq!(op.fhe_type(), 3); // EUint32
    assert_eq!(op.input_a(), 0);
    assert_eq!(op.input_b(), 1);
}

// ── Unary ops ──

#[encrypt_fn_graph]
fn negate_value(x: EUint32) -> EUint32 {
    -x
}

#[test]
fn test_unary_negate() {
    let data = negate_value();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 1);
    assert_eq!(header.num_outputs(), 1);
    assert_eq!(header.num_ops(), 1);

    let op = get_node(nodes, 1).unwrap();
    assert_eq!(op.op_type(), 2); // Negate
    assert_eq!(op.input_a(), 0);
    assert_eq!(op.input_b(), 0xFFFF); // unary marker
}

// ── Boolean ops ──

#[encrypt_fn_graph]
fn bitwise_and(a: EUint8, b: EUint8) -> EUint8 {
    a & b
}

#[test]
fn test_bitwise_and() {
    let data = bitwise_and();
    let pg = parse_graph(&data).expect("valid graph");

    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.header().num_outputs(), 1);
}

// ── Chained operations ──

#[encrypt_fn_graph]
fn chain_ops(a: EUint32, b: EUint32, c: EUint32) -> EUint32 {
    let sum = a + b;
    let product = sum * c;
    product
}

#[test]
fn test_chained_operations() {
    let data = chain_ops();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 3);
    assert_eq!(header.num_ops(), 2); // add, multiply
    assert_eq!(header.num_outputs(), 1);

    // add node at index 3 (after 3 inputs)
    let add = get_node(nodes, 3).unwrap();
    assert_eq!(add.op_type(), 0); // Add
    assert_eq!(add.input_a(), 0); // a
    assert_eq!(add.input_b(), 1); // b

    // multiply node at index 4
    let mul = get_node(nodes, 4).unwrap();
    assert_eq!(mul.op_type(), 1); // Multiply
    assert_eq!(mul.input_a(), 3); // sum (output of add)
    assert_eq!(mul.input_b(), 2); // c
}

// ── Method syntax select ──

#[encrypt_fn_graph]
fn method_select(flag: EBool, a: EUint64, b: EUint64) -> EUint64 {
    flag.select(&a, &b)
}

#[test]
fn test_method_select() {
    let data = method_select();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 3);
    assert_eq!(header.num_ops(), 1); // select
    assert_eq!(header.num_outputs(), 1);

    let sel = get_node(nodes, 3).unwrap();
    assert_eq!(sel.op_type(), 60); // Select
    assert_eq!(sel.fhe_type(), 4); // EUint64 (result type)
    assert_eq!(sel.input_a(), 0); // flag (condition)
    assert_eq!(sel.input_b(), 1); // a (if_true)
    assert_eq!(sel.input_c(), 2); // b (if_false)
}

// ── Constants ──

#[encrypt_fn_graph]
fn with_constant(x: EUint32) -> EUint32 {
    let one = EUint32::from(1u32);
    x + one
}

#[test]
fn test_constant_node() {
    let data = with_constant();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 1);
    assert_eq!(header.num_outputs(), 1);
    assert_eq!(header.num_ops(), 1); // add

    // Node 0: input, Node 1: constant, Node 2: add op, Node 3: output
    assert_eq!(header.num_nodes(), 4);

    let cst = get_node(nodes, 1).unwrap();
    assert_eq!(cst.kind(), GraphNodeKind::Constant as u8);
    assert_eq!(cst.fhe_type(), 3); // EUint32
    assert_eq!(const_val(&pg, 1), 1);

    let add = get_node(nodes, 2).unwrap();
    assert_eq!(add.op_type(), 0); // Add
    assert_eq!(add.input_a(), 0); // x
    assert_eq!(add.input_b(), 1); // constant 1
}

// ── Constants in if/else (SelectScalar pattern) ──

#[encrypt_fn_graph]
fn clamp_to_zero(flag: EBool, val: EUint64) -> EUint64 {
    let zero = EUint64::from(0u64);
    if flag {
        val
    } else {
        zero
    }
}

#[test]
fn test_constant_in_select() {
    let data = clamp_to_zero();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 2); // flag, val
    assert_eq!(header.num_ops(), 1); // select
    assert_eq!(header.num_outputs(), 1);

    // Node 0: flag (input), Node 1: val (input), Node 2: zero (constant),
    // Node 3: select, Node 4: output
    let zero_node = get_node(nodes, 2).unwrap();
    assert_eq!(zero_node.kind(), GraphNodeKind::Constant as u8);
    assert_eq!(const_val(&pg, 2), 0);

    let sel = get_node(nodes, 3).unwrap();
    assert_eq!(sel.op_type(), 60); // Select
    assert_eq!(sel.input_a(), 0); // flag
    assert_eq!(sel.input_b(), 1); // val (if_true)
    assert_eq!(sel.input_c(), 2); // zero (if_false)
}

// ── Bool constant ──

#[encrypt_fn_graph]
fn bool_const() -> EBool {
    EBool::from(true)
}

#[test]
fn test_bool_constant() {
    let data = bool_const();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 0);
    assert_eq!(header.num_outputs(), 1);
    assert_eq!(header.num_nodes(), 2); // constant + output

    let cst = get_node(nodes, 0).unwrap();
    assert_eq!(cst.kind(), GraphNodeKind::Constant as u8);
    assert_eq!(cst.fhe_type(), 0); // EBool
    assert_eq!(const_val(&pg, 0), 1); // true
}

// ── Constants for all scalar widths ──

#[encrypt_fn_graph]
fn const_u8() -> EUint8 {
    EUint8::from(255u8)
}

#[encrypt_fn_graph]
fn const_u16() -> EUint16 {
    EUint16::from(65535u16)
}

#[encrypt_fn_graph]
fn const_u64() -> EUint64 {
    EUint64::from(18446744073709551615u64)
}

#[encrypt_fn_graph]
fn const_u128() -> EUint128 {
    EUint128::from(340282366920938463463374607431768211455u128)
}

#[encrypt_fn_graph]
fn const_address() -> EAddress {
    EAddress::from(0xDEADBEEFu128)
}

#[test]
fn test_scalar_constants() {
    // u8 max
    let data = const_u8();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let n = pg.node_bytes();
    assert_eq!(h.num_nodes(), 2);
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 1); // EUint8
    assert_eq!(const_val(&pg, 0), 255);

    // u16 max
    let data = const_u16();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 2); // EUint16
    assert_eq!(const_val(&pg, 0), 65535);

    // u64 max
    let data = const_u64();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 4); // EUint64
    assert_eq!(const_val(&pg, 0), u64::MAX as u128);

    // u128 max
    let data = const_u128();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 5); // EUint128
    assert_eq!(const_val(&pg, 0), u128::MAX);

    // address
    let data = const_address();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 7); // EAddress
    assert_eq!(const_val(&pg, 0), 0xDEADBEEF);
}

// ── Constants with arithmetic ──

#[encrypt_fn_graph]
fn add_constant_u8(x: EUint8) -> EUint8 {
    let ten = EUint8::from(10u8);
    x + ten
}

#[encrypt_fn_graph]
fn mul_constant_u64(x: EUint64) -> EUint64 {
    let factor = EUint64::from(100u64);
    x * factor
}

#[test]
fn test_constant_arithmetic() {
    let data = add_constant_u8();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let n = pg.node_bytes();
    assert_eq!(h.num_inputs(), 1);
    assert_eq!(h.num_ops(), 1);
    let _cst = get_node(n, 1).unwrap();
    assert_eq!(const_val(&pg, 1), 10);

    let data = mul_constant_u64();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let n = pg.node_bytes();
    assert_eq!(h.num_inputs(), 1);
    assert_eq!(h.num_ops(), 1);
    let _cst = get_node(n, 1).unwrap();
    assert_eq!(const_val(&pg, 1), 100);
    let mul = get_node(n, 2).unwrap();
    assert_eq!(mul.op_type(), 1); // Multiply
}

// ── Multiple constants in one graph ──

#[encrypt_fn_graph]
fn multi_const(x: EUint32) -> EUint32 {
    let a = EUint32::from(10u32);
    let b = EUint32::from(20u32);
    let sum = a + b;
    x * sum
}

#[test]
fn test_multiple_constants() {
    let data = multi_const();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let _n = pg.node_bytes();
    assert_eq!(h.num_inputs(), 1);
    assert_eq!(h.num_ops(), 2); // add, mul
                                // Node 0: input x, Node 1: const 10, Node 2: const 20,
                                // Node 3: add(1,2), Node 4: mul(0,3), Node 5: output
    assert_eq!(h.num_nodes(), 6);
    assert_eq!(const_val(&pg, 1), 10);
    assert_eq!(const_val(&pg, 2), 20);
}

// ── Vector type constants ──

#[encrypt_fn_graph]
fn const_vec_bool() -> E8BitVector {
    E8BitVector::from(0b10101010u128)
}

#[encrypt_fn_graph]
fn const_vec_u32() -> EUint32Vector {
    EUint32Vector::from(42u128)
}

#[encrypt_fn_graph]
fn const_vec_u64() -> EUint64Vector {
    EUint64Vector::from(0u128)
}

#[test]
fn test_vector_constants() {
    // Boolean vector
    let data = const_vec_bool();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let n = pg.node_bytes();
    assert_eq!(h.num_nodes(), 2); // constant + output
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.kind(), GraphNodeKind::Constant as u8);
    assert_eq!(c.fhe_type(), 18); // E8BitVector
    assert_eq!(const_val(&pg, 0), 0b10101010);

    // Arithmetic vector u32
    let data = const_vec_u32();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 34); // EUint32Vector
    assert_eq!(const_val(&pg, 0), 42);

    // Arithmetic vector u64 (zero)
    let data = const_vec_u64();
    let pg = parse_graph(&data).unwrap();
    let n = pg.node_bytes();
    let c = get_node(n, 0).unwrap();
    assert_eq!(c.fhe_type(), 35); // EUint64Vector
    assert_eq!(const_val(&pg, 0), 0);
}

// ── Vector constants with ops ──

#[encrypt_fn_graph]
fn vec_add_const(v: EUint32Vector) -> EUint32Vector {
    let c = EUint32Vector::from(1u128);
    v + c
}

#[test]
fn test_vector_constant_arithmetic() {
    let data = vec_add_const();
    let pg = parse_graph(&data).unwrap();
    let h = pg.header();
    let n = pg.node_bytes();
    assert_eq!(h.num_inputs(), 1);
    assert_eq!(h.num_ops(), 1);
    assert_eq!(h.num_outputs(), 1);
    let cst = get_node(n, 1).unwrap();
    assert_eq!(cst.fhe_type(), 34); // EUint32Vector
    assert_eq!(const_val(&pg, 1), 1);
    let add = get_node(n, 2).unwrap();
    assert_eq!(add.op_type(), 0); // Add
    assert_eq!(add.fhe_type(), 34); // EUint32Vector
}

// ── from_elements: arithmetic vectors ──

#[encrypt_fn_graph]
fn vec_u32_from_elements() -> EUint32Vector {
    EUint32Vector::from_elements([1u32, 2, 3, 4])
}

#[test]
fn test_from_elements_u32() {
    let data = vec_u32_from_elements();
    let pg = parse_graph(&data).unwrap();
    // 4 elements × 4 bytes = 16 bytes in constants
    assert_eq!(pg.constants().len(), 16);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 16).unwrap();
    // Element 0 = 1u32 LE
    assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 1);
    // Element 1 = 2u32 LE
    assert_eq!(u32::from_le_bytes(raw[4..8].try_into().unwrap()), 2);
    // Element 2 = 3
    assert_eq!(u32::from_le_bytes(raw[8..12].try_into().unwrap()), 3);
    // Element 3 = 4
    assert_eq!(u32::from_le_bytes(raw[12..16].try_into().unwrap()), 4);
}

#[encrypt_fn_graph]
fn vec_u64_from_elements() -> EUint64Vector {
    EUint64Vector::from_elements([100u64, 200, 300])
}

#[test]
fn test_from_elements_u64() {
    let data = vec_u64_from_elements();
    let pg = parse_graph(&data).unwrap();
    // 3 elements × 8 bytes = 24 bytes
    assert_eq!(pg.constants().len(), 24);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 24).unwrap();
    assert_eq!(u64::from_le_bytes(raw[0..8].try_into().unwrap()), 100);
    assert_eq!(u64::from_le_bytes(raw[8..16].try_into().unwrap()), 200);
    assert_eq!(u64::from_le_bytes(raw[16..24].try_into().unwrap()), 300);
}

// ── splat: fill all elements with same value ──

#[encrypt_fn_graph]
fn vec_u32_splat() -> EUint32Vector {
    EUint32Vector::splat(42u128)
}

#[test]
fn test_splat_u32() {
    let data = vec_u32_splat();
    let pg = parse_graph(&data).unwrap();
    // EUint32Vector: 2048 elements × 4 bytes = 8192 bytes
    assert_eq!(pg.constants().len(), 8192);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 8192).unwrap();
    // Every 4-byte chunk should be 42u32 LE
    for i in 0..2048 {
        let off = i * 4;
        assert_eq!(
            u32::from_le_bytes(raw[off..off + 4].try_into().unwrap()),
            42,
            "element {i}"
        );
    }
}

#[encrypt_fn_graph]
fn vec_u8_splat() -> EUint8Vector {
    EUint8Vector::splat(0xFFu128)
}

#[test]
fn test_splat_u8() {
    let data = vec_u8_splat();
    let pg = parse_graph(&data).unwrap();
    // EUint8Vector: 8192 elements × 1 byte = 8192
    assert_eq!(pg.constants().len(), 8192);
    let raw = encrypt_types::graph::get_constant(pg.constants(), 0, 8192).unwrap();
    assert!(raw.iter().all(|&b| b == 0xFF));
}

// ── Bool vector from bitmask ──

#[encrypt_fn_graph]
fn bvec_from_bitmask() -> E16BitVector {
    E16BitVector::from(0b1010101010101010u128)
}

#[test]
fn test_bool_vector_bitmask() {
    let data = bvec_from_bitmask();
    let pg = parse_graph(&data).unwrap();
    // E16BitVector = 2 bytes
    assert_eq!(pg.constants().len(), 2);
    assert_eq!(const_val(&pg, 0), 0b1010101010101010);
}

// ── splat + arithmetic ──

#[encrypt_fn_graph]
fn vec_splat_add(v: EUint64Vector) -> EUint64Vector {
    let ones = EUint64Vector::splat(1u128);
    v + ones
}

#[test]
fn test_splat_with_arithmetic() {
    let data = vec_splat_add();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 1);
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.header().num_outputs(), 1);
    // EUint64Vector: 1024 elements × 8 bytes = 8192
    assert_eq!(pg.constants().len(), 8192);
}

// ── Large-element vectors (elem > 16 bytes) ──

#[encrypt_fn_graph]
fn vec_u256_splat() -> EUint256Vector {
    EUint256Vector::splat([0xABu8; 32])
}

#[test]
fn test_splat_u256_vector() {
    let data = vec_u256_splat();
    let pg = parse_graph(&data).unwrap();
    // EUint256Vector: 256 elements × 32 bytes = 8192
    assert_eq!(pg.constants().len(), 8192);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    assert_eq!(node.fhe_type(), 37); // EUint256Vector
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 8192).unwrap();
    // Every 32-byte chunk should be [0xAB; 32]
    for i in 0..256 {
        let off = i * 32;
        assert!(raw[off..off + 32].iter().all(|&b| b == 0xAB), "element {i}");
    }
}

#[encrypt_fn_graph]
fn vec_u512_splat() -> EUint512Vector {
    EUint512Vector::splat([0u8; 64])
}

#[test]
fn test_splat_u512_vector() {
    let data = vec_u512_splat();
    let pg = parse_graph(&data).unwrap();
    // EUint512Vector: 128 elements × 64 bytes = 8192
    assert_eq!(pg.constants().len(), 8192);
}

#[encrypt_fn_graph]
fn vec_u256_from_elements() -> EUint256Vector {
    EUint256Vector::from_elements([[1u8; 32], [2u8; 32]])
}

#[test]
fn test_from_elements_u256_vector() {
    let data = vec_u256_from_elements();
    let pg = parse_graph(&data).unwrap();
    // 2 elements × 32 bytes = 64
    assert_eq!(pg.constants().len(), 64);
    let raw = encrypt_types::graph::get_constant(pg.constants(), 0, 64).unwrap();
    // Element 0: all 1s
    assert!(raw[0..32].iter().all(|&b| b == 1));
    // Element 1: all 2s
    assert!(raw[32..64].iter().all(|&b| b == 2));
}

// ── Big type constants (> 128 bits) ──

#[encrypt_fn_graph]
fn const_u256_scalar() -> EUint256 {
    EUint256::from(0xCAFEBABEu128)
}

#[encrypt_fn_graph]
fn const_u256_bytes() -> EUint256 {
    EUint256::from([0xABu8; 32])
}

#[encrypt_fn_graph]
fn const_u512_bytes() -> EUint512 {
    EUint512::from([0u8; 64])
}

#[encrypt_fn_graph]
fn const_u256_explicit() -> EUint256 {
    EUint256::from([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ])
}

#[encrypt_fn_graph]
fn big_type_arithmetic(a: EUint256, b: EUint256) -> EUint256 {
    let one = EUint256::from(1u128);
    a + one
}

#[test]
fn test_big_type_scalar_constant() {
    let data = const_u256_scalar();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.constants().len(), 32);
    assert_eq!(const_val(&pg, 0), 0xCAFEBABE);
    // Upper 16 bytes are zero
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 32).unwrap();
    assert!(raw[16..32].iter().all(|&b| b == 0));
}

#[test]
fn test_big_type_bytes_repeat() {
    // [0xAB; 32] → 32 bytes all 0xAB
    let data = const_u256_bytes();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.constants().len(), 32);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 32).unwrap();
    assert!(raw.iter().all(|&b| b == 0xAB));
}

#[test]
fn test_big_type_bytes_explicit() {
    // [1, 2, 3, ..., 32]
    let data = const_u256_explicit();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.constants().len(), 32);
    let node = get_node(pg.node_bytes(), 0).unwrap();
    let raw = encrypt_types::graph::get_constant(pg.constants(), node.const_offset(), 32).unwrap();
    for (i, byte) in raw.iter().enumerate().take(32) {
        assert_eq!(*byte, (i + 1) as u8);
    }
}

#[test]
fn test_u512_bytes_constant() {
    let data = const_u512_bytes();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.constants().len(), 64);
}

#[test]
fn test_big_type_arithmetic() {
    let data = big_type_arithmetic();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.constants().len(), 32);
    assert_eq!(const_val(&pg, 2), 1);
}

// ── Big type constant with raw bytes (builder API) ──

#[test]
fn test_constant_bytes_via_builder() {
    use encrypt_dsl::graph::GraphBuilder;
    let mut gb = GraphBuilder::new();

    let mut val = [0u8; 32];
    val[0] = 0xFF;
    val[31] = 0xAA;
    gb.add_constant_bytes(6, &val);
    gb.add_output(6, 0);

    let data = gb.serialize();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.constants().len(), 32);
    let raw = encrypt_types::graph::get_constant(pg.constants(), 0, 32).unwrap();
    assert_eq!(raw[0], 0xFF);
    assert_eq!(raw[31], 0xAA);
}

// ── Scalar-vector type connection ──
// EncryptedVector<FHE_TYPE, T, SIZE> shares T with Encrypted<T>,
// enabling typed ops like gather(vec) → scalar, scatter(scalar) → vec.

#[encrypt_fn_graph]
fn vec_and_scalar_same_graph(scalar: EUint32, vec: EUint32Vector) -> (EUint32, EUint32Vector) {
    // Arithmetic on vector uses same Add op as scalar
    let vec_inc = vec + vec;
    // Scalar arithmetic in the same graph
    let scalar_inc = scalar + scalar;
    (scalar_inc, vec_inc)
}

#[test]
fn test_vec_and_scalar_same_graph() {
    let data = vec_and_scalar_same_graph();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 2); // vec add + scalar add
    assert_eq!(pg.header().num_outputs(), 2);

    // Input 0: scalar EUint32 (type 3)
    let n0 = get_node(pg.node_bytes(), 0).unwrap();
    assert_eq!(n0.fhe_type(), 3);

    // Input 1: vector EUint32Vector (type 34)
    let n1 = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(n1.fhe_type(), 34);

    // Op on vector preserves vector type (34)
    let vec_op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(vec_op.fhe_type(), 34);
    assert_eq!(vec_op.op_type(), 0); // Add

    // Op on scalar preserves scalar type (3)
    let scalar_op = get_node(pg.node_bytes(), 3).unwrap();
    assert_eq!(scalar_op.fhe_type(), 3);
    assert_eq!(scalar_op.op_type(), 0); // Add
}

#[encrypt_fn_graph]
fn bitvec_boolean_ops(a: E8BitVector, b: E8BitVector) -> E8BitVector {
    a ^ b
}

#[test]
fn test_bitvec_boolean_ops() {
    let data = bitvec_boolean_ops();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.header().num_outputs(), 1);

    // Inputs are E8BitVector (type 18 = EncryptedVector<18, Bool, 8>)
    let n0 = get_node(pg.node_bytes(), 0).unwrap();
    assert_eq!(n0.fhe_type(), 18);

    // XOR op preserves bit vector type
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 20); // Xor
    assert_eq!(op.fhe_type(), 18); // still E8BitVector
}

#[encrypt_fn_graph]
fn bitvec_and_bool_graph(
    bits: E16BitVector,
    flag: EBool,
    val_a: E16BitVector,
    val_b: E16BitVector,
) -> E16BitVector {
    // Bool (scalar) used as condition, bit vector (vector of Bool) as branches
    let masked = bits & val_a;
    if flag {
        masked
    } else {
        val_b
    }
}

#[test]
fn test_bitvec_and_bool_graph() {
    let data = bitvec_and_bool_graph();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 4);
    assert_eq!(pg.header().num_ops(), 2); // AND + Select
    assert_eq!(pg.header().num_outputs(), 1);

    // Input 0: E16BitVector (type 19)
    assert_eq!(get_node(pg.node_bytes(), 0).unwrap().fhe_type(), 19);
    // Input 1: EBool (type 0)
    assert_eq!(get_node(pg.node_bytes(), 1).unwrap().fhe_type(), 0);

    // AND op on bit vectors (type 19)
    let and_op = get_node(pg.node_bytes(), 4).unwrap();
    assert_eq!(and_op.op_type(), 21); // And
    assert_eq!(and_op.fhe_type(), 19);

    // Select op uses Bool condition, bit vector result
    let sel = get_node(pg.node_bytes(), 5).unwrap();
    assert_eq!(sel.op_type(), 60); // Select
    assert_eq!(sel.input_a(), 1); // flag (Bool)
}

#[encrypt_fn_graph]
fn mixed_vector_sizes(a: EUint8Vector, b: EUint64Vector) -> (EUint8Vector, EUint64Vector) {
    let a2 = a + a;
    let b2 = b + b;
    (a2, b2)
}

#[test]
fn test_mixed_vector_sizes() {
    let data = mixed_vector_sizes();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 2);
    assert_eq!(pg.header().num_outputs(), 2);

    // EUint8Vector = type 32, SIZE=8192
    assert_eq!(get_node(pg.node_bytes(), 0).unwrap().fhe_type(), 32);
    // EUint64Vector = type 35, SIZE=1024
    assert_eq!(get_node(pg.node_bytes(), 1).unwrap().fhe_type(), 35);

    // Ops preserve their respective types
    assert_eq!(get_node(pg.node_bytes(), 2).unwrap().fhe_type(), 32);
    assert_eq!(get_node(pg.node_bytes(), 3).unwrap().fhe_type(), 35);
}

/// Verify that the unified type aliases have correct FHE type IDs
/// and that EncryptedVector<FHE_TYPE, T, SIZE> is 8 bytes for all variants.
#[test]
fn test_type_alias_fhe_ids() {
    use core::mem::size_of;
    use encrypt_types::encrypted::*;

    // All vector types are 32 bytes (same as scalars)
    assert_eq!(size_of::<EUint8Vector>(), 32);
    assert_eq!(size_of::<EUint64Vector>(), 32);
    assert_eq!(size_of::<E8BitVector>(), 32);
    assert_eq!(size_of::<E64BitVector>(), 32);

    // Scalar and its vector share the same marker type
    // (verified by constructing both from the same marker)
    let _scalar: Encrypted<Uint32> = Encrypted::new([1u8; 32]);
    let _vector: EncryptedVector<34, Uint32, 2048> = EncryptedVector::new([2u8; 32]);
    let _bitvec: EncryptedVector<18, Bool, 8> = EncryptedVector::new([3u8; 32]);

    // Marker types carry scalar FHE type IDs
    assert_eq!(Uint32::FHE_TYPE_ID, 3);
    assert_eq!(Bool::FHE_TYPE_ID, 0);
}

// ── Comparison operators ──

#[encrypt_fn_graph]
fn all_comparisons(
    a: EUint32,
    b: EUint32,
) -> (EUint32, EUint32, EUint32, EUint32, EUint32, EUint32) {
    let lt = a < b;
    let le = a <= b;
    let gt = a > b;
    let ge = a >= b;
    let eq = a == b;
    let ne = a != b;
    (lt, le, gt, ge, eq, ne)
}

#[test]
fn test_all_comparison_operators() {
    let data = all_comparisons();
    let pg = parse_graph(&data).expect("valid graph");
    let header = pg.header();
    let nodes = pg.node_bytes();

    assert_eq!(header.num_inputs(), 2);
    assert_eq!(header.num_ops(), 6);
    assert_eq!(header.num_outputs(), 6);

    // Verify op types: lt=40, le=45, gt=43, ge=44, eq=41, ne=42
    let expected_ops = [40u8, 45, 43, 44, 41, 42];
    for (i, &expected_op) in expected_ops.iter().enumerate() {
        let node = get_node(nodes, (2 + i) as u16).unwrap();
        assert_eq!(node.op_type(), expected_op, "comparison op {i}");
    }
}

// ══════════════════════════════════════════════════════════════
// REFHE Full Operation Coverage Tests
// ══════════════════════════════════════════════════════════════

// ── Blend (ternary arithmetic) ──

#[encrypt_fn_graph]
fn test_blend_fn(mask: EUint32, a: EUint32, b: EUint32) -> EUint32 {
    mask.blend(&a, &b)
}

#[test]
fn test_blend() {
    let data = test_blend_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 3);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 3).unwrap();
    assert_eq!(op.op_type(), 8); // Blend
    assert_eq!(op.input_a(), 0); // mask
    assert_eq!(op.input_b(), 1); // a
    assert_eq!(op.input_c(), 2); // b
}

// ── Arithmetic scalar ops ──

#[encrypt_fn_graph]
fn test_add_scalar_fn(v: EUint32Vector, s: EUint32) -> EUint32Vector {
    v.add(&s)
}

#[encrypt_fn_graph]
fn test_all_arith_scalar_fn(
    v: EUint64Vector,
    s: EUint64,
) -> (
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
) {
    let a = v.add(&s);
    let b = v.multiply(&s);
    let c = v.subtract(&s);
    let d = v.divide(&s);
    let e = v.modulo(&s);
    let f = v.min(&s);
    let g = v.max(&s);
    (a, b, c, d, e, f, g)
}

#[test]
fn test_arithmetic_scalar_ops() {
    let data = test_add_scalar_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 9); // AddScalar
    assert_eq!(op.fhe_type(), 34); // EUint32Vector

    // All 7 scalar ops
    let data = test_all_arith_scalar_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 7);
    let expected = [9u8, 10, 11, 12, 13, 14, 15]; // AddScalar..MaxScalar
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "arith scalar op {i}");
    }
}

// ── Boolean scalar ops ──

#[encrypt_fn_graph]
fn test_bool_scalar_ops(v: E8BitVector, s: EBool) -> (E8BitVector, E8BitVector, E8BitVector) {
    let a = v.and(&s);
    let b = v.or(&s);
    let c = v.xor(&s);
    (a, b, c)
}

#[test]
fn test_boolean_scalar_ops() {
    let data = test_bool_scalar_ops();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 3);
    let expected = [30u8, 31, 32]; // AndScalar, OrScalar, XorScalar
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "bool scalar op {i}");
    }
}

// ── Comparison scalar ops ──

#[encrypt_fn_graph]
fn test_cmp_scalar_ops(
    v: EUint32Vector,
    s: EUint32,
) -> (
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
) {
    let a = v.is_less_than(&s);
    let b = v.is_equal(&s);
    let c = v.is_not_equal(&s);
    let d = v.is_greater_than(&s);
    let e = v.is_greater_or_equal(&s);
    let f = v.is_less_or_equal(&s);
    (a, b, c, d, e, f)
}

#[test]
fn test_comparison_scalar_ops() {
    let data = test_cmp_scalar_ops();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 6);
    let expected = [46u8, 47, 48, 49, 50, 51];
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "cmp scalar op {i}");
    }
}

// ── Select scalar (ternary) ──

#[encrypt_fn_graph]
fn test_select_scalar_fn(cond: EUint32Vector, v: EUint32Vector, s: EUint32) -> EUint32Vector {
    cond.select_scalar(&v, &s)
}

#[test]
fn test_select_scalar() {
    let data = test_select_scalar_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 3);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 3).unwrap();
    assert_eq!(op.op_type(), 61); // SelectScalar
}

// ── Conversion ops ──

#[encrypt_fn_graph]
fn test_bootstrap_fn(a: EUint64) -> EUint64 {
    a.bootstrap()
}

#[encrypt_fn_graph]
fn test_to_boolean_fn(a: EUint32) -> EBool {
    a.to_boolean()
}

#[test]
fn test_conversion_ops() {
    // bootstrap — unary, preserves type
    let data = test_bootstrap_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(op.op_type(), 85); // Bootstrap
    assert_eq!(op.fhe_type(), 4); // EUint64 preserved
    assert_eq!(op.input_b(), 0xFFFF); // unary

    // to_boolean — unary, result = EBool (type 0)
    let data = test_to_boolean_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(op.op_type(), 83); // ToBoolean
    assert_eq!(op.fhe_type(), 0); // EBool
}

// ── Into (scalar conversion) ──

#[encrypt_fn_graph]
fn test_scalar_into_fn(narrow: EUint8) -> EUint32 {
    EUint32::into(narrow)
}

#[encrypt_fn_graph]
fn test_vector_into_fn(v: EUint8Vector) -> EUint16Vector {
    EUint16Vector::into(v)
}

#[test]
fn test_into_conversion() {
    // Scalar into: EUint8 → EUint32
    let data = test_scalar_into_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 1);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(op.op_type(), 82); // Into
    assert_eq!(op.fhe_type(), 3); // target type = EUint32
    assert_eq!(op.input_a(), 0); // source
    assert_eq!(op.input_b(), 0xFFFF); // unary

    // Vector into: EUint8Vector → EUint16Vector
    let data = test_vector_into_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 1);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(op.op_type(), 82); // Into
    assert_eq!(op.fhe_type(), 33); // target type = EUint16Vector
}

// ── Vector ops via method syntax ──

#[encrypt_fn_graph]
fn test_vector_gather_fn(v: EUint32Vector, idx: EUint32Vector) -> EUint32Vector {
    v.gather(&idx)
}

#[encrypt_fn_graph]
fn test_vector_scatter_fn(v: EUint32Vector, idx: EUint32Vector) -> EUint32Vector {
    v.scatter(&idx)
}

#[encrypt_fn_graph]
fn test_vector_get_fn(v: EUint64Vector, idx: EUint64Vector) -> EUint64Vector {
    v.get(&idx)
}

#[test]
fn test_vector_ops() {
    // gather
    let data = test_vector_gather_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 90); // Gather

    // scatter
    let data = test_vector_scatter_fn();
    let pg = parse_graph(&data).unwrap();
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 91); // Scatter

    // get
    let data = test_vector_get_fn();
    let pg = parse_graph(&data).unwrap();
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 95); // Get
}

// ── Extract LSBs / MSBs as binary ops (num_bits passed as encrypted constant) ──

#[encrypt_fn_graph]
fn test_extract_lsbs_fn(val: EUint32, nbits: EUint32) -> EUint32 {
    val.extract_lsbs(&nbits)
}

#[encrypt_fn_graph]
fn test_extract_msbs_fn(val: EUint32, nbits: EUint32) -> EUint32 {
    val.extract_msbs(&nbits)
}

#[test]
fn test_extract_bits() {
    let data = test_extract_lsbs_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 80); // ExtractLsbs

    let data = test_extract_msbs_fn();
    let pg = parse_graph(&data).unwrap();
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 84); // ExtractMsbs
}

// ── Full arithmetic method coverage on scalars ──

#[encrypt_fn_graph]
fn test_all_arith_methods(
    a: EUint64,
    b: EUint64,
) -> (
    EUint64,
    EUint64,
    EUint64,
    EUint64,
    EUint64,
    EUint64,
    EUint64,
    EUint64,
) {
    let r0 = a.add(&b);
    let r1 = a.multiply(&b);
    let r2 = a.negate();
    let r3 = a.subtract(&b);
    let r4 = a.divide(&b);
    let r5 = a.modulo(&b);
    let r6 = a.min(&b);
    let r7 = a.max(&b);
    (r0, r1, r2, r3, r4, r5, r6, r7)
}

#[test]
fn test_all_arithmetic_methods() {
    let data = test_all_arith_methods();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 8);
    let expected = [0u8, 1, 2, 3, 4, 5, 6, 7]; // Add..Max
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "arith op {i}");
    }
}

// ── Full boolean method coverage ──

#[encrypt_fn_graph]
fn test_all_bool_methods(
    a: EUint32,
    b: EUint32,
) -> (
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
    EUint32,
) {
    let r0 = a.xor(&b);
    let r1 = a.and(&b);
    let r2 = a.not();
    let r3 = a.or(&b);
    let r4 = a.nor(&b);
    let r5 = a.nand(&b);
    let r6 = a.shift_left(&b);
    let r7 = a.shift_right(&b);
    let r8 = a.rotate_left(&b);
    let r9 = a.rotate_right(&b);
    (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9)
}

#[test]
fn test_all_boolean_methods() {
    let data = test_all_bool_methods();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 10);
    let expected = [20u8, 21, 22, 23, 24, 25, 26, 27, 28, 29];
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "bool op {i}");
    }
}

// ── Assign and copy via method syntax ──

#[encrypt_fn_graph]
fn test_assign_fn(v: EUint32Vector, idx: EUint32Vector, vals: EUint32Vector) -> EUint32Vector {
    v.assign(&idx, &vals)
}

#[encrypt_fn_graph]
fn test_copy_fn(v: EUint32Vector, src: EUint32Vector) -> EUint32Vector {
    v.copy(&src)
}

#[test]
fn test_assign_and_copy() {
    // assign — ternary
    let data = test_assign_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 3);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 3).unwrap();
    assert_eq!(op.op_type(), 92); // Assign

    // copy — binary
    let data = test_copy_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 94); // Copy
}

// ── pack_into as unary ──

#[encrypt_fn_graph]
fn test_pack_into_fn(bits: E8BitVector) -> E8BitVector {
    bits.pack_into()
}

#[test]
fn test_pack_into() {
    let data = test_pack_into_fn();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(op.op_type(), 81); // PackInto
    assert_eq!(op.input_b(), 0xFFFF); // unary
}

// ══════════════════════════════════════════════════════════════
// Operator syntax for scalar ops (vector OP scalar → scalar variant)
// ══════════════════════════════════════════════════════════════

#[encrypt_fn_graph]
fn test_vec_plus_scalar(v: EUint32Vector, s: EUint32) -> EUint32Vector {
    v + s
}

#[encrypt_fn_graph]
fn test_vec_arith_scalar_ops(
    v: EUint64Vector,
    s: EUint64,
) -> (
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
    EUint64Vector,
) {
    let a = v + s;
    let b = v * s;
    let c = v - s;
    let d = v / s;
    let e = v % s;
    (a, b, c, d, e)
}

#[test]
fn test_operator_scalar_arithmetic() {
    // Single: v + s → AddScalar
    let data = test_vec_plus_scalar();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 9); // AddScalar (auto-promoted from Add)
    assert_eq!(op.fhe_type(), 34); // result = EUint32Vector

    // All 5 arithmetic scalar ops via operators
    let data = test_vec_arith_scalar_ops();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 5);
    let expected = [9u8, 10, 11, 12, 13]; // AddScalar, MulScalar, SubScalar, DivScalar, ModScalar
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "arith scalar operator {i}");
    }
}

#[encrypt_fn_graph]
fn test_bitvec_bool_scalar_ops(
    v: E8BitVector,
    s: EBool,
) -> (E8BitVector, E8BitVector, E8BitVector) {
    let a = v & s;
    let b = v | s;
    let c = v ^ s;
    (a, b, c)
}

#[test]
fn test_operator_scalar_boolean() {
    let data = test_bitvec_bool_scalar_ops();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 3);
    let expected = [30u8, 31, 32]; // AndScalar, OrScalar, XorScalar
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "bool scalar operator {i}");
    }
}

#[encrypt_fn_graph]
fn test_vec_cmp_scalar_ops(
    v: EUint32Vector,
    s: EUint32,
) -> (
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
    EUint32Vector,
) {
    let a = v < s;
    let b = v <= s;
    let c = v > s;
    let d = v >= s;
    let e = v == s;
    let f = v != s;
    (a, b, c, d, e, f)
}

#[test]
fn test_operator_scalar_comparison() {
    let data = test_vec_cmp_scalar_ops();
    let pg = parse_graph(&data).unwrap();
    assert_eq!(pg.header().num_ops(), 6);
    let expected = [46u8, 51, 49, 50, 47, 48]; // lt, le, gt, ge, eq, ne scalar variants
    for (i, &exp) in expected.iter().enumerate() {
        let op = get_node(pg.node_bytes(), (2 + i) as u16).unwrap();
        assert_eq!(op.op_type(), exp, "cmp scalar operator {i}");
    }
}

/// Verify that scalar+scalar still uses base ops (no false promotion)
#[encrypt_fn_graph]
fn test_scalar_plus_scalar(a: EUint64, b: EUint64) -> EUint64 {
    a + b
}

#[test]
fn test_no_false_scalar_promotion() {
    let data = test_scalar_plus_scalar();
    let pg = parse_graph(&data).unwrap();
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 0); // Add, NOT AddScalar
}

/// Verify that vector+vector still uses base ops (no false promotion)
#[encrypt_fn_graph]
fn test_vec_plus_vec(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    a + b
}

#[test]
fn test_no_false_vector_promotion() {
    let data = test_vec_plus_vec();
    let pg = parse_graph(&data).unwrap();
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 0); // Add, NOT AddScalar
}

// ══════════════════════════════════════════════════════════════
// Plaintext input parameters (P-types)
// ══════════════════════════════════════════════════════════════

/// Plaintext param generates PlaintextInput node (kind=1) instead of Input (kind=0)
#[encrypt_fn_graph]
fn test_plaintext_param_fn(balance: EUint64, amount: PUint64) -> EUint64 {
    balance - amount
}

#[test]
fn test_plaintext_param() {
    let data = test_plaintext_param_fn();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 1); // 1 encrypted input
    assert_eq!(pg.header().num_plaintext_inputs(), 1); // 1 plaintext input
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.header().num_outputs(), 1);

    // Node 0: Input (encrypted balance)
    let n0 = get_node(pg.node_bytes(), 0).unwrap();
    assert_eq!(n0.kind(), GraphNodeKind::Input as u8);
    assert_eq!(n0.fhe_type(), 4); // EUint64

    // Node 1: PlaintextInput (plaintext amount)
    let n1 = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(n1.kind(), GraphNodeKind::PlaintextInput as u8);
    assert_eq!(n1.fhe_type(), 4); // same FHE type as EUint64

    // Node 2: Subtract op uses both inputs
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 3); // Subtract
    assert_eq!(op.input_a(), 0); // balance (encrypted)
    assert_eq!(op.input_b(), 1); // amount (plaintext)
}

/// Multiple plaintext params
#[encrypt_fn_graph]
fn test_multi_plaintext_fn(a: EUint32, b: PUint32, c: PUint32) -> EUint32 {
    let sum = b + c;
    a + sum
}

#[test]
fn test_multi_plaintext_params() {
    let data = test_multi_plaintext_fn();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 1); // a
    assert_eq!(pg.header().num_plaintext_inputs(), 2); // b, c
    assert_eq!(pg.header().num_ops(), 2);

    // Verify node kinds
    assert_eq!(
        get_node(pg.node_bytes(), 0).unwrap().kind(),
        GraphNodeKind::Input as u8
    );
    assert_eq!(
        get_node(pg.node_bytes(), 1).unwrap().kind(),
        GraphNodeKind::PlaintextInput as u8
    );
    assert_eq!(
        get_node(pg.node_bytes(), 2).unwrap().kind(),
        GraphNodeKind::PlaintextInput as u8
    );
}

/// All-plaintext inputs, encrypted output
#[encrypt_fn_graph]
fn test_all_plaintext_fn(a: PUint64, b: PUint64) -> EUint64 {
    a + b
}

#[test]
fn test_all_plaintext_inputs() {
    let data = test_all_plaintext_fn();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 0);
    assert_eq!(pg.header().num_plaintext_inputs(), 2);
    assert_eq!(pg.header().num_ops(), 1);
    assert_eq!(pg.header().num_outputs(), 1);
}

/// Plaintext vector param
#[encrypt_fn_graph]
fn test_plaintext_vec_fn(v: EUint32Vector, mask: PUint32Vector) -> EUint32Vector {
    v + mask
}

#[test]
fn test_plaintext_vector_param() {
    let data = test_plaintext_vec_fn();
    let pg = parse_graph(&data).unwrap();

    assert_eq!(pg.header().num_inputs(), 1);
    assert_eq!(pg.header().num_plaintext_inputs(), 1);

    let n0 = get_node(pg.node_bytes(), 0).unwrap();
    assert_eq!(n0.kind(), GraphNodeKind::Input as u8);
    assert_eq!(n0.fhe_type(), 34); // EUint32Vector

    let n1 = get_node(pg.node_bytes(), 1).unwrap();
    assert_eq!(n1.kind(), GraphNodeKind::PlaintextInput as u8);
    assert_eq!(n1.fhe_type(), 34); // same FHE type

    // Auto-promotes to Add (not AddScalar) since both are vectors
    let op = get_node(pg.node_bytes(), 2).unwrap();
    assert_eq!(op.op_type(), 0); // Add
}

/// Plaintext on-chain type sizes
#[test]
fn test_plaintext_type_sizes() {
    use core::mem::size_of;
    use encrypt_types::encrypted::*;

    assert_eq!(size_of::<PBool>(), 1);
    assert_eq!(size_of::<PUint8>(), 1);
    assert_eq!(size_of::<PUint32>(), 4);
    assert_eq!(size_of::<PUint64>(), 8);
    assert_eq!(size_of::<PUint128>(), 16);
    assert_eq!(size_of::<PUint256>(), 32);
    assert_eq!(size_of::<PUint32Vector>(), 8192);
    assert_eq!(size_of::<P8BitVector>(), 1);
    assert_eq!(size_of::<P64BitVector>(), 8);
}

/// Plaintext From impls
#[test]
fn test_plaintext_from_constructors() {
    use encrypt_types::encrypted::*;

    let p = PBool::from(true);
    assert_eq!(p.data(), &[1]);

    let p = PUint32::from(42u32);
    assert_eq!(p.data(), &42u32.to_le_bytes());

    let p = PUint64::from(100u64);
    assert_eq!(p.data(), &100u64.to_le_bytes());
}
