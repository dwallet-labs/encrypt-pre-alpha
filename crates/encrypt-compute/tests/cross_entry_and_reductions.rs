// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! E2E coverage for Cross-Entry and Reduction op categories added in the REFHE refresh:
//! - Reductions: ReduceAdd, ReduceMin, ReduceMax, ReduceAny, ReduceAll
//! - Cross-Entry: RotateEntries
//! - Cross-Entry / linear algebra: LinearTransform, LinearTransformPlaintext, LinearTransformBand
//!   (mock identity passthrough — full semantics need multi-operand graph IR)
//!
//! Each test builds a graph via `GraphBuilder`, evaluates it with `MockComputeEngine`,
//! and decrypts the result through the engine — exercising enum → graph → evaluator → mock
//! end to end.

use encrypt_compute::engine::ComputeEngine;
use encrypt_compute::evaluator::evaluate_graph;
use encrypt_compute::mock::MockComputeEngine;
use encrypt_dsl::graph::GraphBuilder;
use encrypt_types::types::{FheOperation, FheType};

const VEC_BYTES: usize = 8192;

fn make_u32_vector(values: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0u8; VEC_BYTES];
    for (i, v) in values.iter().enumerate() {
        let off = i * 4;
        bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

fn make_u64_vector(values: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0u8; VEC_BYTES];
    for (i, v) in values.iter().enumerate() {
        let off = i * 8;
        bytes[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

fn make_u8_vector(values: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; VEC_BYTES];
    bytes[..values.len()].copy_from_slice(values);
    bytes
}

fn build_unary_graph(op: FheOperation, input_type: FheType, result_type: FheType) -> Vec<u8> {
    let mut gb = GraphBuilder::new();
    let a = gb.add_input(input_type as u8);
    let r = gb.add_op(op as u8, result_type as u8, a, 0xFFFF);
    gb.add_output(result_type as u8, r);
    gb.serialize()
}

// ── Reductions ──

#[test]
fn reduce_add_u32_vector() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[10, 20, 30, 40, 50]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceAdd, FheType::EVectorU32, FheType::EUint32);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let bytes = engine.decrypt(&result.output_digests[0], FheType::EUint32).unwrap();
    let sum = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    assert_eq!(sum, 150, "reduce_add over [10,20,30,40,50] should be 150");
}

#[test]
fn reduce_min_u64_vector() {
    let mut engine = MockComputeEngine::new();
    // Initialize all entries to a high value, then sprinkle smaller ones
    let mut values = vec![u64::MAX; 1024];
    values[5] = 7;
    values[100] = 3;
    values[500] = 42;
    let v_bytes = make_u64_vector(&values);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU64, &v_bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceMin, FheType::EVectorU64, FheType::EUint64);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let bytes = engine.decrypt(&result.output_digests[0], FheType::EUint64).unwrap();
    let min = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    assert_eq!(min, 3, "reduce_min should find smallest entry");
}

#[test]
fn reduce_max_u32_vector() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[1, 5, 999, 42, 7]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceMax, FheType::EVectorU32, FheType::EUint32);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let bytes = engine.decrypt(&result.output_digests[0], FheType::EUint32).unwrap();
    let max = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    assert_eq!(max, 999, "reduce_max should find largest entry");
}

#[test]
fn reduce_any_finds_nonzero() {
    let mut engine = MockComputeEngine::new();
    let mut bytes = vec![0u8; VEC_BYTES];
    bytes[3000] = 1; // single nonzero byte buried in zeros
    let v = engine
        .encode_constant_bytes(FheType::EVectorU8, &bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceAny, FheType::EVectorU8, FheType::EBool);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let out = engine.decrypt(&result.output_digests[0], FheType::EBool).unwrap();
    assert_eq!(out[0], 1, "reduce_any over a vector with any nonzero should return 1");
}

#[test]
fn reduce_any_all_zero_returns_zero() {
    let mut engine = MockComputeEngine::new();
    let bytes = vec![0u8; VEC_BYTES];
    let v = engine
        .encode_constant_bytes(FheType::EVectorU8, &bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceAny, FheType::EVectorU8, FheType::EBool);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let out = engine.decrypt(&result.output_digests[0], FheType::EBool).unwrap();
    assert_eq!(out[0], 0, "reduce_any over all-zero vector should return 0");
}

#[test]
fn reduce_all_nonzero_returns_one() {
    let mut engine = MockComputeEngine::new();
    let bytes = make_u8_vector(&vec![1u8; VEC_BYTES]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU8, &bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceAll, FheType::EVectorU8, FheType::EBool);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let out = engine.decrypt(&result.output_digests[0], FheType::EBool).unwrap();
    assert_eq!(out[0], 1, "reduce_all over all-nonzero should return 1");
}

#[test]
fn reduce_all_one_zero_returns_zero() {
    let mut engine = MockComputeEngine::new();
    let mut bytes = vec![1u8; VEC_BYTES];
    bytes[42] = 0; // single zero entry
    let v = engine
        .encode_constant_bytes(FheType::EVectorU8, &bytes)
        .unwrap();

    let graph = build_unary_graph(FheOperation::ReduceAll, FheType::EVectorU8, FheType::EBool);
    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();

    let out = engine.decrypt(&result.output_digests[0], FheType::EBool).unwrap();
    assert_eq!(out[0], 0, "reduce_all should return 0 if any entry is zero");
}

#[test]
fn reduce_pipeline_max_minus_min() {
    // Compose: max(v) - min(v) — exercises that two reductions and one binary op
    // chain through the evaluator with correct intermediate types.
    // Fill every entry: reductions span the full ciphertext (2048 EUint32 entries),
    // so unfilled positions would be zero and skew min/max.
    let mut engine = MockComputeEngine::new();
    let mut values = vec![50u32; 2048];
    values[7] = 99;
    values[300] = 2;
    values[1500] = 14;
    let v_bytes = make_u32_vector(&values);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let max = gb.add_op(
        FheOperation::ReduceMax as u8,
        FheType::EUint32 as u8,
        a,
        0xFFFF,
    );
    let min = gb.add_op(
        FheOperation::ReduceMin as u8,
        FheType::EUint32 as u8,
        a,
        0xFFFF,
    );
    let diff = gb.add_op(
        FheOperation::Subtract as u8,
        FheType::EUint32 as u8,
        max,
        min,
    );
    gb.add_output(FheType::EUint32 as u8, diff);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EUint32).unwrap();
    let diff = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    assert_eq!(diff, 99 - 2, "max - min should be 97");
}

// ── Cross-Entry: RotateEntries ──

#[test]
fn rotate_entries_left_by_one() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[10, 20, 30, 40, 50]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    // Shift amount: 1 entry. Stored as a u32 so the scalar element width matches the vector.
    let shift = engine.encode_constant(FheType::EUint32, 1).unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let n = gb.add_input(FheType::EUint32 as u8);
    let r = gb.add_op(
        FheOperation::RotateEntries as u8,
        FheType::EVectorU32 as u8,
        a,
        n,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, shift]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();

    // Rotate left by 1 → out[i] = in[i+1]
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 20);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 30);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 40);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 50);
    // Position 4 (last set entry → wraps zero from rest of vector)
    assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 0);
}

#[test]
fn rotate_entries_zero_is_identity() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[1, 2, 3, 4]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    let shift = engine.encode_constant(FheType::EUint32, 0).unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let n = gb.add_input(FheType::EUint32 as u8);
    let r = gb.add_op(
        FheOperation::RotateEntries as u8,
        FheType::EVectorU32 as u8,
        a,
        n,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, shift]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();

    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 4);
}

#[test]
fn rotate_entries_full_count_wraps_to_identity() {
    let mut engine = MockComputeEngine::new();
    let values: Vec<u32> = (0..2048).map(|i| i as u32).collect();
    let v_bytes = make_u32_vector(&values);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    // EVectorU32 has 2048 entries; rotating by 2048 is identity.
    let shift = engine.encode_constant(FheType::EUint32, 2048).unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let n = gb.add_input(FheType::EUint32 as u8);
    let r = gb.add_op(
        FheOperation::RotateEntries as u8,
        FheType::EVectorU32 as u8,
        a,
        n,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, shift]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();

    for i in 0..2048usize {
        let off = i * 4;
        let expected = i as u32;
        let got = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        assert_eq!(got, expected, "entry {i} should be {expected} after full-count rotation");
    }
}

// ── Linear transforms (mock identity) ──
//
// The matrix for these ops is structurally a `Vec<V>` (rows) or `Vec<(i32, V)>`
// (band diagonals), which can't be expressed as a single ciphertext operand in the
// current binary graph IR. For this round, the mock returns the input unchanged
// (identity). These tests verify the wire path: enum variant accepted, graph
// node round-trips, evaluator dispatches, no panic.

#[test]
fn linear_transform_passthrough() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[3, 1, 4, 1, 5, 9, 2, 6]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    // Matrix placeholder: encoded as another vector (the mock ignores its content).
    let m = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let mat = gb.add_input(FheType::EVectorU32 as u8);
    let r = gb.add_op(
        FheOperation::LinearTransform as u8,
        FheType::EVectorU32 as u8,
        a,
        mat,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, m]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();
    // Mock returns input unchanged.
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 3);
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 9);
}

#[test]
fn linear_transform_plaintext_passthrough() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[7, 11, 13]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    let m = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let mat = gb.add_input(FheType::EVectorU32 as u8);
    let r = gb.add_op(
        FheOperation::LinearTransformPlaintext as u8,
        FheType::EVectorU32 as u8,
        a,
        mat,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, m]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 7);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 11);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 13);
}

#[test]
fn linear_transform_band_passthrough() {
    let mut engine = MockComputeEngine::new();
    let v_bytes = make_u32_vector(&[100, 200, 300]);
    let v = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();
    let m = engine
        .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
        .unwrap();

    let mut gb = GraphBuilder::new();
    let a = gb.add_input(FheType::EVectorU32 as u8);
    let diag = gb.add_input(FheType::EVectorU32 as u8);
    let r = gb.add_op(
        FheOperation::LinearTransformBand as u8,
        FheType::EVectorU32 as u8,
        a,
        diag,
    );
    gb.add_output(FheType::EVectorU32 as u8, r);
    let graph = gb.serialize();

    let result = evaluate_graph(&mut engine, &graph, &[v, m]).unwrap();
    let bytes = engine.decrypt(&result.output_digests[0], FheType::EVectorU32).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 100);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 200);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 300);
}

