// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Graph evaluator — evaluates a computation graph using a `ComputeEngine`.
//!
//! Extracted from the voting example's `run_mock()` pattern, generalized
//! to work with any `ComputeEngine` implementation.

use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
use encrypt_types::types::{FheOperation, FheType};

use crate::engine::{CiphertextDigest, ComputeEngine};

/// Result of evaluating a computation graph.
pub struct GraphEvalResult {
    /// Output digests, one per Output node in the graph.
    pub output_digests: Vec<CiphertextDigest>,
}

/// Errors that can occur during graph evaluation.
#[derive(Debug)]
pub enum EvalError<E: core::fmt::Debug> {
    /// Invalid graph binary data.
    InvalidGraph,
    /// Not enough input digests for the graph's Input nodes.
    NotEnoughInputs { expected: usize, got: usize },
    /// Unknown node kind encountered.
    UnknownNodeKind(u8),
    /// Invalid FHE type discriminant.
    InvalidFheType(u8),
    /// Node references an out-of-bounds operand index.
    InvalidNodeReference { node_index: usize, operand_index: usize },
    /// Compute engine error.
    Compute(E),
}

impl<E: core::fmt::Debug> core::fmt::Display for EvalError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidGraph => write!(f, "invalid graph binary"),
            Self::NotEnoughInputs { expected, got } => {
                write!(f, "expected {expected} inputs, got {got}")
            }
            Self::UnknownNodeKind(k) => write!(f, "unknown node kind: {k}"),
            Self::InvalidFheType(t) => write!(f, "invalid FHE type: {t}"),
            Self::InvalidNodeReference {
                node_index,
                operand_index,
            } => write!(f, "node {node_index} references invalid operand {operand_index}"),
            Self::Compute(e) => write!(f, "compute error: {e:?}"),
        }
    }
}

impl<E: core::fmt::Debug> std::error::Error for EvalError<E> {}

/// Evaluate a computation graph given input ciphertext digests.
///
/// `graph_data` is the serialized graph binary (from `GraphBuilder::serialize()`
/// or extracted from `execute_graph` instruction data).
///
/// `input_digests` provides the digest for each encrypted Input node, in order.
///
/// Returns one digest per Output node.
pub fn evaluate_graph<E: ComputeEngine>(
    engine: &mut E,
    graph_data: &[u8],
    input_digests: &[CiphertextDigest],
) -> Result<GraphEvalResult, EvalError<E::Error>> {
    let pg = parse_graph(graph_data).ok_or(EvalError::InvalidGraph)?;
    let header = pg.header();
    let num_nodes = header.num_nodes() as usize;
    let num_inputs = header.num_inputs() as usize;

    if input_digests.len() < num_inputs {
        return Err(EvalError::NotEnoughInputs {
            expected: num_inputs,
            got: input_digests.len(),
        });
    }

    let mut digests: Vec<CiphertextDigest> = Vec::with_capacity(num_nodes);
    let mut input_idx = 0usize;

    for i in 0..num_nodes {
        let node = get_node(pg.node_bytes(), i as u16).ok_or(EvalError::InvalidGraph)?;
        let ft = FheType::from_u8(node.fhe_type())
            .ok_or(EvalError::InvalidFheType(node.fhe_type()))?;

        let digest = match node.kind() {
            k if k == GraphNodeKind::Input as u8 => {
                let d = input_digests[input_idx];
                input_idx += 1;
                d
            }

            k if k == GraphNodeKind::PlaintextInput as u8 => {
                // PlaintextInput nodes use the same digest encoding as constants
                // The plaintext value should be provided as an input digest
                let d = input_digests[input_idx];
                input_idx += 1;
                d
            }

            k if k == GraphNodeKind::Constant as u8 => {
                let byte_width = ft.byte_width().min(16);
                let offset = node.const_offset() as usize;
                let mut buf = [0u8; 16];
                let constants = pg.constants();
                if offset + byte_width > constants.len() {
                    return Err(EvalError::InvalidGraph);
                }
                buf[..byte_width].copy_from_slice(&constants[offset..offset + byte_width]);
                let value = u128::from_le_bytes(buf);
                engine.encode_constant(ft, value).map_err(EvalError::Compute)?
            }

            k if k == GraphNodeKind::Op as u8 => {
                let a = node.input_a() as usize;
                let b = node.input_b() as usize;
                let c = node.input_c() as usize;

                if a >= digests.len() {
                    return Err(EvalError::InvalidNodeReference {
                        node_index: i,
                        operand_index: a,
                    });
                }

                if node.op_type() == FheOperation::Select as u8 {
                    // Ternary select: condition=a, if_true=b, if_false=c
                    if b >= digests.len() || c >= digests.len() {
                        return Err(EvalError::InvalidNodeReference {
                            node_index: i,
                            operand_index: b.max(c),
                        });
                    }
                    engine
                        .select(&digests[a], &digests[b], &digests[c])
                        .map_err(EvalError::Compute)?
                } else if b == 0xFFFF {
                    // Unary operation
                    let op = unsafe {
                        core::mem::transmute::<u8, FheOperation>(node.op_type())
                    };
                    engine
                        .unary_op(op, &digests[a], ft)
                        .map_err(EvalError::Compute)?
                } else {
                    // Binary operation
                    if b >= digests.len() {
                        return Err(EvalError::InvalidNodeReference {
                            node_index: i,
                            operand_index: b,
                        });
                    }
                    let op = unsafe {
                        core::mem::transmute::<u8, FheOperation>(node.op_type())
                    };
                    engine
                        .binary_op(op, &digests[a], &digests[b], ft)
                        .map_err(EvalError::Compute)?
                }
            }

            k if k == GraphNodeKind::Output as u8 => {
                let source = node.input_a() as usize;
                if source >= digests.len() {
                    return Err(EvalError::InvalidNodeReference {
                        node_index: i,
                        operand_index: source,
                    });
                }
                digests[source]
            }

            k => return Err(EvalError::UnknownNodeKind(k)),
        };

        digests.push(digest);
    }

    // Collect output digests
    let output_digests: Vec<CiphertextDigest> = (0..num_nodes)
        .filter(|&i| {
            get_node(pg.node_bytes(), i as u16)
                .map(|n| n.kind() == GraphNodeKind::Output as u8)
                .unwrap_or(false)
        })
        .map(|i| digests[i])
        .collect();

    Ok(GraphEvalResult { output_digests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockComputeEngine;
    /// Helper: decrypt a digest to u64 using the engine.
    fn decrypt_u64(engine: &mut MockComputeEngine, digest: &[u8; 32]) -> u64 {
        let bytes = engine.decrypt(digest, FheType::EUint64).unwrap();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// Build a simple add graph: a + b
    fn build_add_graph() -> Vec<u8> {
        use encrypt_dsl::graph::GraphBuilder;
        let mut gb = GraphBuilder::new();
        let a = gb.add_input(4); // EUint64
        let b = gb.add_input(4);
        let sum = gb.add_op(FheOperation::Add as u8, 4, a, b);
        gb.add_output(4, sum);
        gb.serialize()
    }

    /// Build the cast_vote graph: if vote { yes+1 } else { yes }, if vote { no } else { no+1 }
    fn build_vote_graph() -> Vec<u8> {
        use encrypt_dsl::graph::GraphBuilder;
        let mut gb = GraphBuilder::new();
        let yes = gb.add_input(4); // EUint64
        let no = gb.add_input(4);
        let vote = gb.add_input(0); // EBool
        let one = gb.add_constant(4, 1u128);
        let yes_plus_1 = gb.add_op(FheOperation::Add as u8, 4, yes, one);
        let no_plus_1 = gb.add_op(FheOperation::Add as u8, 4, no, one);
        let new_yes = gb.add_ternary_op(FheOperation::Select as u8, 4, vote, yes_plus_1, yes);
        let new_no = gb.add_ternary_op(FheOperation::Select as u8, 4, vote, no, no_plus_1);
        gb.add_output(4, new_yes);
        gb.add_output(4, new_no);
        gb.serialize()
    }

    #[test]
    fn evaluate_add() {
        let mut engine = MockComputeEngine::new();
        let graph = build_add_graph();
        let a = engine.encode_constant(FheType::EUint64, 10).unwrap();
        let b = engine.encode_constant(FheType::EUint64, 32).unwrap();

        let result = evaluate_graph(&mut engine, &graph, &[a, b]).unwrap();
        assert_eq!(result.output_digests.len(), 1);
        assert_eq!(decrypt_u64(&mut engine, &result.output_digests[0]), 42);
    }

    #[test]
    fn evaluate_vote_yes() {
        let mut engine = MockComputeEngine::new();
        let graph = build_vote_graph();

        let yes = engine.encode_constant(FheType::EUint64, 10).unwrap();
        let no = engine.encode_constant(FheType::EUint64, 5).unwrap();
        let vote = engine.encode_constant(FheType::EBool, 1).unwrap();

        let result = evaluate_graph(&mut engine, &graph, &[yes, no, vote]).unwrap();
        assert_eq!(result.output_digests.len(), 2);
        assert_eq!(
            decrypt_u64(&mut engine, &result.output_digests[0]),
            11,
            "yes should be 11"
        );
        assert_eq!(
            decrypt_u64(&mut engine, &result.output_digests[1]),
            5,
            "no should stay 5"
        );
    }

    #[test]
    fn evaluate_vote_no() {
        let mut engine = MockComputeEngine::new();
        let graph = build_vote_graph();

        let yes = engine.encode_constant(FheType::EUint64, 10).unwrap();
        let no = engine.encode_constant(FheType::EUint64, 5).unwrap();
        let vote = engine.encode_constant(FheType::EBool, 0).unwrap();

        let result = evaluate_graph(&mut engine, &graph, &[yes, no, vote]).unwrap();
        assert_eq!(
            decrypt_u64(&mut engine, &result.output_digests[0]),
            10,
            "yes should stay 10"
        );
        assert_eq!(
            decrypt_u64(&mut engine, &result.output_digests[1]),
            6,
            "no should be 6"
        );
    }

    #[test]
    fn evaluate_not_enough_inputs() {
        let mut engine = MockComputeEngine::new();
        let graph = build_add_graph();
        let a = engine.encode_constant(FheType::EUint64, 10).unwrap();

        let result = evaluate_graph(&mut engine, &graph, &[a]);
        assert!(matches!(
            result,
            Err(EvalError::NotEnoughInputs {
                expected: 2,
                got: 1
            })
        ));
    }
}
