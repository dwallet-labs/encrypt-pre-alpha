// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use alloc::vec;
use alloc::vec::Vec;
use encrypt_types::graph::{GraphHeader, GraphNode, GraphNodeKind};
use encrypt_types::types::FheType;

/// Builder for constructing computation graphs at runtime.
pub struct GraphBuilder {
    nodes: Vec<[u8; 9]>,
    constants: Vec<u8>,
    num_inputs: u8,
    num_plaintext_inputs: u8,
    num_constants: u8,
    num_ops: u8,
    num_outputs: u8,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            constants: Vec::new(),
            num_inputs: 0,
            num_plaintext_inputs: 0,
            num_constants: 0,
            num_ops: 0,
            num_outputs: 0,
        }
    }

    fn push_node(&mut self, kind: u8, op_type: u8, fhe_type: u8, a: u16, b: u16, c: u16) -> u16 {
        let idx = self.nodes.len() as u16;
        let mut buf = [0u8; 9];
        buf[0] = kind;
        buf[1] = op_type;
        buf[2] = fhe_type;
        buf[3..5].copy_from_slice(&a.to_le_bytes());
        buf[5..7].copy_from_slice(&b.to_le_bytes());
        buf[7..9].copy_from_slice(&c.to_le_bytes());
        self.nodes.push(buf);
        idx
    }

    /// Add an encrypted input node, returns its index.
    pub fn add_input(&mut self, fhe_type: u8) -> u16 {
        self.num_inputs += 1;
        self.push_node(GraphNodeKind::Input as u8, 0, fhe_type, 0xFFFF, 0xFFFF, 0xFFFF)
    }

    /// Add a plaintext input node, returns its index.
    pub fn add_plaintext_input(&mut self, fhe_type: u8) -> u16 {
        self.num_plaintext_inputs += 1;
        self.push_node(GraphNodeKind::PlaintextInput as u8, 0, fhe_type, 0xFFFF, 0xFFFF, 0xFFFF)
    }

    /// Add a constant node from a u128 value. The value is stored as
    /// `fhe_type.byte_width()` LE bytes in the constants section.
    /// Types > 128 bits get the lower 128 bits + zero padding.
    pub fn add_constant(&mut self, fhe_type: u8, value: u128) -> u16 {
        let byte_width = FheType::from_u8(fhe_type)
            .map(|t| t.byte_width())
            .unwrap_or(16);
        let value_bytes = value.to_le_bytes();
        let mut buf = vec![0u8; byte_width];
        let copy_len = byte_width.min(16);
        buf[..copy_len].copy_from_slice(&value_bytes[..copy_len]);
        self.add_constant_bytes(fhe_type, &buf)
    }

    /// Add a constant node from raw bytes (any width).
    /// `data.len()` must equal `fhe_type.byte_width()`.
    ///
    /// Deduplicates: if the same (fhe_type, bytes) already exists, returns
    /// the existing node index instead of creating a duplicate.
    pub fn add_constant_bytes(&mut self, fhe_type: u8, data: &[u8]) -> u16 {
        // Check for existing identical constant
        for (i, node) in self.nodes.iter().enumerate() {
            if node[0] == GraphNodeKind::Constant as u8 && node[2] == fhe_type {
                let offset = u16::from_le_bytes([node[3], node[4]]) as usize;
                let end = offset + data.len();
                if end <= self.constants.len()
                    && &self.constants[offset..end] == data
                {
                    return i as u16;
                }
            }
        }

        let offset = self.constants.len() as u16;
        self.constants.extend_from_slice(data);
        self.num_constants += 1;
        self.push_node(GraphNodeKind::Constant as u8, 0, fhe_type, offset, 0xFFFF, 0xFFFF)
    }

    /// Add a binary operation node, returns its index.
    pub fn add_op(&mut self, op_type: u8, fhe_type: u8, input_a: u16, input_b: u16) -> u16 {
        self.num_ops += 1;
        self.push_node(GraphNodeKind::Op as u8, op_type, fhe_type, input_a, input_b, 0xFFFF)
    }

    /// Add a ternary operation node (e.g. select), returns its index.
    pub fn add_ternary_op(&mut self, op_type: u8, fhe_type: u8, a: u16, b: u16, c: u16) -> u16 {
        self.num_ops += 1;
        self.push_node(GraphNodeKind::Op as u8, op_type, fhe_type, a, b, c)
    }

    /// Mark a node as output, returns its index.
    pub fn add_output(&mut self, fhe_type: u8, source: u16) -> u16 {
        self.num_outputs += 1;
        self.push_node(GraphNodeKind::Output as u8, 0, fhe_type, source, 0xFFFF, 0xFFFF)
    }

    /// Serialize: `[Header 8B][Nodes N×9B][Constants section]`
    pub fn serialize(&self) -> Vec<u8> {
        let total = GraphHeader::SIZE
            + self.nodes.len() * GraphNode::SIZE
            + self.constants.len();
        let mut buf = Vec::with_capacity(total);

        let constants_len = self.constants.len() as u16;

        // Header (8 bytes) — counts as u8, constants_len as u16
        buf.push(1); // version
        buf.push(self.num_inputs);
        buf.push(self.num_plaintext_inputs);
        buf.push(self.num_constants);
        buf.push(self.num_ops);
        buf.push(self.num_outputs);
        buf.extend_from_slice(&constants_len.to_le_bytes());

        // Nodes (9 bytes each)
        for node in &self.nodes {
            buf.extend_from_slice(node);
        }

        // Constants section
        buf.extend_from_slice(&self.constants);

        buf
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypt_types::graph::{get_constant_u128, get_node, parse_graph, GraphNodeKind};

    #[test]
    fn round_trip_no_constants() {
        let mut gb = GraphBuilder::new();
        let i0 = gb.add_input(3);
        let i1 = gb.add_input(3);
        let op = gb.add_op(0, 3, i0, i1);
        gb.add_output(3, op);

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");
        let h = pg.header();

        assert_eq!(h.version(), 1);
        assert_eq!(h.num_nodes(), 4);
        assert_eq!(h.num_inputs(), 2);
        assert_eq!(h.num_outputs(), 1);
        assert_eq!(h.num_ops(), 1);
        assert_eq!(h.num_constants(), 0);
        assert_eq!(pg.constants().len(), 0);
    }

    #[test]
    fn constant_u32_stored_as_4_bytes() {
        let mut gb = GraphBuilder::new();
        let c = gb.add_constant(3, 42); // EUint32 = 4 bytes

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_constants(), 1);
        let node = get_node(pg.node_bytes(), c).unwrap();
        assert_eq!(node.kind(), GraphNodeKind::Constant as u8);
        assert_eq!(node.const_offset(), 0);
        assert_eq!(get_constant_u128(pg.constants(), 0, 4).unwrap(), 42);
    }

    #[test]
    fn constant_u128_stored_as_16_bytes() {
        let mut gb = GraphBuilder::new();
        gb.add_constant(5, u128::MAX); // EUint128 = 16 bytes

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_constants(), 1);
        assert_eq!(get_constant_u128(pg.constants(), 0, 16).unwrap(), u128::MAX);
    }

    #[test]
    fn constant_u256_stored_as_32_bytes() {
        let mut gb = GraphBuilder::new();
        gb.add_constant(6, 0xDEADBEEF);

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_constants(), 1);
        assert_eq!(get_constant_u128(pg.constants(), 0, 16).unwrap(), 0xDEADBEEF);
        assert_eq!(get_constant_u128(pg.constants(), 16, 16).unwrap(), 0);
    }

    #[test]
    fn constant_bytes_arbitrary_width() {
        let mut gb = GraphBuilder::new();
        let big_val = vec![0xABu8; 64];
        gb.add_constant_bytes(8, &big_val);

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_constants(), 1);
        assert_eq!(&pg.constants()[..64], &big_val[..]);
    }

    #[test]
    fn multiple_constants_at_different_offsets() {
        let mut gb = GraphBuilder::new();
        let c0 = gb.add_constant(1, 10); // EUint8 = 1 byte, offset 0
        let c1 = gb.add_constant(3, 20); // EUint32 = 4 bytes, offset 1
        let c2 = gb.add_constant(4, 30); // EUint64 = 8 bytes, offset 5

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_constants(), 3);

        let n0 = get_node(pg.node_bytes(), c0).unwrap();
        assert_eq!(n0.const_offset(), 0);
        assert_eq!(get_constant_u128(pg.constants(), 0, 1).unwrap(), 10);

        let n1 = get_node(pg.node_bytes(), c1).unwrap();
        assert_eq!(n1.const_offset(), 1);
        assert_eq!(get_constant_u128(pg.constants(), 1, 4).unwrap(), 20);

        let n2 = get_node(pg.node_bytes(), c2).unwrap();
        assert_eq!(n2.const_offset(), 5);
        assert_eq!(get_constant_u128(pg.constants(), 5, 8).unwrap(), 30);
    }

    #[test]
    fn duplicate_constants_are_deduplicated() {
        let mut gb = GraphBuilder::new();
        let c0 = gb.add_constant(4, 1);
        let c1 = gb.add_constant(4, 1);
        let c2 = gb.add_constant(4, 2);
        let c3 = gb.add_constant(3, 1);

        assert_eq!(c0, c1, "identical constants should be deduplicated");
        assert_ne!(c0, c2, "different values should be separate");
        assert_ne!(c0, c3, "different types should be separate");

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        assert_eq!(pg.header().num_nodes(), 3);
        assert_eq!(pg.constants().len(), 20);
    }

    #[test]
    fn duplicate_constant_bytes_are_deduplicated() {
        let mut gb = GraphBuilder::new();
        let data_a = [0xABu8; 32];
        let data_b = [0xABu8; 32];
        let data_c = [0xCDu8; 32];

        let c0 = gb.add_constant_bytes(6, &data_a);
        let c1 = gb.add_constant_bytes(6, &data_b);
        let c2 = gb.add_constant_bytes(6, &data_c);

        assert_eq!(c0, c1);
        assert_ne!(c0, c2);
    }

    #[test]
    fn ternary_op_preserves_three_inputs() {
        let mut gb = GraphBuilder::new();
        let cond = gb.add_input(0);
        let a = gb.add_input(4);
        let b = gb.add_input(4);
        let sel = gb.add_ternary_op(60, 4, cond, a, b);
        gb.add_output(4, sel);

        let data = gb.serialize();
        let pg = parse_graph(&data).expect("valid graph");

        let sel_node = get_node(pg.node_bytes(), 3).unwrap();
        assert_eq!(sel_node.input_a(), cond);
        assert_eq!(sel_node.input_b(), a);
        assert_eq!(sel_node.input_c(), b);
    }
}
