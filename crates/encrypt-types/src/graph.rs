// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! FHE computation graph binary format.
//!
//! A computation graph is a DAG of FHE operations compiled from an `#[encrypt_fn]`
//! function. It is serialized into a compact binary format for on-chain storage
//! and off-chain executor evaluation.
//!
//! # Binary layout
//!
//! ```text
//! [Header 8B] [Nodes N×9B] [Constants section]
//! ```
//!
//! - **Header** (8 bytes): Version + per-kind node counts (u8 each) + constants byte length (u16).
//!   Max 255 nodes per kind. `constants_len` stays u16 (constants can exceed 255 bytes).
//!
//! - **Nodes** (9 bytes each): Fixed-size entries representing inputs, constants,
//!   operations, and outputs. Nodes reference each other by index (u16 LE).
//!   Node ordering matches execution order — inputs first, then plaintext inputs,
//!   then constants, then operations (topologically sorted), then outputs.
//!
//! - **Constants section**: Variable-length byte blob storing literal values.
//!   Constant nodes point into this section by byte offset (`input_a`).
//!   Each constant's size is determined by its `fhe_type`'s byte width.
//!   Identical constants are deduplicated by the graph builder.
//!
//! # Node kinds
//!
//! | Kind (u8) | Name | Fields used |
//! |-----------|------|-------------|
//! | 0 | Input | `fhe_type` |
//! | 1 | PlaintextInput | `fhe_type` |
//! | 2 | Constant | `fhe_type`, `input_a` = byte offset into constants |
//! | 3 | Op | `op_type`, `fhe_type`, `input_a`, `input_b`, `input_c` |
//! | 4 | Output | `fhe_type`, `input_a` = source node index |
//!
//! # Node byte layout (9 bytes)
//!
//! ```text
//! kind(1) | op_type(1) | fhe_type(1) | input_a(2 LE) | input_b(2 LE) | input_c(2 LE)
//! ```
//!
//! # Header byte layout (8 bytes)
//!
//! ```text
//! version(1) | num_inputs(1) | num_plaintext_inputs(1) | num_constants(1) | num_ops(1) | num_outputs(1) | constants_len(2 LE)
//! ```

/// Node types in a computation graph.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum GraphNodeKind {
    /// Encrypted ciphertext account passed as a remaining account.
    Input = 0,
    /// Plaintext value passed in instruction data.
    PlaintextInput = 1,
    /// Literal value stored in the constants section.
    Constant = 2,
    /// FHE operation (binary, unary, or ternary select).
    Op = 3,
    /// Marks a computation result as a graph output.
    Output = 4,
}

/// Zero-copy view over a single 9-byte node in the graph.
pub struct GraphNode<'a>(&'a [u8]);

impl<'a> GraphNode<'a> {
    /// Size of a single node in bytes.
    pub const SIZE: usize = 9;

    #[inline]
    pub fn kind(&self) -> u8 {
        self.0[0]
    }

    #[inline]
    pub fn op_type(&self) -> u8 {
        self.0[1]
    }

    #[inline]
    pub fn fhe_type(&self) -> u8 {
        self.0[2]
    }

    /// First operand: node index (Op/Output) or byte offset (Constant).
    #[inline]
    pub fn input_a(&self) -> u16 {
        u16::from_le_bytes([self.0[3], self.0[4]])
    }

    /// Second operand node index. `0xFFFF` for unary ops and non-Op nodes.
    #[inline]
    pub fn input_b(&self) -> u16 {
        u16::from_le_bytes([self.0[5], self.0[6]])
    }

    /// Third operand (select condition). `0xFFFF` when unused.
    #[inline]
    pub fn input_c(&self) -> u16 {
        u16::from_le_bytes([self.0[7], self.0[8]])
    }

    /// For Constant nodes: byte offset into the constants section.
    #[inline]
    pub fn const_offset(&self) -> u16 {
        self.input_a()
    }
}

/// Zero-copy view over the 8-byte graph header.
pub struct GraphHeader<'a>(&'a [u8]);

impl<'a> GraphHeader<'a> {
    /// Size of the header in bytes.
    pub const SIZE: usize = 8;

    /// Graph format version (currently 1).
    #[inline]
    pub fn version(&self) -> u8 {
        self.0[0]
    }

    /// Number of encrypted input nodes.
    #[inline]
    pub fn num_inputs(&self) -> u8 {
        self.0[1]
    }

    /// Number of plaintext input nodes.
    #[inline]
    pub fn num_plaintext_inputs(&self) -> u8 {
        self.0[2]
    }

    /// Number of constant nodes.
    #[inline]
    pub fn num_constants(&self) -> u8 {
        self.0[3]
    }

    /// Number of operation nodes.
    #[inline]
    pub fn num_ops(&self) -> u8 {
        self.0[4]
    }

    /// Number of output nodes.
    #[inline]
    pub fn num_outputs(&self) -> u8 {
        self.0[5]
    }

    /// Total bytes in the constants section (u16 — can exceed 255).
    #[inline]
    pub fn constants_len(&self) -> u16 {
        u16::from_le_bytes([self.0[6], self.0[7]])
    }

    /// Total number of nodes (sum of all per-kind counts).
    #[inline]
    pub fn num_nodes(&self) -> u16 {
        self.num_inputs() as u16
            + self.num_plaintext_inputs() as u16
            + self.num_constants() as u16
            + self.num_ops() as u16
            + self.num_outputs() as u16
    }
}

/// A parsed graph providing zero-copy access to header, nodes, and constants.
pub struct ParsedGraph<'a> {
    data: &'a [u8],
    nodes_start: usize,
    nodes_end: usize,
    constants_end: usize,
}

impl<'a> ParsedGraph<'a> {
    pub fn header(&self) -> GraphHeader<'a> {
        GraphHeader(&self.data[..GraphHeader::SIZE])
    }

    pub fn node_bytes(&self) -> &'a [u8] {
        &self.data[self.nodes_start..self.nodes_end]
    }

    pub fn constants(&self) -> &'a [u8] {
        &self.data[self.nodes_end..self.constants_end]
    }

    pub fn get_node(&self, index: u16) -> Option<GraphNode<'a>> {
        get_node(self.node_bytes(), index)
    }

    pub fn num_nodes(&self) -> u16 {
        self.header().num_nodes()
    }
}

/// Parse a serialized graph from bytes.
pub fn parse_graph(data: &[u8]) -> Option<ParsedGraph<'_>> {
    if data.len() < GraphHeader::SIZE {
        return None;
    }
    let header = GraphHeader(&data[..GraphHeader::SIZE]);
    let nodes_start = GraphHeader::SIZE;
    let num_nodes = header.num_nodes() as usize;
    let nodes_end = nodes_start + num_nodes * GraphNode::SIZE;
    let constants_end = nodes_end + header.constants_len() as usize;
    if data.len() < constants_end {
        return None;
    }

    Some(ParsedGraph {
        data,
        nodes_start,
        nodes_end,
        constants_end,
    })
}

/// Get a node by index from raw node bytes.
pub fn get_node<'a>(node_bytes: &'a [u8], index: u16) -> Option<GraphNode<'a>> {
    let offset = index as usize * GraphNode::SIZE;
    let end = offset + GraphNode::SIZE;
    if end > node_bytes.len() {
        return None;
    }
    Some(GraphNode(&node_bytes[offset..end]))
}

/// Read constant bytes from the constants section at a given offset.
pub fn get_constant(constants: &[u8], offset: u16, len: usize) -> Option<&[u8]> {
    let start = offset as usize;
    let end = start + len;
    if end > constants.len() {
        return None;
    }
    Some(&constants[start..end])
}

/// Read a constant as u128. Zero-pads if shorter than 16 bytes.
pub fn get_constant_u128(constants: &[u8], offset: u16, len: usize) -> Option<u128> {
    let bytes = get_constant(constants, offset, len)?;
    let mut buf = [0u8; 16];
    let copy_len = len.min(16);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    Some(u128::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_8() {
        assert_eq!(GraphHeader::SIZE, 8);
    }

    #[test]
    fn node_size_is_9() {
        assert_eq!(GraphNode::SIZE, 9);
    }

    #[test]
    fn parse_graph_valid() {
        // Header(8) + 2 nodes(18) + 0 constants = 26
        let mut buf = [0u8; 26];
        buf[0] = 1; // version
        buf[1] = 1; // num_inputs
        buf[5] = 1; // num_outputs

        buf[8] = GraphNodeKind::Input as u8;
        buf[8 + 9] = GraphNodeKind::Output as u8;

        let pg = parse_graph(&buf).unwrap();
        let h = pg.header();
        assert_eq!(h.num_nodes(), 2);
        assert_eq!(h.num_inputs(), 1);
        assert_eq!(h.num_plaintext_inputs(), 0);
        assert_eq!(h.num_constants(), 0);
        assert_eq!(pg.node_bytes().len(), 18);
        assert_eq!(pg.constants().len(), 0);
    }

    #[test]
    fn parse_graph_with_constants() {
        // Header(8) + 1 node(9) + 4 constant bytes = 21
        let mut buf = [0u8; 21];
        buf[0] = 1; // version
        buf[3] = 1; // num_constants
        buf[6] = 4; // constants_len LE low byte

        buf[8] = GraphNodeKind::Constant as u8;
        buf[10] = 3; // fhe_type = EUint32

        let val = 42u32.to_le_bytes();
        buf[17..21].copy_from_slice(&val);

        let pg = parse_graph(&buf).unwrap();
        assert_eq!(pg.header().num_constants(), 1);
        assert_eq!(pg.constants().len(), 4);
        let v = get_constant_u128(pg.constants(), 0, 4).unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn parse_graph_too_short() {
        assert!(parse_graph(&[0u8; 4]).is_none());
        let mut buf = [0u8; 8];
        buf[1] = 1; // num_inputs = 1 but no node bytes
        assert!(parse_graph(&buf).is_none());
    }

    #[test]
    fn get_node_by_index() {
        let mut nodes = [0u8; 18];
        nodes[0] = GraphNodeKind::Input as u8;
        nodes[9] = GraphNodeKind::Op as u8;
        nodes[10] = 5;
        nodes[11] = 3;

        let n0 = get_node(&nodes, 0).unwrap();
        assert_eq!(n0.kind(), GraphNodeKind::Input as u8);

        let n1 = get_node(&nodes, 1).unwrap();
        assert_eq!(n1.op_type(), 5);

        assert!(get_node(&nodes, 2).is_none());
    }

    #[test]
    fn get_constant_reads_correctly() {
        let constants = [10u8, 0, 0, 0, 0xFF, 0xFF, 0, 0];
        assert_eq!(get_constant_u128(&constants, 0, 4).unwrap(), 10);
        assert_eq!(get_constant_u128(&constants, 4, 4).unwrap(), 0xFFFF);
        assert!(get_constant(&constants, 0, 9).is_none());
    }

    #[test]
    fn num_nodes_is_sum_of_counts() {
        let mut buf = [0u8; 8];
        buf[0] = 1; // version
        buf[1] = 3; // num_inputs
        buf[2] = 1; // num_plaintext_inputs
        buf[3] = 2; // num_constants
        buf[4] = 5; // num_ops
        buf[5] = 2; // num_outputs
        let header = GraphHeader(&buf);
        assert_eq!(header.num_nodes(), 13);
    }
}
