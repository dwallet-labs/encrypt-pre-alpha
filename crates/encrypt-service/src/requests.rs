// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Chain-agnostic work request types and listener trait.
//!
//! These represent off-chain work items that the executor/decryptor must process.
//! Chain-specific listeners (Solana WebSocket, EVM eth_subscribe, etc.) parse
//! raw blockchain data into these types.

use encrypt_types::types::FheType;

/// Source blockchain where the request originated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceChain {
    Solana,
    Evm,
    Sui,
}

/// Opaque on-chain identifier for an account/object/address.
///
/// Chain-agnostic: Solana pubkey (32 bytes), EVM address (20 bytes zero-padded),
/// Sui object ID (32 bytes). Always stored as 32 bytes for uniformity.
pub type OnChainId = [u8; 32];

/// A parsed request from the on-chain program that requires off-chain action.
#[derive(Clone, Debug)]
pub enum EncryptRequest {
    /// A computation graph was executed. Executor must evaluate and commit results.
    GraphExecuted(GraphExecutedRequest),
    /// A ciphertext was created (authority-driven). Executor should track it.
    CiphertextCreated(CiphertextCreatedRequest),
    /// A decryption was requested. Decryptor must decrypt and respond.
    DecryptionRequested(DecryptionRequestData),
    /// A ciphertext was committed (digest written). Informational.
    CiphertextCommitted(CiphertextCommittedRequest),
    /// A decryption response was completed. Informational.
    DecryptionResponded(DecryptionRespondedRequest),
}

impl EncryptRequest {
    pub fn source_chain(&self) -> SourceChain {
        match self {
            Self::GraphExecuted(r) => r.source_chain,
            Self::CiphertextCreated(r) => r.source_chain,
            Self::DecryptionRequested(r) => r.source_chain,
            Self::CiphertextCommitted(r) => r.source_chain,
            Self::DecryptionResponded(r) => r.source_chain,
        }
    }
}

/// Graph execution request — executor must evaluate graph and commit results.
#[derive(Clone, Debug)]
pub struct GraphExecutedRequest {
    pub source_chain: SourceChain,
    /// The graph binary data (extracted from the on-chain instruction).
    pub graph_data: Vec<u8>,
    /// Identifiers of input ciphertext accounts/objects.
    pub input_ids: Vec<OnChainId>,
    /// Identifiers of output ciphertext accounts/objects.
    pub output_ids: Vec<OnChainId>,
    /// Number of inputs declared.
    pub num_inputs: u16,
    /// Number of outputs declared.
    pub num_outputs: u16,
    /// The caller that executed the graph.
    pub caller: OnChainId,
}

/// Ciphertext creation notification — executor should track it.
#[derive(Clone, Debug)]
pub struct CiphertextCreatedRequest {
    pub source_chain: SourceChain,
    /// Ciphertext identifier.
    pub ciphertext_id: OnChainId,
    /// The digest (may be zero for plaintext ciphertexts).
    pub ciphertext_digest: [u8; 32],
    /// FHE type.
    pub fhe_type: u8,
}

/// Decryption request — decryptor must decrypt and respond.
#[derive(Clone, Debug)]
pub struct DecryptionRequestData {
    pub source_chain: SourceChain,
    /// Ciphertext being decrypted.
    pub ciphertext_id: OnChainId,
    /// Who requested the decryption.
    pub requester: OnChainId,
    /// The decryption request identifier (needed for response submission).
    pub request_id: OnChainId,
    /// FHE type (determines result byte width).
    pub fhe_type: FheType,
}

/// Ciphertext committed notification (informational).
#[derive(Clone, Debug)]
pub struct CiphertextCommittedRequest {
    pub source_chain: SourceChain,
    pub ciphertext_id: OnChainId,
    pub ciphertext_digest: [u8; 32],
}

/// Decryption responded notification (informational).
#[derive(Clone, Debug)]
pub struct DecryptionRespondedRequest {
    pub source_chain: SourceChain,
    pub ciphertext_id: OnChainId,
    pub requester: OnChainId,
}

/// Chain-agnostic request listener trait.
///
/// Implementations poll or subscribe for requests from on-chain programs.
/// - Solana: WebSocket/Geyser subscription to inner instructions
/// - EVM: eth_subscribe (future)
/// - Sui: event subscription (future)
pub trait RequestListener {
    type Error: std::error::Error;

    /// Poll for new requests since the last call.
    fn poll_requests(&mut self) -> Result<Vec<EncryptRequest>, Self::Error>;
}
