// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Pipeline types — pending work items, work queue, and result submission trait.
//!
//! Chain-agnostic. Uses `OnChainId` for identifiers instead of chain-specific types.

use encrypt_types::types::FheType;

use crate::requests::{OnChainId, SourceChain};

/// A pending graph execution to be processed by the executor.
#[derive(Clone, Debug)]
pub struct PendingGraphExecution {
    pub source_chain: SourceChain,
    /// The graph binary data (from the on-chain instruction).
    pub graph_data: Vec<u8>,
    /// Identifiers of input ciphertext accounts/objects.
    pub input_ids: Vec<OnChainId>,
    /// Identifiers of output ciphertext accounts/objects.
    pub output_ids: Vec<OnChainId>,
}

/// A pending decryption request to be processed by the decryptor.
#[derive(Clone, Debug)]
pub struct PendingDecryption {
    pub source_chain: SourceChain,
    /// Identifier of the decryption request account/object.
    pub request_id: OnChainId,
    /// Identifier of the ciphertext being decrypted.
    pub ciphertext_id: OnChainId,
    /// FHE type of the ciphertext (determines result byte width).
    pub fhe_type: FheType,
}

/// Work queue for pending executor and decryptor tasks.
#[derive(Default)]
pub struct WorkQueue {
    pub executions: Vec<PendingGraphExecution>,
    pub decryptions: Vec<PendingDecryption>,
}

impl WorkQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_execution(&mut self, execution: PendingGraphExecution) {
        self.executions.push(execution);
    }

    pub fn enqueue_decryption(&mut self, decryption: PendingDecryption) {
        self.decryptions.push(decryption);
    }

    /// Drain all pending work, returning (executions, decryptions).
    pub fn drain(&mut self) -> (Vec<PendingGraphExecution>, Vec<PendingDecryption>) {
        let executions = std::mem::take(&mut self.executions);
        let decryptions = std::mem::take(&mut self.decryptions);
        (executions, decryptions)
    }

    pub fn is_empty(&self) -> bool {
        self.executions.is_empty() && self.decryptions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.executions.len() + self.decryptions.len()
    }
}

/// Chain-agnostic trait for submitting executor/decryptor results.
///
/// Local dev: direct authority-signed transactions.
/// Production: submit to Ika validators for write-back.
pub trait ResultSubmitter {
    type Error: std::error::Error;

    /// Submit a ciphertext commitment (graph output result).
    fn commit_ciphertext(
        &mut self,
        ciphertext_id: OnChainId,
        digest: [u8; 32],
    ) -> Result<(), Self::Error>;

    /// Submit a decryption response with plaintext result.
    fn respond_decryption(
        &mut self,
        request_id: OnChainId,
        plaintext_data: &[u8],
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_queue_basic() {
        let mut q = WorkQueue::new();
        assert!(q.is_empty());

        q.enqueue_execution(PendingGraphExecution {
            source_chain: SourceChain::Solana,
            graph_data: vec![1, 2, 3],
            input_ids: vec![[1u8; 32]],
            output_ids: vec![[2u8; 32]],
        });

        q.enqueue_decryption(PendingDecryption {
            source_chain: SourceChain::Solana,
            request_id: [3u8; 32],
            ciphertext_id: [4u8; 32],
            fhe_type: FheType::EUint64,
        });

        assert_eq!(q.len(), 2);

        let (execs, decrypts) = q.drain();
        assert_eq!(execs.len(), 1);
        assert_eq!(decrypts.len(), 1);
        assert!(q.is_empty());
    }
}
