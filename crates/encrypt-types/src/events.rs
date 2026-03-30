// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Emitted when the authority creates a new ciphertext (after ZK proof verification).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CiphertextCreatedEvent {
    pub ciphertext_id: [u8; 32],
    pub ciphertext_digest: [u8; 32],
    pub fhe_type: u8,
    pub creator: [u8; 32],
}

/// Emitted when the authority commits a computation result to an existing ciphertext.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CiphertextCommittedEvent {
    pub ciphertext_id: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}

/// Emitted when a user requests plaintext decryption.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct DecryptionRequestedEvent {
    pub ciphertext_id: [u8; 32],
    pub requester: [u8; 32],
}

/// Emitted when the authority completes a decryption response.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct DecryptionRespondedEvent {
    pub ciphertext_id: [u8; 32],
    pub requester: [u8; 32],
}

/// Emitted when a computation graph is executed.
/// The executor uses this to schedule off-chain FHE evaluation.
///
/// Output IDs are variable-length: `num_outputs * 32` bytes are emitted
/// as trailing data after the fixed header when logged via `sol_log_data`.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct GraphExecutedEvent {
    pub num_outputs: u16,
    pub num_inputs: u16,
    pub caller_program: [u8; 32],
    // Followed by: output_ids: [[u8; 32]; num_outputs] (trailing bytes)
}
