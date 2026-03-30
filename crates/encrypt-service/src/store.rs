// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Ciphertext storage — maps on-chain ciphertext identifier to digest + metadata.
//!
//! Chain-agnostic. Uses `OnChainId` for identifiers.

use std::collections::HashMap;
use std::sync::RwLock;

use encrypt_types::types::FheType;

use crate::requests::OnChainId;

/// A stored ciphertext entry.
#[derive(Clone, Debug)]
pub struct CiphertextEntry {
    /// 32-byte digest. In mock mode, encodes the plaintext directly.
    pub digest: [u8; 32],
    /// FHE type of the ciphertext.
    pub fhe_type: FheType,
    /// Optional ciphertext blob (None in mock mode, Some in real REFHE mode).
    pub blob: Option<Vec<u8>>,
}

/// Storage backend for ciphertext data.
///
/// Maps on-chain ciphertext identifier → (digest, fhe_type, optional blob).
pub trait CiphertextStore {
    /// Store or update a ciphertext entry.
    fn put(
        &self,
        id: OnChainId,
        digest: [u8; 32],
        fhe_type: FheType,
        blob: Option<Vec<u8>>,
    );

    /// Look up a ciphertext digest by on-chain identifier.
    fn get_digest(&self, id: &OnChainId) -> Option<[u8; 32]>;

    /// Look up the full entry (digest + fhe_type + optional blob).
    fn get(&self, id: &OnChainId) -> Option<CiphertextEntry>;

    /// Remove an entry.
    fn remove(&self, id: &OnChainId);
}

/// In-memory ciphertext store for local development.
///
/// Thread-safe via `RwLock`. Production would use PostgreSQL or S3.
pub struct InMemoryCiphertextStore {
    entries: RwLock<HashMap<OnChainId, CiphertextEntry>>,
}

impl InMemoryCiphertextStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

impl Default for InMemoryCiphertextStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CiphertextStore for InMemoryCiphertextStore {
    fn put(
        &self,
        id: OnChainId,
        digest: [u8; 32],
        fhe_type: FheType,
        blob: Option<Vec<u8>>,
    ) {
        self.entries.write().unwrap().insert(
            id,
            CiphertextEntry {
                digest,
                fhe_type,
                blob,
            },
        );
    }

    fn get_digest(&self, id: &OnChainId) -> Option<[u8; 32]> {
        self.entries.read().unwrap().get(id).map(|e| e.digest)
    }

    fn get(&self, id: &OnChainId) -> Option<CiphertextEntry> {
        self.entries.read().unwrap().get(id).cloned()
    }

    fn remove(&self, id: &OnChainId) {
        self.entries.write().unwrap().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let store = InMemoryCiphertextStore::new();
        let pubkey = [1u8; 32];
        let digest = [0xABu8; 32];

        store.put(pubkey, digest, FheType::EUint64, None);

        assert_eq!(store.get_digest(&pubkey), Some(digest));
        let entry = store.get(&pubkey).unwrap();
        assert_eq!(entry.fhe_type, FheType::EUint64);
        assert!(entry.blob.is_none());
    }

    #[test]
    fn overwrite() {
        let store = InMemoryCiphertextStore::new();
        let pubkey = [1u8; 32];

        store.put(pubkey, [0xAAu8; 32], FheType::EUint64, None);
        store.put(pubkey, [0xBBu8; 32], FheType::EUint64, None);

        assert_eq!(store.get_digest(&pubkey), Some([0xBBu8; 32]));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn get_missing() {
        let store = InMemoryCiphertextStore::new();
        assert_eq!(store.get_digest(&[99u8; 32]), None);
        assert!(store.get(&[99u8; 32]).is_none());
    }

    #[test]
    fn remove_entry() {
        let store = InMemoryCiphertextStore::new();
        let pubkey = [1u8; 32];
        store.put(pubkey, [0xAAu8; 32], FheType::EUint64, None);
        store.remove(&pubkey);
        assert!(store.is_empty());
    }

    #[test]
    fn with_blob() {
        let store = InMemoryCiphertextStore::new();
        let pubkey = [2u8; 32];
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF];

        store.put(pubkey, [0xCCu8; 32], FheType::EUint32, Some(blob.clone()));

        let entry = store.get(&pubkey).unwrap();
        assert_eq!(entry.blob, Some(blob));
    }
}
