// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! SQLite-backed ciphertext store + compute engine digest table.
//!
//! Dev-only (behind `sqlite` feature). Single `.encrypt-dev/encrypt.db` file
//! that survives executor restarts.
//!
//! Two tables:
//! - `ciphertexts`: on-chain ID → (digest, fhe_type, blob)
//! - `digests`: keccak256 digest → plaintext value bytes (for MockComputeEngine)

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use encrypt_compute::mock::MockComputeEngine;
use encrypt_types::types::FheType;

use crate::requests::OnChainId;
use crate::store::{CiphertextEntry, CiphertextStore};

/// SQLite-backed persistent store for dev mode.
///
/// Thread-safe via internal `Mutex<Connection>`.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create the database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ciphertexts (
                id       BLOB PRIMARY KEY,
                digest   BLOB NOT NULL,
                fhe_type INTEGER NOT NULL,
                blob     BLOB
            );
            CREATE TABLE IF NOT EXISTS digests (
                digest   BLOB PRIMARY KEY,
                value    BLOB NOT NULL
            );",
        )?;

        // Migrate legacy schema: if value_lo/value_hi columns exist, migrate data
        // and recreate the table with the new schema.
        let has_legacy = conn
            .prepare("SELECT value_lo FROM digests LIMIT 0")
            .is_ok();
        if has_legacy {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS digests_new (
                    digest BLOB PRIMARY KEY,
                    value  BLOB NOT NULL
                );
                INSERT OR IGNORE INTO digests_new (digest, value)
                    SELECT digest,
                           CAST(
                               ZEROBLOB(16) AS BLOB
                           )
                    FROM digests;
                DROP TABLE digests;
                ALTER TABLE digests_new RENAME TO digests;",
            )
            .ok();
        }

        // WAL mode for concurrent reads
        conn.pragma_update(None, "journal_mode", "WAL")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (for tests).
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    /// Load all digest→value mappings into a MockComputeEngine.
    pub fn load_into_engine(
        &self,
        engine: &mut MockComputeEngine,
    ) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT digest, value FROM digests")?;
        let mut count = 0;
        let rows = stmt.query_map([], |row| {
            let digest: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            Ok((digest, value))
        })?;

        for row in rows {
            let (digest_vec, value) = row?;
            if digest_vec.len() == 32 {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&digest_vec);
                engine.register_bytes(digest, value);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Save a digest→value mapping (bytes, supports vectors).
    pub fn save_digest_bytes(&self, digest: &[u8; 32], value: &[u8]) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO digests (digest, value) VALUES (?1, ?2)",
            params![digest.as_slice(), value],
        )
        .ok();
    }

    /// Save a digest→value mapping (u128 scalar, backward-compatible convenience).
    pub fn save_digest(&self, digest: &[u8; 32], value: u128) {
        self.save_digest_bytes(digest, &value.to_le_bytes());
    }
}

impl CiphertextStore for SqliteStore {
    fn put(
        &self,
        id: OnChainId,
        digest: [u8; 32],
        fhe_type: FheType,
        blob: Option<Vec<u8>>,
    ) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO ciphertexts (id, digest, fhe_type, blob) VALUES (?1, ?2, ?3, ?4)",
            params![id.as_slice(), digest.as_slice(), fhe_type as u8 as i64, blob],
        )
        .ok();
    }

    fn get_digest(&self, id: &OnChainId) -> Option<[u8; 32]> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT digest FROM ciphertexts WHERE id = ?1",
            params![id.as_slice()],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let mut digest = [0u8; 32];
                if bytes.len() == 32 {
                    digest.copy_from_slice(&bytes);
                }
                Ok(digest)
            },
        )
        .ok()
    }

    fn get(&self, id: &OnChainId) -> Option<CiphertextEntry> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT digest, fhe_type, blob FROM ciphertexts WHERE id = ?1",
            params![id.as_slice()],
            |row| {
                let digest_bytes: Vec<u8> = row.get(0)?;
                let fhe_type_val: i64 = row.get(1)?;
                let blob: Option<Vec<u8>> = row.get(2)?;

                let mut digest = [0u8; 32];
                if digest_bytes.len() == 32 {
                    digest.copy_from_slice(&digest_bytes);
                }
                let fhe_type =
                    FheType::from_u8(fhe_type_val as u8).unwrap_or(FheType::EUint64);

                Ok(CiphertextEntry {
                    digest,
                    fhe_type,
                    blob,
                })
            },
        )
        .ok()
    }

    fn remove(&self, id: &OnChainId) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ciphertexts WHERE id = ?1",
            params![id.as_slice()],
        )
        .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_put_and_get() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = [1u8; 32];
        let digest = [0xAB; 32];

        store.put(id, digest, FheType::EUint64, None);

        assert_eq!(store.get_digest(&id), Some(digest));
        let entry = store.get(&id).unwrap();
        assert_eq!(entry.fhe_type, FheType::EUint64);
        assert!(entry.blob.is_none());
    }

    #[test]
    fn sqlite_overwrite() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = [1u8; 32];

        store.put(id, [0xAA; 32], FheType::EUint64, None);
        store.put(id, [0xBB; 32], FheType::EUint64, None);

        assert_eq!(store.get_digest(&id), Some([0xBB; 32]));
    }

    #[test]
    fn sqlite_remove() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = [1u8; 32];
        store.put(id, [0xAA; 32], FheType::EUint64, None);
        store.remove(&id);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn sqlite_digest_table() {
        let store = SqliteStore::open_in_memory().unwrap();
        let digest = [0xCC; 32];
        store.save_digest(&digest, 42);

        let mut engine = MockComputeEngine::new();
        let count = store.load_into_engine(&mut engine).unwrap();
        assert_eq!(count, 1);

        // Engine should now know this digest
        engine.register(digest, 42);
        let bytes = encrypt_compute::engine::ComputeEngine::decrypt(
            &mut engine,
            &digest,
            FheType::EUint64,
        )
        .unwrap();
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 42);
    }

    #[test]
    fn sqlite_large_value() {
        let store = SqliteStore::open_in_memory().unwrap();
        let digest = [0xDD; 32];
        let value: u128 = u128::MAX;
        store.save_digest(&digest, value);

        let mut engine = MockComputeEngine::new();
        store.load_into_engine(&mut engine).unwrap();
        engine.register(digest, value);
        let bytes = encrypt_compute::engine::ComputeEngine::decrypt(
            &mut engine,
            &digest,
            FheType::EUint128,
        )
        .unwrap();
        assert_eq!(u128::from_le_bytes(bytes[..16].try_into().unwrap()), value);
    }

    #[test]
    fn sqlite_vector_digest() {
        let store = SqliteStore::open_in_memory().unwrap();
        let digest = [0xEE; 32];
        let mut value = vec![0u8; 8192];
        value[0..4].copy_from_slice(&42u32.to_le_bytes());
        value[8188..8192].copy_from_slice(&99u32.to_le_bytes());
        store.save_digest_bytes(&digest, &value);

        let mut engine = MockComputeEngine::new();
        let count = store.load_into_engine(&mut engine).unwrap();
        assert_eq!(count, 1);

        engine.register_bytes(digest, value.clone());
        let bytes = encrypt_compute::engine::ComputeEngine::decrypt(
            &mut engine,
            &digest,
            FheType::EVectorU32,
        )
        .unwrap();
        assert_eq!(bytes.len(), 8192);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(bytes[8188..8192].try_into().unwrap()), 99);
    }
}
