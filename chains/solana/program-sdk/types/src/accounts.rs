// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Shared account types and byte-level readers for Encrypt program state.
//!
//! Framework-agnostic (no pinocchio/solana-program dependency).
//! Used by pinocchio, native, and anchor SDKs.

use encrypt_types::encrypted::EncryptedType;

// ── Layout offsets ──

/// Ciphertext account layout offsets (after 2-byte disc+ver prefix).
/// Fields: ciphertext_digest(32), authorized(32), network_encryption_public_key(32), fhe_type(1), status(1)
pub const CT_CIPHERTEXT_DIGEST: usize = 2;
pub const CT_AUTHORIZED: usize = 34; // 2 + 32
pub const CT_FHE_TYPE: usize = 98; // 2 + 32 + 32 + 32
pub const CT_STATUS: usize = 99;
pub const CT_LEN: usize = 100; // 2 + 98

/// DecryptionRequestHeader layout offsets (after 2-byte disc+ver prefix).
/// Fields: ciphertext(32), ciphertext_digest(32), requester(32), fhe_type(1), total_len(4), bytes_written(4)
pub const DR_CIPHERTEXT: usize = 2;
pub const DR_CIPHERTEXT_DIGEST: usize = 34;
pub const DR_REQUESTER: usize = 66;
pub const DR_FHE_TYPE: usize = 98;
pub const DR_TOTAL_LEN: usize = 99;
pub const DR_BYTES_WRITTEN: usize = 103;
pub const DR_HEADER_END: usize = 107; // 2 + 105

/// Zero address means public.
pub const AUTHORIZED_PUBLIC: [u8; 32] = [0u8; 32];

// ── Typed decryption status ──

/// Typed status of a decryption request.
///
/// Generic over `T: EncryptedType` — the `Complete` variant holds a
/// zero-copy reference to the decrypted value as `&T::DecryptedValue`.
pub enum DecryptionRequestStatus<'a, T: EncryptedType> {
    /// No bytes written yet — waiting for authority to respond.
    Pending,
    /// Authority has written some bytes but not all.
    InProgress {
        bytes_written: u32,
        total_len: u32,
    },
    /// All bytes written — result is ready to read as `&T::DecryptedValue`.
    Complete {
        value: &'a T::DecryptedValue,
    },
}

// ── Pure byte readers (return Option, no framework error type) ──

/// Read the typed decryption status from raw account data.
///
/// Returns `None` if the data is too short or type width doesn't match.
pub fn parse_decryption_status<'a, T: EncryptedType>(
    data: &'a [u8],
) -> Option<DecryptionRequestStatus<'a, T>> {
    if data.len() < DR_HEADER_END {
        return None;
    }
    let total = u32::from_le_bytes(data[DR_TOTAL_LEN..DR_TOTAL_LEN + 4].try_into().ok()?);
    let written = u32::from_le_bytes(data[DR_BYTES_WRITTEN..DR_BYTES_WRITTEN + 4].try_into().ok()?);

    if written == 0 {
        Some(DecryptionRequestStatus::Pending)
    } else if written < total {
        Some(DecryptionRequestStatus::InProgress {
            bytes_written: written,
            total_len: total,
        })
    } else {
        let end = DR_HEADER_END + total as usize;
        if data.len() < end || total as usize != T::BYTE_WIDTH {
            return None;
        }
        Some(DecryptionRequestStatus::Complete {
            value: T::from_plaintext_bytes(&data[DR_HEADER_END..end]),
        })
    }
}

/// Read the decrypted value from raw account data, only if complete.
pub fn parse_decrypted<'a, T: EncryptedType>(data: &'a [u8]) -> Option<&'a T::DecryptedValue> {
    match parse_decryption_status::<T>(data)? {
        DecryptionRequestStatus::Complete { value } => Some(value),
        _ => None,
    }
}

/// Read the ciphertext_digest from a Ciphertext account.
pub fn parse_ciphertext_digest(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < CT_LEN {
        return None;
    }
    Some(data[CT_CIPHERTEXT_DIGEST..CT_CIPHERTEXT_DIGEST + 32].try_into().ok()?)
}

/// Read the ciphertext_digest snapshot from a DecryptionRequest account.
pub fn parse_decryption_digest(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < DR_HEADER_END {
        return None;
    }
    Some(data[DR_CIPHERTEXT_DIGEST..DR_CIPHERTEXT_DIGEST + 32].try_into().ok()?)
}

/// Read the decrypted value, verifying the request's ciphertext_digest matches
/// the expected digest. Returns None if digests don't match or request not complete.
///
/// Use `parse_ciphertext_digest(ct_data)` to extract the digest from a ciphertext account.
pub fn parse_decrypted_verified<'a, T: EncryptedType>(
    request_data: &'a [u8],
    expected_digest: &[u8; 32],
) -> Option<&'a T::DecryptedValue> {
    let req_digest = parse_decryption_digest(request_data)?;
    if req_digest != expected_digest {
        return None;
    }
    parse_decrypted::<T>(request_data)
}

/// Read the authorized address from a Ciphertext account.
pub fn parse_ciphertext_authorized(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < CT_LEN {
        return None;
    }
    Some(data[CT_AUTHORIZED..CT_AUTHORIZED + 32].try_into().ok()?)
}

/// Check if a Ciphertext is public (authorized == zero).
pub fn parse_ciphertext_is_public(data: &[u8]) -> Option<bool> {
    let auth = parse_ciphertext_authorized(data)?;
    Some(*auth == AUTHORIZED_PUBLIC)
}

/// Read the ciphertext status (0=Pending, 1=Verified).
pub fn parse_ciphertext_status(data: &[u8]) -> Option<u8> {
    if data.len() < CT_LEN { None } else { Some(data[CT_STATUS]) }
}

/// Read the requester from a DecryptionRequest account.
pub fn parse_decryption_requester(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < DR_HEADER_END {
        return None;
    }
    Some(data[DR_REQUESTER..DR_REQUESTER + 32].try_into().ok()?)
}

/// Read the ciphertext pubkey from a DecryptionRequest account.
pub fn parse_decryption_ciphertext(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < DR_HEADER_END {
        return None;
    }
    Some(data[DR_CIPHERTEXT..DR_CIPHERTEXT + 32].try_into().ok()?)
}
