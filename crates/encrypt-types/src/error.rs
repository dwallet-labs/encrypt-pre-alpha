// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Executor/relayer is not authorized to submit results.
pub const UNAUTHORIZED_EXECUTOR: u32 = 6000;

/// Caller does not have Guard permission for this handle.
pub const UNAUTHORIZED_ACCESS: u32 = 6001;

/// FHE type discriminant is invalid.
pub const INVALID_FHE_TYPE: u32 = 6002;

/// FHE operation discriminant is invalid.
pub const INVALID_OPERATION: u32 = 6003;

/// Result has already been committed for this operation.
pub const ALREADY_COMMITTED: u32 = 6004;

/// Decryption/seal request has already been fulfilled.
pub const ALREADY_FULFILLED: u32 = 6005;

/// Cryptographic signature verification failed.
pub const INVALID_SIGNATURE: u32 = 6006;

/// Relayer is not authorized to fulfill requests.
pub const UNAUTHORIZED_RELAYER: u32 = 6007;

/// Ciphertext handle does not exist or is malformed.
pub const INVALID_HANDLE: u32 = 6008;

/// Referenced handle has not yet been committed by the executor.
pub const HANDLE_NOT_COMMITTED: u32 = 6009;

/// Guard permission already exists for this handle+address pair.
pub const PERMISSION_ALREADY_EXISTS: u32 = 6010;

/// Operand FHE types do not match the operation requirements.
pub const TYPE_MISMATCH: u32 = 6011;

/// Permit has expired (block height / timestamp exceeded).
pub const PERMIT_EXPIRED: u32 = 6012;

/// Permit signature verification failed.
pub const INVALID_PERMIT_SIGNATURE: u32 = 6013;

/// Batch exceeds `MAX_BATCH_SIZE`.
pub const BATCH_TOO_LARGE: u32 = 6014;
