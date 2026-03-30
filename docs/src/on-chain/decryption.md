# Decryption

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Request → Respond → Read

Decryption is an async on-chain request/response pattern:

### 1. Request Decryption

```rust
let digest = ctx.request_decryption(request_acct, ciphertext)?;
// Store `digest` in your program state for later verification
proposal.pending_digest = digest;
```

- Creates a DecryptionRequest keypair account
- Stores a `ciphertext_digest` snapshot (stale-value protection)
- Returns the digest — **store it for verification at read time**
- The decryptor detects the event and responds

### 2. Process (Automatic)

The decryptor:
1. Detects `DecryptionRequestedEvent`
2. Performs threshold MPC decryption (or mock decryption locally)
3. Calls `respond_decryption` to write plaintext bytes into the request account

### 3. Read Result

```rust
let req_data = request_acct.try_borrow_data()?;
let value = read_decrypted_verified::<Uint64>(&req_data, &proposal.pending_digest)?;
```

**Always verify against the stored digest** — if the ciphertext was updated between request and response, the digest won't match and `read_decrypted_verified` returns an error.

### 4. Close Request

After reading the result, reclaim rent:

```rust
ctx.close_decryption_request(request_acct, destination)?;
```

## DecryptionRequest Account

| Field | Size | Description |
|-------|------|-------------|
| `ciphertext` | 32 | Ciphertext account pubkey |
| `ciphertext_digest` | 32 | Digest snapshot at request time |
| `requester` | 32 | Who requested |
| `fhe_type` | 1 | Type (determines result byte width) |
| `total_len` | 4 | Expected result size |
| `bytes_written` | 4 | Progress (0=pending, ==total_len=complete) |
| *result data* | variable | Plaintext bytes (appended after header) |

Total: 2 (prefix) + 105 (header) + byte_width(fhe_type) bytes.

## Type-Safe Reading

Use the SDK helpers:

```rust
// Pinocchio
use encrypt_pinocchio::accounts::{read_decrypted_verified, ciphertext_digest};

// Read digest from ciphertext account
let ct_data = ciphertext.borrow_unchecked();
let digest = ciphertext_digest(ct_data)?;

// Verify and read result
let value: &u64 = read_decrypted_verified::<Uint64>(req_data, digest)?;
```

## Best Practice: Store-and-Verify

```rust
// At request time:
let digest = ctx.request_decryption(request, ciphertext)?;
state.pending_digest = digest;

// At reveal time:
let value = read_decrypted_verified::<Uint64>(req_data, &state.pending_digest)?;
```

This pattern protects against the ciphertext being updated between request and reveal.
