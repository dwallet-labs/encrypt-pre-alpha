# Account Reference

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


All 7 account types in the Encrypt Solana program. Each account starts with a 2-byte prefix: `discriminator(1) | version(1)`, followed by the account data.

## Account Discriminators

| Discriminator | Account Type |
|---------------|-------------|
| 1 | EncryptConfig |
| 2 | Authority |
| 3 | DecryptionRequest |
| 4 | EncryptDeposit |
| 5 | RegisteredGraph |
| 6 | Ciphertext |
| 7 | NetworkEncryptionKey |

---

## EncryptConfig (disc 1)

Program-wide configuration. PDA seeds: `["encrypt_config"]`.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `1` |
| 1 | version | 1 | `1` |
| 2 | current_epoch | 8 | Current epoch (LE u64) |
| 10 | enc_per_input | 8 | ENC fee per input (LE u64) |
| 18 | enc_per_output | 8 | ENC fee per output (LE u64) |
| 26 | max_enc_per_op | 8 | Max ENC fee per operation (LE u64) |
| 34 | max_ops_per_graph | 2 | Max operations per graph (LE u16) |
| 36 | gas_base | 8 | Base SOL gas fee (LE u64) |
| 44 | gas_per_input | 8 | SOL gas fee per input (LE u64) |
| 52 | gas_per_output | 8 | SOL gas fee per output (LE u64) |
| 60 | gas_per_byte | 8 | SOL gas fee per byte (LE u64) |
| 68 | enc_mint | 32 | ENC SPL token mint address |
| 100 | enc_vault | 32 | ENC vault token account address |
| 132 | bump | 1 | PDA bump |

**Total: 2 + 131 = 133 bytes**

---

## Authority (disc 2)

Authorized operator (executor/decryptor). PDA seeds: `["authority", pubkey]`.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `2` |
| 1 | version | 1 | `1` |
| 2 | pubkey | 32 | Authority's public key |
| 34 | active | 1 | Active flag (0 = deactivated) |
| 35 | bump | 1 | PDA bump |

**Total: 2 + 34 = 36 bytes**

---

## DecryptionRequest (disc 3)

Decryption request with result storage. **Keypair account** (not PDA) -- no seed conflicts on multiple requests.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `3` |
| 1 | version | 1 | `1` |
| 2 | ciphertext | 32 | Ciphertext account pubkey |
| 34 | ciphertext_digest | 32 | Digest snapshot at request time |
| 66 | requester | 32 | Who requested decryption |
| 98 | fhe_type | 1 | FHE type (determines result size) |
| 99 | total_len | 4 | Expected result byte count (LE u32) |
| 103 | bytes_written | 4 | Bytes written so far (LE u32) |
| 107 | *result data* | N | Plaintext bytes (N = byte_width of fhe_type) |

**Total: 2 + 105 + byte_width(fhe_type) bytes**

Status is determined by `bytes_written`:
- `0` = pending (decryptor has not responded)
- `== total_len` = complete (result is ready)

---

## EncryptDeposit (disc 4)

Fee deposit for a user. PDA seeds: `["encrypt_deposit", owner]`.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `4` |
| 1 | version | 1 | `1` |
| 2 | owner | 32 | Deposit owner pubkey |
| 34 | enc_balance | 8 | ENC token balance (LE u64) |
| 42 | gas_balance | 8 | SOL gas balance (LE u64) |
| 50 | pending_enc_withdrawal | 8 | Pending ENC withdrawal (LE u64) |
| 58 | pending_gas_withdrawal | 8 | Pending SOL withdrawal (LE u64) |
| 66 | withdrawal_epoch | 8 | Epoch when withdrawal becomes available (LE u64) |
| 74 | num_txs | 8 | Transaction counter (LE u64) |
| 82 | bump | 1 | PDA bump |

**Total: 2 + 81 = 83 bytes**

---

## RegisteredGraph (disc 5)

A reusable computation graph stored on-chain. PDA seeds: `["registered_graph", graph_hash]`.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `5` |
| 1 | version | 1 | `1` |
| 2 | graph_hash | 32 | SHA-256 hash of graph data |
| 34 | registrar | 32 | Who registered the graph |
| 66 | num_inputs | 2 | Number of inputs (LE u16) |
| 68 | num_outputs | 2 | Number of outputs (LE u16) |
| 70 | num_ops | 2 | Number of operations (LE u16) |
| 72 | finalized | 1 | Finalized flag |
| 73 | bump | 1 | PDA bump |
| 74 | graph_data_len | 2 | Actual graph data length (LE u16) |
| 76 | graph_data | 4096 | Graph data (padded to max) |

**Total: 2 + 4170 = 4172 bytes**

Maximum graph data: 4096 bytes.

---

## Ciphertext (disc 6)

An encrypted value. **Keypair account** (not PDA) -- the account pubkey IS the ciphertext identifier.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `6` |
| 1 | version | 1 | `1` |
| 2 | ciphertext_digest | 32 | Hash of the encrypted blob (zero until committed) |
| 34 | authorized | 32 | Who can use this (`[0; 32]` = public) |
| 66 | network_encryption_public_key | 32 | FHE key it was encrypted under |
| 98 | fhe_type | 1 | Type discriminant (EBool=0, EUint64=4, etc.) |
| 99 | status | 1 | Pending(0) or Verified(1) |

**Total: 2 + 98 = 100 bytes**

Status values:
- `0` = PENDING -- waiting for executor to commit
- `1` = VERIFIED -- digest is valid, ciphertext can be used as input

---

## NetworkEncryptionKey (disc 7)

FHE network public key. PDA seeds: `["network_encryption_key", key_bytes]`.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | discriminator | 1 | `7` |
| 1 | version | 1 | `1` |
| 2 | network_encryption_public_key | 32 | FHE network public key bytes |
| 34 | active | 1 | Active flag (0 = deactivated) |
| 35 | bump | 1 | PDA bump |

**Total: 2 + 34 = 36 bytes**

---

## Account Type Summary

| Account | Disc | Type | Size (bytes) | PDA Seeds |
|---------|------|------|-------------|-----------|
| EncryptConfig | 1 | PDA | 133 | `["encrypt_config"]` |
| Authority | 2 | PDA | 36 | `["authority", pubkey]` |
| DecryptionRequest | 3 | Keypair | 107 + N | -- |
| EncryptDeposit | 4 | PDA | 83 | `["encrypt_deposit", owner]` |
| RegisteredGraph | 5 | PDA | 4172 | `["registered_graph", graph_hash]` |
| Ciphertext | 6 | Keypair | 100 | -- |
| NetworkEncryptionKey | 7 | PDA | 36 | `["network_encryption_key", key_bytes]` |
