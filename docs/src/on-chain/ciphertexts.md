# Ciphertext Accounts

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Structure

Ciphertext accounts are **regular keypair accounts** (not PDAs). The Encrypt program is the Solana owner.

| Field | Size | Description |
|-------|------|-------------|
| `ciphertext_digest` | 32 | Hash of the encrypted blob (zero until committed) |
| `authorized` | 32 | Who can use this (zero address = public) |
| `network_encryption_public_key` | 32 | FHE key it was encrypted under |
| `fhe_type` | 1 | Type discriminant (EBool=0, EUint64=4, etc.) |
| `status` | 1 | Pending(0) or Verified(1) |

Total: 98 bytes data + 2 bytes prefix (discriminator + version) = **100 bytes**.

## Account Pubkey = Identifier

The account's Solana pubkey IS the ciphertext identifier. There is no separate `ciphertext_id` field. This means:
- Client generates a keypair for each new ciphertext
- The pubkey is used in events, store lookups, and all references
- Update mode reuses the same account (same pubkey, new digest)

## Creating Ciphertexts

### Authority Input (`create_input_ciphertext`, disc 1)

User encrypts off-chain → submits to executor with ZK proof → executor verifies → calls this instruction. Status = Verified.

### Plaintext (`create_plaintext_ciphertext`, disc 2)

User provides plaintext value directly. Executor encrypts off-chain and commits digest later. Status = Pending until committed.

```rust
ctx.create_plaintext_typed::<Uint64>(&0u64, ciphertext_account)?;
```

### Graph Output (`execute_graph`, disc 4)

Computation outputs are created automatically by `execute_graph`:
- **New account** (empty) → creates Ciphertext with status=Pending
- **Existing account** (has data) → resets digest/status (update mode)

## Status Lifecycle

```
Created (by execute_graph) → PENDING → commit_ciphertext → VERIFIED
Created (by create_input)  → VERIFIED (immediately)
Created (by plaintext)     → PENDING → commit_ciphertext → VERIFIED
```
