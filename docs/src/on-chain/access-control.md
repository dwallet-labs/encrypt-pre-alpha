# Access Control

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## The `authorized` Field

Every ciphertext has an `authorized` field (32 bytes):

| Value | Meaning |
|-------|---------|
| `[0; 32]` (zero) | **Public** — anyone can compute on it and decrypt it |
| `<pubkey>` | Only that address can use it (wallet signer or program) |

There are no separate guard/permission accounts. The ciphertext IS the access token.

## Managing Access

### Transfer Authorization

Move authorization from current party to a new party:

```rust
// Pinocchio
ctx.transfer_ciphertext(ciphertext, new_authorized)?;

// Anchor
ctx.transfer_ciphertext(&ciphertext.to_account_info(), &new_auth.to_account_info())?;
```

The current authorized party must sign the transaction.

### Copy with Different Authorization

Create a copy of the ciphertext authorized to a different party:

```rust
ctx.copy_ciphertext(
    source_ciphertext,
    new_ciphertext,     // empty keypair account
    new_authorized,
    false,              // permanent (rent-exempt)
)?;
```

Set `transient: true` for copies that only live within the current transaction (0 lamports, GC'd after tx).

### Make Public

Set authorized to zero — irreversible, anyone can use it:

```rust
ctx.make_public(ciphertext)?;
```

Idempotent — calling on an already-public ciphertext is a no-op.

## CPI Authorization

When a program calls Encrypt via CPI:
- **Signer path**: `caller` is a wallet signer → `authorized` checked against signer pubkey
- **Program path**: `caller` is executable → next account is CPI authority PDA (`__encrypt_cpi_authority`) → `authorized` checked against program address

Detection is automatic via `caller.executable()`.
