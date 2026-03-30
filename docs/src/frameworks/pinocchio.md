# Pinocchio

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Dependencies

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-pinocchio = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
pinocchio = "0.10"
pinocchio-system = "0.5"
```

## Setup EncryptContext

```rust
use encrypt_pinocchio::EncryptContext;

let ctx = EncryptContext {
    encrypt_program,
    config,
    deposit,
    cpi_authority,
    caller_program,
    network_encryption_key,
    payer,
    event_authority,
    system_program,
    cpi_authority_bump,
};
```

## Create Encrypted Zeros

```rust
use encrypt_types::encrypted::Uint64;

ctx.create_plaintext_typed::<Uint64>(&0u64, ciphertext_acct)?;
```

## Execute Graph

```rust
// Via DSL-generated method (preferred)
ctx.cast_vote_graph(yes_ct, no_ct, vote_ct, yes_ct, no_ct)?;

// Via manual execute_graph
ctx.execute_graph(&ix_data, &[yes_ct, no_ct, vote_ct, yes_ct, no_ct])?;
```

## Request Decryption

```rust
let digest = ctx.request_decryption(request_acct, ciphertext)?;
// Store digest for later verification
```

## Read Decrypted Value

```rust
use encrypt_pinocchio::accounts::{read_decrypted_verified, ciphertext_digest};

let ct_data = unsafe { ciphertext.borrow_unchecked() };
let digest = ciphertext_digest(ct_data)?;
let req_data = unsafe { request_acct.borrow_unchecked() };
let value: &u64 = read_decrypted_verified::<Uint64>(req_data, digest)?;
```

## Full Example

See `chains/solana/examples/confidential-voting-pinocchio/` for a complete confidential voting program.
