# Native (solana-program)

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Dependencies

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-native = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
solana-program = "4"
```

## Setup EncryptContext

```rust
use encrypt_native::EncryptContext;

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
ctx.cast_vote_graph(
    yes_ct.clone(), no_ct.clone(), vote_ct.clone(),
    yes_ct.clone(), no_ct.clone(),
)?;
```

Note: Native `AccountInfo` is `Clone`, so you can clone for duplicate references.

## Request Decryption

```rust
let digest = ctx.request_decryption(request_acct, ciphertext)?;
```

## Read Decrypted Value

```rust
use encrypt_native::accounts::{read_decrypted_verified, ciphertext_digest};

let ct_data = ciphertext.try_borrow_data()?;
let digest = ciphertext_digest(&ct_data)?;
let req_data = request_acct.try_borrow_data()?;
let value = read_decrypted_verified::<Uint64>(&req_data, digest)?;
```

## Full Example

See `chains/solana/examples/confidential-voting-native/` for a complete program.
