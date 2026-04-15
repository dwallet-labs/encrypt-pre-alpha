# Quasar Framework

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption -- all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

The `encrypt-quasar` crate provides a Quasar-native CPI SDK for the Encrypt program. [Quasar](https://github.com/blueshift-gg/quasar) is a zero-copy Solana program framework with alignment-1 Pod types, declarative account validation, and `invoke_signed_unchecked` CPI.

## Dependencies

```toml
[dependencies]
encrypt-types = { git = "https://github.com/nicedwalletlabs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/nicedwalletlabs/encrypt-pre-alpha" }
encrypt-quasar = { git = "https://github.com/nicedwalletlabs/encrypt-pre-alpha" }
quasar-lang = { git = "https://github.com/blueshift-gg/quasar", branch = "master" }
solana-address = { version = "2.4", features = ["curve25519"] }

[lib]
crate-type = ["cdylib", "lib"]
```

## EncryptContext

```rust
use encrypt_quasar::EncryptContext;

let ctx = EncryptContext {
    encrypt_program: self.encrypt_program.to_account_view(),
    config: self.config.to_account_view(),
    deposit: self.deposit.to_account_view(),
    cpi_authority: self.cpi_authority.to_account_view(),
    caller_program: self.caller_program.to_account_view(),
    network_encryption_key: self.network_encryption_key.to_account_view(),
    payer: self.payer.to_account_view(),
    event_authority: self.event_authority.to_account_view(),
    system_program: self.system_program.to_account_view(),
    cpi_authority_bump,
};
```

Convert Quasar owned types (`Signer`, `UncheckedAccount`, `Program<System>`) to `&AccountView` using `.to_account_view()`.

## Creating Encrypted Zeros

```rust
use encrypt_types::encrypted::Uint64;

ctx.create_plaintext_typed::<Uint64>(
    &0u64,
    self.value_ct.to_account_view(),
)?;
```

## Executing FHE Graphs

Define graphs with `#[encrypt_fn]`:

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}
```

Execute via CPI (generated `_cpi` function on EncryptContext):

```rust
ctx.increment_graph(
    self.value_ct.to_account_view(),  // input
    self.value_ct.to_account_view(),  // output (same account for in-place)
)?;
```

## Requesting Decryption

```rust
let digest = ctx.request_decryption(
    self.request_acct.to_account_view(),
    self.ciphertext.to_account_view(),
)?;

// Store digest in your program state for later verification
self.my_state.pending_digest = digest;
```

## Reading Decrypted Values

```rust
use encrypt_quasar::accounts;
use encrypt_types::encrypted::Uint64;

let req_data = unsafe { self.request_acct.to_account_view().borrow_unchecked() };
let value: &u64 = accounts::read_decrypted_verified::<Uint64>(
    req_data,
    &self.my_state.pending_digest,
)?;
```

## Quasar Program Patterns

Quasar programs use owned types, explicit discriminators, and `impl` handlers:

```rust
#![no_std]

use encrypt_quasar::EncryptContext;
use quasar_lang::prelude::*;

declare_id!("...");

#[program]
mod my_program {
    use super::*;

    #[instruction(discriminator = 0)]
    pub fn create(ctx: Ctx<Create>, /* args */) -> Result<(), ProgramError> {
        ctx.accounts.create(/* args */)
    }
}

#[derive(Accounts)]
pub struct Create {
    #[account(init, payer = payer, seeds = MyState::seeds(state_id), bump)]
    pub state: Account<MyState>,

    // Encrypt program accounts
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}
```

## Performance

Quasar produces the smallest binaries and near-lowest CU usage of any declarative framework:

| Consideration | Pinocchio | Native | Anchor | Quasar |
|---|---|---|---|---|
| **CU efficiency** | Best | Good | Good | Best |
| **Binary size** | Small | Medium | Largest | Smallest |
| **`no_std` support** | Yes | No | No | Yes |
| **Account validation** | Manual | Manual | Declarative | Declarative |
| **Zero-copy** | Manual | No | No | Built-in |

All four SDKs use the same CPI authority seed (`b"__encrypt_cpi_authority"`), the same instruction discriminators, and the same `EncryptCpi` trait. Programs built with any SDK are fully interoperable.
