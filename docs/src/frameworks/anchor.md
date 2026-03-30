# Anchor

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Dependencies

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-anchor = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
anchor-lang = "0.32"
```

## Setup EncryptContext

```rust
use encrypt_anchor::EncryptContext;

let ctx = EncryptContext {
    encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
    config: ctx.accounts.config.to_account_info(),
    deposit: ctx.accounts.deposit.to_account_info(),
    cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
    caller_program: ctx.accounts.caller_program.to_account_info(),
    network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
    payer: ctx.accounts.payer.to_account_info(),
    event_authority: ctx.accounts.event_authority.to_account_info(),
    system_program: ctx.accounts.system_program.to_account_info(),
    cpi_authority_bump,
};
```

## Execute Graph

```rust
let yes_ct = ctx.accounts.yes_ct.to_account_info();
let no_ct = ctx.accounts.no_ct.to_account_info();
let vote_ct = ctx.accounts.vote_ct.to_account_info();
encrypt_ctx.cast_vote_graph(
    yes_ct.clone(), no_ct.clone(), vote_ct,
    yes_ct, no_ct,
)?;
```

Note: Anchor's `AccountInfo` is `Clone`, so you can pass the same account as both input and output.

## Request Decryption

```rust
let digest = encrypt_ctx.request_decryption(
    &ctx.accounts.request_acct.to_account_info(),
    &ctx.accounts.ciphertext.to_account_info(),
)?;
```

## Read Decrypted Value

```rust
use encrypt_anchor::accounts::{read_decrypted_verified, ciphertext_digest};

let ct_data = ctx.accounts.ciphertext.try_borrow_data()?;
let digest = ciphertext_digest(&ct_data)?;
let req_data = ctx.accounts.request_acct.try_borrow_data()?;
let value = read_decrypted_verified::<Uint64>(&req_data, digest)?;
```

## Account Structs

Include Encrypt accounts in your Anchor `#[derive(Accounts)]`:

```rust
#[derive(Accounts)]
pub struct CastVote<'info> {
    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
    pub voter: Signer<'info>,
    /// CHECK: Vote ciphertext
    #[account(mut)]
    pub vote_ct: UncheckedAccount<'info>,
    /// CHECK: Yes count ciphertext
    #[account(mut)]
    pub yes_ct: UncheckedAccount<'info>,
    /// CHECK: No count ciphertext
    #[account(mut)]
    pub no_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    // ... config, deposit, cpi_authority, etc.
}
```

## Full Example

See `chains/solana/examples/confidential-voting-anchor/` for a complete program.
