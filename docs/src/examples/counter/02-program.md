# Confidential Counter: Building the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## 1. Cargo.toml

```toml
[package]
name = "confidential-counter-anchor"
edition.workspace = true

[dependencies]
encrypt-types = { workspace = true }
encrypt-dsl = { package = "encrypt-solana-dsl", path = "../../../program-sdk/dsl" }
encrypt-anchor = { workspace = true }
anchor-lang = { workspace = true }

[lib]
crate-type = ["cdylib", "lib"]
```

Three Encrypt crates:
- `encrypt-types` -- FHE type definitions (`EUint64`, `Uint64`, etc.)
- `encrypt-dsl` (aliased from `encrypt-solana-dsl`) -- the `#[encrypt_fn]` macro that generates FHE graphs + Solana CPI glue
- `encrypt-anchor` -- `EncryptContext` struct and account helpers for Anchor

## 2. FHE Graphs

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}
```

The `#[encrypt_fn]` macro does two things at compile time:

1. **Generates a graph function** (`increment_graph() -> Vec<u8>`) that returns a
   serialized computation graph in the Encrypt binary format. The graph has one
   `Input` node (the encrypted value), one `Constant` node (the literal `1`),
   one `Op` node (add or subtract), and one `Output` node.

2. **Generates a CPI extension trait** (`IncrementGraphCpi`) with a blanket
   implementation on `EncryptContext`. This gives you a method like
   `encrypt_ctx.increment_graph(input_ct, output_ct)` that builds and executes
   the `execute_graph` CPI to the Encrypt program.

The graph is embedded in the program binary. When the CPI fires, the Encrypt
program emits an event that the off-chain executor picks up. The executor
deserializes the graph, evaluates each node using real FHE operations, and
commits the result ciphertext on-chain.

Key point: the same ciphertext account can be both input and output (in-place
update). That's how `increment` works -- the counter value is updated without
creating new accounts.

## 3. Counter State

```rust
#[account]
#[derive(InitSpace)]
pub struct Counter {
    pub authority: Pubkey,          // who can increment/decrypt
    pub counter_id: [u8; 32],      // unique ID, used as PDA seed
    pub value: [u8; 32],           // pubkey of the ciphertext account
    pub pending_digest: [u8; 32],  // digest from request_decryption
    pub revealed_value: u64,       // plaintext after decryption
    pub bump: u8,                  // PDA bump
}
```

- `value` stores the **pubkey** of a ciphertext account, not the ciphertext
  itself. Ciphertext accounts are owned by the Encrypt program.
- `pending_digest` is the store-and-verify pattern: when you request decryption,
  the Encrypt program returns a digest of the ciphertext at that moment. You
  store it and later verify the decryption result matches.
- `revealed_value` holds the plaintext once decrypted. Until then it's 0.

## 4. create_counter

```rust
pub fn create_counter(
    ctx: Context<CreateCounter>,
    counter_id: [u8; 32],
    initial_value_id: [u8; 32],
) -> Result<()> {
    let ctr = &mut ctx.accounts.counter;
    ctr.authority = ctx.accounts.authority.key();
    ctr.counter_id = counter_id;
    ctr.value = initial_value_id;
    ctr.pending_digest = [0u8; 32];
    ctr.revealed_value = 0;
    ctr.bump = ctx.bumps.counter;
    Ok(())
}
```

The caller creates an encrypted zero off-chain (via the gRPC `CreateInput`
RPC), which produces a ciphertext account on Solana. The caller passes that
account's pubkey as `initial_value_id`. The counter PDA just stores the
reference.

Account constraints:

```rust
#[derive(Accounts)]
#[instruction(counter_id: [u8; 32])]
pub struct CreateCounter<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Counter::INIT_SPACE,
        seeds = [b"counter", counter_id.as_ref()],
        bump,
    )]
    pub counter: Account<'info, Counter>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

The PDA is seeded by `["counter", counter_id]`. The `counter_id` is an
arbitrary 32-byte value chosen by the caller (typically a random keypair's
pubkey bytes).

## 5. increment / decrement

```rust
pub fn increment(ctx: Context<Increment>, cpi_authority_bump: u8) -> Result<()> {
    let encrypt_ctx = EncryptContext {
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

    let value_ct = ctx.accounts.value_ct.to_account_info();
    encrypt_ctx.increment_graph(value_ct.clone(), value_ct)?;

    Ok(())
}
```

Step by step:

1. Build an `EncryptContext` with all the Encrypt program accounts. These are
   infrastructure accounts (config, deposit, CPI authority PDA, network
   encryption key, event authority). Every Encrypt CPI needs them.

2. Call `encrypt_ctx.increment_graph(input, output)`. This method was generated
   by `#[encrypt_fn]`. It:
   - Serializes the graph bytes
   - Verifies the input ciphertext's `fhe_type` matches `EUint64`
   - Builds an `execute_graph` CPI instruction
   - Invokes the Encrypt program

3. The input and output are the **same account** (`value_ct`). This is an
   in-place update -- the executor will overwrite the ciphertext with the
   computed result.

The `cpi_authority_bump` is the bump for the PDA
`["__encrypt_cpi_authority"]` derived from your program ID. The Encrypt
program uses this to verify the CPI came from an authorized program.

`decrement` is identical except it calls `encrypt_ctx.decrement_graph(...)`.

The Increment accounts struct shows the full set of accounts needed for any
Encrypt CPI:

```rust
#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Value ciphertext account
    #[account(mut)]
    pub value_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
```

## 6. request_value_decryption

```rust
pub fn request_value_decryption(
    ctx: Context<RequestValueDecryption>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let ctr = &ctx.accounts.counter;
    require!(
        ctr.authority == ctx.accounts.payer.key(),
        CounterError::Unauthorized
    );

    let encrypt_ctx = EncryptContext { /* ... same fields ... */ };

    let digest = encrypt_ctx.request_decryption(
        &ctx.accounts.request_acct.to_account_info(),
        &ctx.accounts.ciphertext.to_account_info(),
    )?;

    let ctr = &mut ctx.accounts.counter;
    ctr.pending_digest = digest;

    Ok(())
}
```

`request_decryption` does two things:
1. Creates a `DecryptionRequest` account (keypair account, passed as a signer)
2. Returns a `[u8; 32]` digest -- a snapshot of the ciphertext's current state

You **must** store this digest. It prevents stale-value attacks: if someone
modifies the ciphertext between your request and the decryptor's response,
the digest won't match and `reveal_value` will fail.

The decryption request account is a keypair account (not a PDA). The caller
generates a fresh keypair and passes it as a signer. This avoids seed
conflicts when making multiple decryption requests.

## 7. reveal_value

```rust
pub fn reveal_value(ctx: Context<RevealValue>) -> Result<()> {
    let ctr = &mut ctx.accounts.counter;
    require!(
        ctr.authority == ctx.accounts.authority.key(),
        CounterError::Unauthorized
    );

    let expected_digest = &ctr.pending_digest;

    let req_data = ctx.accounts.request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        expected_digest,
    )
    .map_err(|_| CounterError::DecryptionNotComplete)?;

    ctr.revealed_value = *value;
    Ok(())
}
```

`read_decrypted_verified::<Uint64>` does three checks:
1. The decryption request is complete (decryptor has written the plaintext)
2. The ciphertext digest in the request matches `expected_digest`
3. The FHE type matches `Uint64` (the plaintext type corresponding to `EUint64`)

If all checks pass, it returns a reference to the plaintext value. The
`Uint64` type parameter is the **plaintext** counterpart of `EUint64`.

The `RevealValue` accounts are minimal -- no Encrypt CPI needed:

```rust
#[derive(Accounts)]
pub struct RevealValue<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
```

## Error Codes

```rust
#[error_code]
pub enum CounterError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Decryption not complete")]
    DecryptionNotComplete,
}
```
