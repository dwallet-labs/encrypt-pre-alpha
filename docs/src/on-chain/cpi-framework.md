# CPI Framework

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## EncryptCpi Trait

All three framework SDKs implement the same trait:

```rust
pub trait EncryptCpi {
    type Error;
    type Account<'a>: Clone where Self: 'a;

    fn invoke_execute_graph<'a>(
        &'a self, ix_data: &[u8], accounts: &[Self::Account<'a>],
    ) -> Result<(), Self::Error>;

    fn read_fhe_type<'a>(&'a self, account: Self::Account<'a>) -> Option<u8>;
    fn type_mismatch_error(&self) -> Self::Error;
}
```

## EncryptContext

Each framework provides `EncryptContext`:

```rust
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

The struct is identical across frameworks — only the account types differ:
- **Pinocchio**: `&'a AccountView`
- **Native**: `&'a AccountInfo<'info>`
- **Anchor**: `AccountInfo<'info>`

## Available Methods

| Method | Description |
|--------|-------------|
| `create_plaintext(fhe_type, bytes, ct)` | Create plaintext ciphertext |
| `create_plaintext_typed::<T>(value, ct)` | Type-safe plaintext creation |
| `execute_graph(ix_data, remaining)` | Execute computation graph |
| `execute_registered_graph(graph_pda, ix_data, remaining)` | Execute registered graph |
| `register_graph(pda, bump, hash, data)` | Register a reusable graph |
| `transfer_ciphertext(ct, new_authorized)` | Transfer authorization |
| `copy_ciphertext(source, new_ct, new_auth, transient)` | Copy with different auth |
| `make_public(ct)` | Make ciphertext public |
| `request_decryption(request, ct)` | Request decryption (returns digest) |
| `close_decryption_request(request, destination)` | Close and reclaim rent |

## DSL Extension Traits

`#[encrypt_fn]` generates extension traits that add graph-specific methods:

```rust
// Your DSL function:
#[encrypt_fn]
fn add(a: EUint64, b: EUint64) -> EUint64 { a + b }

// Call as a method on any EncryptContext:
ctx.add(input_a, input_b, output)?;
```

The generated method:
1. Verifies each input account's `fhe_type` at runtime
2. Builds the execute_graph instruction data
3. Assembles remaining accounts (inputs then outputs)
4. Invokes CPI
