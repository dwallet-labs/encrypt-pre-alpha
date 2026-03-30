# Core Concepts

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Ciphertext

A **ciphertext** is an encrypted value stored on-chain. It's a regular Solana keypair account (not a PDA) owned by the Encrypt program. The account pubkey IS the ciphertext identifier.

```
Ciphertext account (98 bytes):
  ciphertext_digest(32)              — hash of the actual encrypted blob
  authorized(32)                     — who can use this (zero = public)
  network_encryption_public_key(32)  — FHE key it was encrypted under
  fhe_type(1)                        — EBool, EUint64, etc.
  status(1)                          — Pending(0) or Verified(1)
```

Ciphertexts are created in three ways:
- **Authority input** (`create_input_ciphertext`): user submits encrypted data + ZK proof → executor verifies → creates on-chain
- **Plaintext** (`create_plaintext_ciphertext`): user provides plaintext value → encrypted off-chain by executor
- **Graph output** (`execute_graph`): computation produces new ciphertexts (status=PENDING until executor commits)

## Computation Graph

FHE operations are compiled into a **computation graph** — a DAG of operations:

```
Input(a) ──┐
            ├── Op(Add) ── Output
Input(b) ──┘
```

The `#[encrypt_fn]` macro compiles your Rust code into this graph at compile time. The graph is serialized into the `execute_graph` instruction data. The executor evaluates it off-chain using real FHE.

## Executor & Decryptor

The **executor** and **decryptor** are off-chain services managed by the Encrypt network:

- **Executor**: listens for `GraphExecuted` events, evaluates computation graphs, commits results on-chain
- **Decryptor**: listens for `DecryptionRequested` events, performs threshold decryption, writes plaintext results on-chain

In the pre-alpha environment, these are hosted at `pre-alpha-dev-1.encrypt.ika-network.net:443`. You don't need to run them — just submit encrypted inputs via gRPC and let the network handle the rest.

For **local testing**, `EncryptTestContext` simulates both services in-process via `process_pending()`.

## Access Control

Every ciphertext has an `authorized` field:
- `authorized = [0; 32]` → **public** — anyone can compute on it or decrypt it
- `authorized = <pubkey>` → only that address can use it

Access is managed via:
- **`transfer_ciphertext`**: change who's authorized
- **`copy_ciphertext`**: create a copy with different authorization
- **`make_public`**: set authorized to zero (irreversible)

## Digest Verification

When requesting decryption, the `ciphertext_digest` is stored in the DecryptionRequest as a snapshot. At reveal time, verify the digest matches to ensure the ciphertext wasn't updated between request and response:

```rust
let digest = ctx.request_decryption(request_acct, ciphertext)?;
proposal.pending_digest = digest;  // store for later

// ... later, at reveal time ...
let value = read_decrypted_verified::<Uint64>(req_data, &proposal.pending_digest)?;
```
