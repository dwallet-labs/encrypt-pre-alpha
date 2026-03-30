# Quick Start

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


Build your first encrypted program in 5 minutes.

## 1. Write an FHE Function

```rust
use encrypt_dsl::prelude::*;

#[encrypt_fn]
fn add(a: EUint64, b: EUint64) -> EUint64 {
    a + b
}
```

The `#[encrypt_fn]` macro generates:
- `add()` — returns the serialized computation graph bytes
- `AddCpi` — an extension trait on `EncryptCpi` with method `ctx.add(a, b, output)?`

## 2. Use It in Your Program

### Pinocchio

```rust
use encrypt_pinocchio::EncryptContext;

let ctx = EncryptContext { /* ... */ };
ctx.add(input_a, input_b, output_ct)?;
```

### Anchor

```rust
use encrypt_anchor::EncryptContext;

let ctx = EncryptContext { /* ... */ };
ctx.add(input_a.to_account_info(), input_b.to_account_info(), output.to_account_info())?;
```

### Native

```rust
use encrypt_native::EncryptContext;

let ctx = EncryptContext { /* ... */ };
ctx.add(input_a.clone(), input_b.clone(), output.clone())?;
```

## 3. Test It

```rust
#[cfg(test)]
mod tests {
    use encrypt_solana_test::EncryptTestContext;
    use encrypt_types::encrypted::Uint64;

    #[test]
    fn test_add() {
        let mut ctx = EncryptTestContext::new_default();
        let user = ctx.new_funded_keypair();

        let a = ctx.create_input::<Uint64>(10, &user.pubkey());
        let b = ctx.create_input::<Uint64>(32, &user.pubkey());

        let graph = super::add();
        let outputs = ctx.execute_and_commit(&graph, &[a, b], 1, &[], &user);

        let result = ctx.decrypt::<Uint64>(&outputs[0], &user);
        assert_eq!(result, 42);
    }
}
```

## 4. Client SDK (gRPC)

Submit encrypted inputs and read ciphertexts via the gRPC client:

### Rust

```rust
use encrypt_solana_client::grpc::{EncryptClient, TypedInput};
use encrypt_types::encrypted::{Uint64, Bool};

// Connect to pre-alpha endpoint
let mut client = EncryptClient::connect().await?;

// Create a single encrypted input
let ct = client.create_input::<Uint64>(42u64, &program_id, &network_key).await?;

// Create batch inputs (one proof covers all)
let cts = client.create_inputs(
    &[TypedInput::new::<Uint64>(&10u64), TypedInput::new::<Bool>(&true)],
    &program_id, &network_key,
).await?;

// Read a ciphertext off-chain (signs request with keypair)
let result = client.read_ciphertext(&ct, &reencryption_key, epoch, &keypair).await?;
// result.value = plaintext bytes (mock) or re-encrypted ciphertext (production)
// result.fhe_type, result.digest
```

### TypeScript

```typescript
import { createEncryptClient, encodeReadCiphertextMessage, Chain } from "@encrypt.xyz/pre-alpha-solana-client/grpc";

const client = createEncryptClient();

// Create encrypted input
const { ciphertextIdentifiers } = await client.createInput({
  chain: Chain.SOLANA,
  inputs: [{ ciphertextBytes: ciphertext, fheType: 4 }],
  proof: proofBytes,
  authorized: programId.toBytes(),
  networkEncryptionPublicKey: networkKey,
});

// Read ciphertext off-chain
const msg = encodeReadCiphertextMessage(Chain.SOLANA, ctId, reencryptionKey, epoch);
const result = await client.readCiphertext({ message: msg, signature, signer });
```

## What Happens Under the Hood

1. Your program calls `execute_graph` → on-chain creates output ciphertext accounts (status=PENDING)
2. The executor detects the event → evaluates the computation graph → calls `commit_ciphertext` (status=VERIFIED)
3. When you call `request_decryption` → the decryptor responds with the plaintext result
4. Your program reads the result from the DecryptionRequest account
5. Off-chain reads via `read_ciphertext` gRPC — public ciphertexts are open, private ones require signed request

In test mode, `EncryptTestContext` handles all of this automatically via `process_pending()`.

## Pre-Alpha Environment

| Resource | Endpoint |
|----------|----------|
| **Encrypt gRPC** | `pre-alpha-dev-1.encrypt.ika-network.net:443` (TLS) |
| **Solana Network** | Devnet (`https://api.devnet.solana.com`) |
| **Program ID** | `4ebfzWdKnrnGseuQpezXdG8yCdHqwQ1SSBHD3bWArND8` |
