# Encrypt Pre-Alpha SDK

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Build Solana programs that compute on encrypted data (FHE) using the Encrypt protocol.

## What's in this repo

This is the **developer SDK** for building programs on top of the Encrypt protocol. The Encrypt program is already deployed to Solana devnet, and a mock executor is running at the pre-alpha endpoint.

```
crates/                             Chain-agnostic core
  encrypt-types/                    FHE types, graph IR, Encryptor/Verifier traits
  encrypt-dsl/                      Graph builder + #[encrypt_fn_graph] macro
  encrypt-compute/                  MockComputeEngine for local testing
  encrypt-service/                  CiphertextStore for test harness
  encrypt-grpc/                     gRPC client types (proto-generated)

chains/solana/                      Solana SDK
  program-sdk/                      CPI SDKs (pinocchio, native, anchor)
  dev/                              EncryptTxBuilder + runtime traits
  test/                             LiteSVM + ProgramTest test harness
  clients/                          Rust + TypeScript clients (Codama + gRPC)
  examples/                         Example programs (voting, counter, ACL, coin-flip)

proto/                              gRPC service definition
docs/                               Developer documentation (mdbook)
```

## Quick Start

### Prerequisites

- Rust (edition 2024)
- Solana CLI 3.x (`cargo build-sbf`)
- Bun (for TypeScript)

### 1. Write an FHE program

```rust
use encrypt_dsl::prelude::*;

#[encrypt_fn]
fn transfer(from: EUint64, to: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let has_funds = from >= amount;
    let new_from = if has_funds { from - amount } else { from };
    let new_to = if has_funds { to + amount } else { to };
    (new_from, new_to)
}
```

### 2. Test locally

```bash
just test-unit         # fast, no SBF compilation
just test-examples     # full integration tests
```

### 3. Submit encrypted inputs via gRPC

**Rust:**
```rust
use encrypt_solana_client::grpc::EncryptClient;
use encrypt_types::encrypted::Uint64;

let mut client = EncryptClient::connect_default().await?;
let ct = client.create_input::<Uint64>(42u64, &program_id, &network_key).await?;
```

**TypeScript:**
```typescript
import { createEncryptClient, Chain } from "@encrypt.xyz/pre-alpha-solana-client/grpc";

const encrypt = createEncryptClient(); // connects to pre-alpha endpoint
const { ciphertextIdentifiers } = await encrypt.createInput({
  chain: Chain.Solana,
  inputs: [{ ciphertextBytes: Buffer.from(...), fheType: 4 }],
  authorized: programId.toBytes(),
  networkEncryptionPublicKey: networkKey,
});
```

## Pre-Alpha Environment

| Resource | Endpoint |
|----------|----------|
| **Encrypt gRPC** | `pre-alpha-dev-1.encrypt.ika-network.net:443` (TLS) |
| **Solana RPC** | `https://api.devnet.solana.com` |
| **Program ID** | `4ebfzWdKnrnGseuQpezXdG8yCdHqwQ1SSBHD3bWArND8` |

The executor is running and handles:
- `create_input_ciphertext` via gRPC (clients submit encrypted inputs)
- Graph evaluation + `commit_ciphertext` (automatic)
- Decryption + `respond_decryption` (automatic)

## Examples

See `chains/solana/examples/` for complete working programs:
- **Confidential Voting** — encrypted tallies with conditional increment
- **Counter** — basic encrypted counter
- **ACL** — access control patterns
- **Coin Flip** — random encrypted boolean

Each example has Pinocchio, Native, and Anchor variants with unit + integration tests.

## Documentation

```bash
# Build and serve the docs
cd docs && mdbook serve
```

## Build Commands

```bash
just build              # check all crates
just build-sbf          # build example SBF binaries
just test-unit          # unit tests (fast)
just test-examples      # integration tests (needs SBF)
just test               # full test suite
just lint               # fmt + clippy
just generate-clients   # regenerate Codama clients
```
