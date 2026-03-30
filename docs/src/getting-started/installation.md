# Installation

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Prerequisites

- **Rust** (edition 2024): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Solana CLI** 3.x+: `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`
- **Bun** (for TypeScript clients): `curl -fsSL https://bun.sh/install | bash`

## Add Dependencies

### For Pinocchio Programs

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-pinocchio = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
pinocchio = "0.10"

[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
```

### For Anchor Programs

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-anchor = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
anchor-lang = "0.32"

[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
```

### For Native Programs

```toml
[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-native = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
solana-program = "4"

[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
```

## Client SDKs

### Rust gRPC Client

```toml
[dependencies]
encrypt-solana-client = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### TypeScript gRPC Client

```bash
bun add @encrypt.xyz/pre-alpha-solana-client
```

## Pre-Alpha Environment

The Encrypt program is deployed to **Solana devnet**. An executor is running at:

| Resource | Endpoint |
|----------|----------|
| **Encrypt gRPC** | `https://pre-alpha-dev-1.encrypt.ika-network.net:443` |
| **Solana RPC** | `https://api.devnet.solana.com` |
| **Program ID** | `TODO: will be updated after deployment` |

No local executor or validator setup needed — just connect to devnet.
