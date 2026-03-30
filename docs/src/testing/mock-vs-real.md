# Mock vs Real FHE

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Mock Mode (Pre-Alpha)

The pre-alpha environment uses **mock FHE** — operations are performed as plaintext arithmetic with keccak256 digests. This means:

- `add(encrypt(10), encrypt(32))` → `encrypt(42)` — correct result, no actual encryption
- Graph evaluation is instantaneous (no FHE overhead)
- Decryption is trivial
- **No security** — values are not encrypted on-chain

Your program logic, computation graphs, and client code all work identically in mock and real mode. Only the off-chain executor differs.

## Real REFHE Mode (Coming Soon)

In production, the executor will use the REFHE library:
- Actual homomorphic encryption on ciphertext blobs
- Decryption requires threshold MPC (multiple decryptor nodes)
- Full privacy — values are never visible on-chain

**No code changes required** — the same `#[encrypt_fn]` graphs, CPI calls, and gRPC client calls work in both modes.
