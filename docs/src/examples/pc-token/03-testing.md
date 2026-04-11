# PC-Token: Testing

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## Unit Tests (10)

FHE graph logic tested via mock compute engine:

- `mint_to` — balance + amount
- `transfer_ok` / `transfer_insufficient` — conditional transfer
- `burn_ok` / `burn_insufficient` — conditional burn
- `transfer_from_ok` / `transfer_from_insufficient` — delegated with allowance check
- `unwrap_burn_sufficient` / `unwrap_burn_insufficient` — burn with receipt output
- `graph_shapes` — verify input/output counts

## LiteSVM Integration Tests (9)

Full on-chain lifecycle with Encrypt CPI:

- `test_initialize_mint` / `test_initialize_mint_with_freeze_authority`
- `test_initialize_account` — create token account, verify encrypted zero balance
- `test_mint_to` — set balance via harness, verify encrypted value
- `test_transfer` / `test_transfer_insufficient_funds` — encrypted transfer
- `test_approve_and_transfer_from` — delegation + delegated transfer
- `test_freeze_blocks_transfer` — freeze/thaw cycle
- `test_full_lifecycle` — mint → transfer → freeze → thaw → approve → transfer_from

## E2E Devnet Test

Full USDC → pcUSDC → USDC flow on Solana devnet:

```
Alice wraps 10 USDC → sends 5 pcUSDC to Bob → Bob unwraps 5 →
Alice sends 3 to Mark → Mark unwraps 2 → Alice unwraps 1 →
Final: Alice=1 USDC+1cp, Bob=5 USDC, Mark=2 USDC+1cp, Vault=2 USDC
```

Run:
```bash
cargo build-sbf --manifest-path chains/solana/examples/pc-token/pinocchio/Cargo.toml
solana program deploy target/deploy/pc_token.so
bun chains/solana/examples/pc-token/e2e/main.ts <ENCRYPT_ID> <PC_TOKEN_ID>
```