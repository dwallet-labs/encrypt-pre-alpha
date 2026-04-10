# CP-Token: Testing

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

Full USDC → cpUSDC → USDC flow on Solana devnet:

```
Alice wraps 10 USDC → sends 5 cpUSDC to Bob → Bob unwraps 5 →
Alice sends 3 to Mark → Mark unwraps 2 → Alice unwraps 1 →
Final: Alice=1 USDC+1cp, Bob=5 USDC, Mark=2 USDC+1cp, Vault=2 USDC
```

Run:
```bash
cargo build-sbf --manifest-path chains/solana/examples/cp-token/pinocchio/Cargo.toml
solana program deploy target/deploy/cp_token.so
bun chains/solana/examples/cp-token/e2e/main.ts <ENCRYPT_ID> <CP_TOKEN_ID>
```
