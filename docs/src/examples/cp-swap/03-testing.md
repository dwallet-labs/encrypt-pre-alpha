# CP-Swap: Testing

## Unit Tests (9)

- `swap_basic` — verify output, reserves, k-invariant, price update
- `swap_slippage` — excessive min_amount_out → no-op, price unchanged
- `swap_k_preserved` — 5 alternating swaps, k never decreases
- `add_liq_first` — first deposit LP = a × b
- `add_liq_second_deposit` — proportional LP minting
- `remove_liq_sufficient` — proportional withdrawal, LP decremented
- `remove_liq_insufficient` — burn more than owned → no-op
- `remove_liq_full` — 100% withdrawal, pool empty
- `graph_shapes` — verify input/output counts

## LiteSVM Integration Tests (6)

- `test_create_pool` — encrypted zero reserves + LP supply
- `test_add_and_remove` — add liquidity, remove 50%, verify balances
- `test_remove_more_than_owned` — burn 2x LP → no-op, everything unchanged
- `test_cannot_use_other_users_lp` — cross-user LP access rejected
- `test_swap_k_invariant` — k-invariant verified after swap
- `test_swap_then_remove_earns_fees` — LP earns fees from trading

## E2E Devnet Test

```
Create pool → add 10,000/100 liquidity → swap 1,000 A→B →
swap 10 B→A → slippage rejection → remove 50% LP →
read public price via gRPC (0.008271 B per A)
```

All reserves, trade sizes, and LP positions encrypted. Only the price is public.

Run:
```bash
cargo build-sbf --manifest-path chains/solana/examples/cp-swap/pinocchio/Cargo.toml
solana program deploy target/deploy/cp_swap.so
bun chains/solana/examples/cp-swap/e2e/main.ts <ENCRYPT_ID> <CP_SWAP_ID>
```
