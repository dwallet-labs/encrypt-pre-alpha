# PC-Swap: Testing

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## Unit Tests

FHE graph soundness against the mock compute engine:

- `swap_basic` — receipt = amount_in case: output and reserves move, k-invariant holds.
- `swap_slippage` — `min_out` higher than achievable: `final_in` and `final_out` collapse to 0, reserves unchanged.
- `swap_lying_user_receipt_zero` — receipt = 0 simulates a no-op deposit: every output is 0, reserves stay put.
- `add_liq_first` — first deposit, `lp = receipt_a`.
- `add_liq_second` — proportional LP minting against existing reserves.
- `add_liq_lying_a_receipt_zero` — one side's receipt is 0: only the honest side's reserve advances, `lp_to_mint = 0`, supply unchanged, user LP unchanged.
- `remove_liq_sufficient` — proportional withdrawal, LP decremented.
- `remove_liq_insufficient` — burn more than `user_lp`: full no-op.
- `graph_shapes` — verify input/output counts (`swap_graph` 4/4, `add_liquidity_graph` 6/6, `remove_liquidity_graph` 5/6).

## E2E Test

The end-to-end runner exercises the program against a live executor (devnet or localnet — `RPC_URL` and `GRPC_URL` env vars override the defaults). Stages:

```
1. Create mock SPL mints (USD, DOGE)
2. Create pcUSD + pcDOGE mints, vaults, user accounts
3. Wrap 1000 USD + 1000 DOGE into pcTokens
4. Create the pool (encrypted zero reserves + LP supply) + LP position
5. AddLiquidity (500 + 500): two TransferWithReceipt CPIs feed add_liquidity_graph
6. Swap 50 pcUSD → pcDOGE: TransferWithReceipt feeds swap_graph
7. Swap with unattainable min_out: in-FHE no-op, no plaintext difference
8. Lying user — claim amount_in = 99,999 pcUSD with ~450 left:
       receipt = 0 → reserves unchanged, user pcDOGE balance unchanged
9. RemoveLiquidity: vault → user transfers signed by the pool PDA
```

Stage 8 is the soundness assertion: the only way to pass it is for receipt-gating to flow all the way through `swap_graph` and the cluster commit, leaving the pool exactly as it was before the lying tx.

Run:
```bash
cargo build-sbf --manifest-path chains/solana/examples/pc-token/pinocchio/Cargo.toml
cargo build-sbf --manifest-path chains/solana/examples/pc-swap/pinocchio/Cargo.toml
solana program deploy target/deploy/pc_token.so
solana program deploy target/deploy/pc_swap.so
bun chains/solana/examples/pc-swap/e2e/main.ts <ENCRYPT_ID> <PC_TOKEN_ID> <PC_SWAP_ID>
```
