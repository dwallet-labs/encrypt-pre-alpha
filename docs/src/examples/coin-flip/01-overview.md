# Encrypted Coin Flip

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Provably fair coin flip with on-chain escrow, built on Encrypt + Solana.

## What you'll learn

- How XOR on encrypted values produces a provably fair coin flip
- On-chain escrow pattern for trustless betting
- The player-vs-house architecture with an automated backend
- End-to-end flow from encrypted commit to payout

## How it works

Two sides each commit an encrypted value (0 or 1). The Encrypt executor computes `result = commit_a XOR commit_b` using FHE -- neither side can see the other's value before committing. XOR = 1 means side A wins; XOR = 0 means side B wins.

Both sides deposit equal bets into a game PDA. The winner receives 2x from escrow.

## Architecture

```
Player (React)          House (Bun backend)         Solana Program
     |                        |                          |
     |-- create_game -------->|                          |
     |   (encrypt commit,     |                          |
     |    deposit bet)        |                          |
     |                        |                          |
     |-- POST /api/join ----->|                          |
     |                        |-- play ----------------->|
     |                        |   (encrypt commit,       |
     |                        |    match bet, XOR graph) |
     |                        |                          |
     |                        |      Executor computes   |
     |                        |      XOR off-chain       |
     |                        |                          |
     |                        |-- request_decryption --->|
     |                        |-- reveal_result -------->|
     |                        |   (pay winner from PDA)  |
     |                        |                          |
     |<-- GET /api/game ------|                          |
     |   (result: win/lose)   |                          |
```

## Why this is provably fair

1. Both sides commit encrypted values before seeing the other's choice
2. The FHE XOR computation is deterministic -- the executor cannot alter it
3. The on-chain program enforces payout rules -- neither side can withhold funds
4. The ciphertext digest is verified at reveal time -- stale or tampered results are rejected

## Components

| Component | Location | Role |
|-----------|----------|------|
| Solana program (Anchor) | `anchor/src/lib.rs` | Game state, escrow, CPI to Encrypt |
| Solana program (Pinocchio) | `pinocchio/src/lib.rs` | Same logic, low-level |
| House backend | `react/server/house.ts` | Auto-joins games, handles decrypt + reveal |
| React frontend | `react/src/App.tsx` | Player UI: bet, flip, see result |
