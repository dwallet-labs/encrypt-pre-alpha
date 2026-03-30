# Confidential Voting

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Encrypted voting where individual votes are hidden but the tally is computed via FHE.

## What you'll learn

- How FHE enables private voting with public tallies
- The architecture: React frontend (gRPC-Web) + Bun backend + Solana program + executor
- End-to-end flow from encrypted vote to revealed results

## How it works

Voters cast encrypted yes/no votes (EBool). The on-chain program CPIs into Encrypt to run an FHE graph that conditionally increments encrypted yes or no counters. Nobody -- not the program, not the executor, not other voters -- can see individual votes. Only when the proposal authority closes voting and requests decryption are the final tallies revealed.

## Architecture

```
Voter (React)           Backend (Bun)              Executor (:50051)
     |                        |                          |
     |-- create_proposal ---->|                          |
     |   (creates encrypted   |                          |
     |    zero counters)      |                          |
     |                        |                          |
     |-- encryptValue() ----->|                          |
     |-- gRPC-Web createInput =========================>|
     |<- ciphertextId ================================--|
     |                        |                          |
     |-- cast_vote tx ------->|                          |
     |   (encrypted vote +    |     Executor computes    |
     |    graph executes)     |     conditional add      |
     |                        |                          |
     |-- close_proposal ----->|                          |
     |                        |                          |
     |-- POST /api/decrypt -->|-- request_decryption --->|
     |                        |-- poll for result ------>|
     |<- decryption ready ----|                          |
     |                        |                          |
     |-- reveal_tally tx ---->|                          |
     |   (read + store        |                          |
     |    plaintext on-chain) |                          |
```

The browser encrypts votes locally and sends ciphertext directly to the executor via gRPC-Web -- the plaintext never leaves the client. The backend only handles decryption requests and polling.

## Privacy guarantees

- **Individual votes are hidden.** Each vote is an encrypted boolean. The graph operates on ciphertexts -- the executor never sees plaintext votes.
- **Tallies are computed homomorphically.** The yes/no counters are encrypted integers. Each vote conditionally adds 1 to one counter without decrypting either.
- **Only the authority can reveal.** Decryption requires the proposal authority to request it and sign the reveal transaction.
- **Double-voting is prevented.** A VoteRecord PDA per voter per proposal enforces one vote each.

## Components

| Component | Location | Role |
|-----------|----------|------|
| Solana program (Anchor) | `anchor/src/lib.rs` | Proposal state, vote graph CPI, tally reveal |
| Solana program (Pinocchio) | `pinocchio/src/lib.rs` | Same logic, low-level |
| Backend | `react/server/backend.ts` | Decryption request + polling |
| React frontend | `react/src/App.tsx` | Create proposals, vote, close, reveal |
