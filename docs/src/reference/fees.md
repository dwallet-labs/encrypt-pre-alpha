# Fee Model

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


Encrypt uses a dual-token fee model: **ENC** (SPL token) for FHE computation costs and **SOL gas** for Solana transaction costs. Fees are charged upfront from the user's `EncryptDeposit` account and partially reimbursed after actual costs are known.

## Overview

```
User creates EncryptDeposit
    ├── ENC balance   (SPL token transfer to vault)
    └── Gas balance   (SOL transfer to deposit PDA)

execute_graph charges:
    ├── ENC: enc_per_input × total_inputs + enc_per_output × outputs + max_enc_per_op × ops
    └── Gas: gas_base + gas_per_input × inputs + gas_per_output × outputs

Authority reimburses (max_charge - actual_cost) after off-chain evaluation
```

## Fee Parameters

Stored in the `EncryptConfig` account, updatable by authorities via `update_config_fees`:

| Parameter | Size | Description |
|-----------|------|-------------|
| `enc_per_input` | u64 | ENC charged per input (encrypted + plaintext + constant) |
| `enc_per_output` | u64 | ENC charged per output ciphertext |
| `max_enc_per_op` | u64 | Maximum ENC charged per FHE operation |
| `max_ops_per_graph` | u16 | Maximum operations allowed per graph |
| `gas_base` | u64 | Base SOL gas fee per graph execution |
| `gas_per_input` | u64 | SOL gas fee per input |
| `gas_per_output` | u64 | SOL gas fee per output |
| `gas_per_byte` | u64 | SOL gas fee per byte of graph data |

## ENC Fee Calculation

When `execute_graph` is called, the ENC fee is calculated as:

```
total_inputs = num_inputs + num_plaintext_inputs + num_constants
enc_fee = enc_per_input * total_inputs
        + enc_per_output * num_outputs
        + max_enc_per_op * num_ops
```

The `max_enc_per_op` is a **worst-case** charge. Different FHE operations have vastly different costs (e.g., multiplication is far more expensive than addition). Since the on-chain processor cannot determine actual costs without performing the FHE computation, it charges the maximum. The authority reimburses the difference after off-chain evaluation.

## Gas Fee Calculation

SOL gas covers the Solana transaction costs:

```
gas_fee = gas_base
        + gas_per_input * num_inputs
        + gas_per_output * num_outputs
```

## Deposit Lifecycle

### 1. Create Deposit

```rust
// Instruction: create_deposit (disc 13)
// Data: bump(1) | initial_enc_amount(8) | initial_gas_amount(8)
```

Creates an `EncryptDeposit` PDA for the user. Transfers `initial_enc_amount` ENC tokens from the user's ATA to the program vault, and `initial_gas_amount` lamports as gas.

### 2. Top Up

```rust
// Instruction: top_up (disc 14)
// Data: enc_amount(8) | gas_amount(8)
```

Add more ENC and/or SOL to an existing deposit. Either amount can be zero.

### 3. Use (Automatic)

Every `execute_graph`, `create_input_ciphertext`, `create_plaintext_ciphertext`, and `request_decryption` call deducts fees from the deposit automatically. The deposit account is passed as a writable account in each of these instructions.

### 4. Reimburse

```rust
// Instruction: reimburse (disc 17)
// Data: enc_amount(8) | gas_amount(8)
```

After the executor evaluates a computation graph, it knows the actual per-operation costs. The authority calls `reimburse` to credit back the difference between `max_enc_per_op * ops` and the actual cost.

### 5. Request Withdraw

```rust
// Instruction: request_withdraw (disc 18)
// Data: enc_amount(8) | gas_amount(8)
```

Requests a withdrawal. Sets `pending_enc_withdrawal`, `pending_gas_withdrawal`, and `withdrawal_epoch = current_epoch + 1`. The withdrawal is delayed by one epoch to prevent front-running.

### 6. Withdraw

```rust
// Instruction: withdraw (disc 15)
// No data
```

Executes the pending withdrawal if `current_epoch >= withdrawal_epoch`. Actual amounts are capped at current balances (charges during the delay may have reduced them).

## Registered Graph Fee Optimization

When using `execute_registered_graph` instead of `execute_graph`, the authority can compute exact per-operation costs because the graph is known ahead of time. This eliminates the max-charge gap and the need for reimbursement.

```rust
// Register a graph once
ctx.register_graph(graph_pda, bump, &graph_hash, &graph_data)?;

// Execute with exact fees (no max-charge overcharge)
ctx.execute_registered_graph(graph_pda, ix_data, remaining)?;
```

## Fee Example

Given fee parameters:
- `enc_per_input = 100`
- `enc_per_output = 50`
- `max_enc_per_op = 200`
- `gas_base = 5000`
- `gas_per_input = 1000`
- `gas_per_output = 500`

For `cast_vote_graph` (3 inputs, 2 outputs, ~5 ops, 1 constant):

```
ENC upfront = 100 * (3 + 1) + 50 * 2 + 200 * 5 = 400 + 100 + 1000 = 1500
Gas         = 5000 + 1000 * 3 + 500 * 2 = 5000 + 3000 + 1000 = 9000
```

If actual per-op costs total 600 ENC (instead of max 1000), the authority reimburses 400 ENC.

## EncryptDeposit Account Fields

| Field | Size | Description |
|-------|------|-------------|
| owner | 32 | Deposit owner pubkey |
| enc_balance | 8 | Current ENC balance |
| gas_balance | 8 | Current SOL gas balance |
| pending_enc_withdrawal | 8 | Pending ENC withdrawal amount |
| pending_gas_withdrawal | 8 | Pending SOL gas withdrawal amount |
| withdrawal_epoch | 8 | Epoch when withdrawal is available |
| num_txs | 8 | Total transaction count |
| bump | 1 | PDA bump |
