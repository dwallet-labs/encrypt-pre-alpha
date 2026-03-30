# Test Framework

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Overview

`encrypt-solana-test` provides three testing modes:

- **LiteSVM** (`EncryptTestContext`) — fast in-process e2e tests
- **solana-program-test** (`ProgramTestEncryptContext`) — official Solana runtime e2e tests
- **Mollusk** — single-instruction unit tests with pre-built account data

```toml
[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
```

## Architecture

```
encrypt-dev (chains/solana/dev/) — production-safe, no test deps
  ├── SolanaRuntime                # Production (send_transaction, get_account_data, ...)
  ├── TestRuntime                  # Dev/test (adds airdrop, deploy_program)
  ├── InProcessTestRuntime         # In-process only (adds set_account, advance_slot)
  └── EncryptTxBuilder<R>          # Tx construction for all Encrypt instructions

encrypt-solana-test (chains/solana/test/)
  ├── LiteSvmRuntime               # LiteSVM backend (InProcessTestRuntime)
  ├── ProgramTestRuntime           # solana-program-test backend (InProcessTestRuntime)
  ├── EncryptTestHarness<R>        # Wraps TxBuilder + MockComputeEngine + store + work queue
  ├── EncryptTestContext            # Ergonomic LiteSVM wrapper
  ├── ProgramTestEncryptContext     # Ergonomic solana-program-test wrapper
  └── mollusk helpers               # Account builders, discriminators, setup
```

`encrypt-dev` has no test framework dependencies — only the runtime trait hierarchy and `EncryptTxBuilder`. Test runtimes and harness live in `encrypt-solana-test`.

## EncryptTestContext

```rust
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::Uint64;

#[test]
fn test_my_program() {
    let mut ctx = EncryptTestContext::new_default();
    let user = ctx.new_funded_keypair();

    let a = ctx.create_input::<Uint64>(10, &user.pubkey());
    let b = ctx.create_input::<Uint64>(32, &user.pubkey());

    let graph = my_add_graph();
    let outputs = ctx.execute_and_commit(&graph, &[a, b], 1, &[], &user);

    let result = ctx.decrypt::<Uint64>(&outputs[0], &user);
    assert_eq!(result, 42);
}
```

## How It Works

1. **LiteSVM** runs in-process — no external validator needed
2. A **local authority keypair** signs `commit_ciphertext` and `respond_decryption`
3. An **in-memory CiphertextStore** tracks all ciphertext digests
4. `execute_and_commit()` calls `execute_graph` on-chain, then evaluates the graph off-chain using `MockComputeEngine` and commits results
5. `decrypt()` calls `request_decryption` on-chain, then decrypts and responds

All off-chain processing happens synchronously — no event polling needed.

## API Reference

| Method | Description |
|--------|-------------|
| `new(elf_path)` | Create context with custom program path |
| `new_default()` | Create with default build output path |
| `new_funded_keypair()` | Create and fund a new keypair (10 SOL) |
| `create_input::<T>(value, authorized)` | Create verified encrypted input (authority-driven) |
| `create_plaintext::<T>(value, creator)` | Create plaintext ciphertext (user-signed) |
| `execute_and_commit(graph, inputs, n_outputs, existing_outputs, caller)` | Execute + commit in one call |
| `decrypt::<T>(ct_pubkey, requester)` | Decrypt and return plaintext value |
| `decrypt_from_store(ct_pubkey)` | Read value from mock store (no on-chain request) |
| `deploy_program(elf_path)` | Deploy an additional program, returns ID |
| `deploy_program_at(id, elf_path)` | Deploy at a specific address |
| `cpi_authority_for(caller_program)` | Derive CPI authority PDA for a program |
| `send_transaction(ixs, signers)` | Sign and send a transaction |
| `get_account_data(pubkey)` | Read raw account data |
| `register_ciphertext(pubkey)` | Register CPI-created ciphertext in the store |
| `enqueue_graph_execution(graph, inputs, outputs)` | Enqueue CPI-triggered graph for processing |
| `process_pending()` | Process all queued graph executions and decryptions |
| `program_id()` / `config_pda()` / `deposit_pda()` / etc. | Access Encrypt program PDAs |

## Testing CPI Programs (e2e)

For programs that call the Encrypt program via CPI (like the voting examples):

```rust
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{Bool, Uint64};

#[test]
fn test_voting_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();

    // Deploy your program
    let program_id = ctx.deploy_program("path/to/your_program.so");
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);

    // Create proposal (CPI creates ciphertexts)
    // ... send create_proposal transaction ...

    // Register CPI-created ciphertexts in the harness store
    ctx.register_ciphertext(&yes_ct_pubkey);
    ctx.register_ciphertext(&no_ct_pubkey);

    // Cast vote (CPI to execute_graph)
    // ... send cast_vote transaction ...

    // Enqueue the graph execution for off-chain processing
    ctx.enqueue_graph_execution(&graph_data, &inputs, &outputs);
    ctx.process_pending();

    // Re-register updated ciphertexts
    ctx.register_ciphertext(&yes_ct_pubkey);
    ctx.register_ciphertext(&no_ct_pubkey);

    // Verify results from the mock store
    let yes = ctx.decrypt_from_store(&yes_ct_pubkey);
    assert_eq!(yes, 1);
}
```

## Testing Update Mode

For programs that reuse ciphertext accounts:

```rust
let yes_ct = ctx.create_input::<Uint64>(0, &program_id);
let no_ct = ctx.create_input::<Uint64>(0, &program_id);
let vote = ctx.create_input::<Bool>(1, &program_id);

// Pass yes_ct and no_ct as both inputs and existing outputs (update mode)
let outputs = ctx.execute_and_commit(
    &cast_vote_graph(),
    &[yes_ct, no_ct, vote],
    0,                       // no new outputs
    &[yes_ct, no_ct],        // existing outputs (update mode)
    &caller,
);
```

## Mollusk Mode

For single-instruction unit tests:

```rust
use encrypt_solana_test::mollusk::*;

let (mollusk, program_id) = setup();
let ct_data = build_ciphertext_data(&digest, &authorized, &nk, fhe_type, status);

let result = mollusk.process_instruction(
    &Instruction::new_with_bytes(program_id, &ix_data, accounts),
    &[(key, program_account(&program_id, ct_data))],
);
assert!(result.program_result.is_ok());
```

Mollusk is best for testing individual instructions in isolation — signer checks, discriminator validation, authority verification, digest matching, etc.
