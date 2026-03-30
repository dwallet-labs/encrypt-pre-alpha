# Testing

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


Encrypt provides four levels of testing for your programs:

1. **Unit tests** — verify graph logic with mock arithmetic (no SBF needed)
2. **LiteSVM e2e tests** — fast in-process lifecycle with deployed programs and CPI
3. **solana-program-test e2e tests** — official Solana runtime, full sysvar support
4. **Mollusk tests** — isolated instruction-level validation

## Setup

```toml
[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
solana-sdk = "4"
mollusk-svm = "0.11"
solana-account = "3"
solana-pubkey = "4"
solana-instruction = "3"
```

## Unit Testing the Graph

The simplest tests verify graph correctness with mock plaintext arithmetic:

```rust
#[cfg(test)]
mod tests {
    use super::cast_vote_graph;

    #[test]
    fn vote_yes_increments_yes_count() {
        let r = run_mock(
            cast_vote_graph,
            &[10, 5, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool],
        );
        assert_eq!(r[0], 11);
        assert_eq!(r[1], 5);
    }

    #[test]
    fn graph_shape() {
        let d = cast_vote_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 3);
        assert_eq!(pg.header().num_outputs(), 2);
    }
}
```

Run with `cargo test -p your-program --lib` — no SBF build needed.

## LiteSVM End-to-End Tests

Test the full lifecycle: deploy your program → send transactions → CPI to Encrypt → verify results.

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EBool, EUint64, Bool, Uint64};

// Redefine graph for off-chain evaluation
#[encrypt_fn]
fn cast_vote_graph(yes_count: EUint64, no_count: EUint64, vote: EBool) -> (EUint64, EUint64) {
    let new_yes = if vote { yes_count + 1 } else { yes_count };
    let new_no = if vote { no_count } else { no_count + 1 };
    (new_yes, new_no)
}

#[test]
fn test_full_voting_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();

    // Deploy your program
    let program_id = ctx.deploy_program("path/to/your_program.so");
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);

    // 1. Create proposal (CPI creates yes/no ciphertexts)
    ctx.send_transaction(&[create_proposal_ix(...)], &[&authority, &yes_ct, &no_ct]);
    ctx.register_ciphertext(&yes_pubkey);
    ctx.register_ciphertext(&no_pubkey);

    // 2. Cast vote (CPI to execute_graph)
    let vote_ct = ctx.create_input::<Bool>(1, &program_id);
    ctx.send_transaction(&[cast_vote_ix(...)], &[&voter]);

    // 3. Process the graph execution off-chain
    let graph = cast_vote_graph();
    ctx.enqueue_graph_execution(&graph, &[yes_pubkey, no_pubkey, vote_ct], &[yes_pubkey, no_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&yes_pubkey);
    ctx.register_ciphertext(&no_pubkey);

    // 4. Close proposal
    ctx.send_transaction(&[close_ix(...)], &[&authority]);

    // 5. Verify results
    assert_eq!(ctx.decrypt_from_store(&yes_pubkey), 1);
    assert_eq!(ctx.decrypt_from_store(&no_pubkey), 0);
}
```

### Key patterns for CPI e2e tests

- **`register_ciphertext`** — call after CPI creates/updates ciphertexts the harness doesn't know about
- **`enqueue_graph_execution` + `process_pending`** — simulate the off-chain executor evaluating graphs triggered by CPI
- **`decrypt_from_store`** — read results from the mock store (no on-chain decryption request needed)
- **Ciphertext authorization** — authorize to the *program* ID (not the voter), since the program is the CPI caller

## Mollusk Instruction Tests

Test individual instructions in isolation without CPI. Best for:
- Signer/authority checks
- Account validation
- Edge cases (already closed, wrong digest, missing accounts)

```rust
use mollusk_svm::Mollusk;

#[test]
fn test_close_proposal_rejects_wrong_authority() {
    let (mollusk, program_id) = setup();
    let auth = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();

    let prop_data = build_proposal_data(&auth, &proposal_id, true, 0);

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(program_id, &[2u8], vec![
            AccountMeta::new(prop_key, false),
            AccountMeta::new_readonly(wrong, true),
        ]),
        &[(prop_key, program_account(&program_id, prop_data)), (wrong, funded_account())],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_reveal_tally_rejects_digest_mismatch() {
    let (mollusk, program_id) = setup();
    // ... build proposal with digest A, request with digest B
    // ... verify the reveal fails
}
```

## solana-program-test

Same API as LiteSVM but uses the official Solana runtime. Programs must be declared upfront:

```rust
use encrypt_solana_test::program_test::ProgramTestEncryptContext;

#[test]
fn test_with_official_runtime() {
    let mut ctx = ProgramTestEncryptContext::builder()
        .add_program("my_program", program_id)
        .build();
    // Same API as EncryptTestContext
}
```

`ProgramTestEncryptContext` wraps `EncryptTestHarness<ProgramTestRuntime>`. The `ProgramTestRuntime` blocks async `BanksClient` calls on a tokio runtime, so tests remain synchronous.

**When to use which:**
- **LiteSVM** — fastest, good for iteration. Partial sysvar support.
- **solana-program-test** — slower, but uses the real Solana runtime. Full sysvar + rent support. Use for CI or when LiteSVM behavior diverges.

## Running Tests

```bash
# All tests (builds SBF first)
just test

# Unit tests only (fast, no SBF)
just test-unit

# Example tests only
just test-examples               # All (unit + litesvm + mollusk + program-test)
just test-examples-litesvm       # LiteSVM e2e only
just test-examples-mollusk       # Mollusk only
just test-examples-program-test  # solana-program-test e2e only

# Single example
cargo test -p confidential-voting-pinocchio
```

## Mock vs Real FHE

In test mode, `EncryptTestContext` uses `MockComputeEngine` — operations are performed as plaintext arithmetic. The 32-byte ciphertext digest directly encodes the plaintext value. This means:
- Graph evaluation is instantaneous
- Decryption is trivial
- No privacy (values visible in account data)

The same test code will work unchanged when real REFHE is available. See [Mock vs Real FHE](../testing/mock-vs-real.md) for details.
