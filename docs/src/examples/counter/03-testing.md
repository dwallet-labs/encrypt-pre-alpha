# Confidential Counter: Testing

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## 1. Unit Tests (Graph Logic)

Unit tests verify the FHE graph produces correct results using a mock evaluator.
No SBF build or Solana runtime needed.

```bash
cargo test -p confidential-counter-anchor --lib
```

The tests use a `run_mock` helper that walks the graph nodes and evaluates them
with mock arithmetic (operating on plaintext values encoded as mock digests):

```rust
#[test]
fn increment_from_zero() {
    let r = run_mock(increment_graph, &[0], &[FheType::EUint64]);
    assert_eq!(r[0], 1, "0 + 1 = 1");
}

#[test]
fn increment_from_ten() {
    let r = run_mock(increment_graph, &[10], &[FheType::EUint64]);
    assert_eq!(r[0], 11, "10 + 1 = 11");
}

#[test]
fn decrement_from_ten() {
    let r = run_mock(decrement_graph, &[10], &[FheType::EUint64]);
    assert_eq!(r[0], 9, "10 - 1 = 9");
}

#[test]
fn graph_shapes() {
    let inc = increment_graph();
    let pg = parse_graph(&inc).unwrap();
    assert_eq!(pg.header().num_inputs(), 1);
    assert_eq!(pg.header().num_outputs(), 1);
}
```

## 2. LiteSVM Integration Tests (E2E)

Full lifecycle tests using LiteSVM -- a lightweight Solana runtime that runs
in-process. Tests deploy the SBF binary, create ciphertexts, execute graphs,
and verify results.

```bash
# Build SBF first
just build-sbf-examples

# Run LiteSVM tests
cargo test -p confidential-counter-anchor --test litesvm
```

The test uses `EncryptTestContext` which bundles a LiteSVM instance with the
Encrypt program pre-deployed and a mock compute engine:

```rust
#[test]
fn test_increment() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    // Create encrypted zero
    let value_ct = ctx.create_input::<Uint64>(0, &program_id);

    // Create counter PDA
    // ... send create_counter ix ...

    // Increment via CPI
    // ... send increment ix ...

    // Simulate executor: evaluate graph + commit result
    let graph = increment_graph();
    ctx.enqueue_graph_execution(&graph, &[value_ct], &[value_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&value_ct);

    // Verify
    let result = ctx.decrypt_from_store(&value_ct);
    assert_eq!(result, 1);
}
```

Key `EncryptTestContext` methods:
- `create_input::<Uint64>(value, program_id)` -- creates a ciphertext account
- `enqueue_graph_execution(graph, inputs, outputs)` -- queues a graph for mock evaluation
- `process_pending()` -- runs the mock FHE engine
- `register_ciphertext(pubkey)` -- syncs the on-chain account with the mock store
- `decrypt_from_store(pubkey)` -- returns the plaintext value

## 3. Mollusk Instruction-Level Tests

Mollusk tests individual instructions in isolation without CPI. Useful for
testing `reveal_value` logic (authorization checks, digest verification)
without needing the full Encrypt program.

```bash
just build-sbf-examples
cargo test -p confidential-counter-anchor --test mollusk
```

Tests construct raw account data and verify instruction behavior:

```rust
#[test]
fn test_reveal_value_success() {
    let (mollusk, pid) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let counter_data = build_anchor_counter_with_digest(
        &authority, &[1u8; 32], &Pubkey::new_unique(), &digest, 0,
    );
    let request_data = build_decryption_request_data(&digest, 42);

    let result = mollusk.process_instruction(/* ... */);
    assert!(result.program_result.is_ok());
    // Check revealed_value == 42
}

#[test]
fn test_reveal_value_rejects_wrong_authority() { /* ... */ }

#[test]
fn test_reveal_value_rejects_digest_mismatch() { /* ... */ }
```

## 4. Running All Example Tests

```bash
# Everything (build + all test types)
just test-examples

# Just LiteSVM e2e
just test-examples-litesvm

# Just Mollusk
just test-examples-mollusk

# Just program-test (solana-program-test runtime)
just test-examples-program-test
```
