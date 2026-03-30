# Testing Confidential Voting

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What you'll learn

- Unit testing the cast_vote FHE graph
- How conditional logic (Select) is tested
- What each test case validates

## Graph unit tests

The `#[encrypt_fn]` macro generates a function returning the graph bytecode. Test it with a mock evaluator:

```rust
#[test]
fn vote_yes_increments_yes_count() {
    let r = run_mock(
        cast_vote_graph,
        &[10, 5, 1],  // yes_count=10, no_count=5, vote=true
        &[FheType::EUint64, FheType::EUint64, FheType::EBool],
    );
    assert_eq!(r[0], 11);  // yes_count incremented
    assert_eq!(r[1], 5);   // no_count unchanged
}

#[test]
fn vote_no_increments_no_count() {
    let r = run_mock(
        cast_vote_graph,
        &[10, 5, 0],  // yes_count=10, no_count=5, vote=false
        &[FheType::EUint64, FheType::EUint64, FheType::EBool],
    );
    assert_eq!(r[0], 10);  // yes_count unchanged
    assert_eq!(r[1], 6);   // no_count incremented
}

#[test]
fn vote_from_zero() {
    let r = run_mock(
        cast_vote_graph,
        &[0, 0, 1],  // both counters at zero, vote yes
        &[FheType::EUint64, FheType::EUint64, FheType::EBool],
    );
    assert_eq!(r[0], 1);
    assert_eq!(r[1], 0);
}
```

The `run_mock` helper parses the graph bytecode and evaluates nodes using mock digest encoding. It handles the `Select` operation (op_type 60) which is what `if vote { ... } else { ... }` compiles to.

## Test matrix

| yes_count | no_count | vote | new_yes | new_no | Test |
|-----------|----------|------|---------|--------|------|
| 10 | 5 | true | 11 | 5 | `vote_yes_increments_yes_count` |
| 10 | 5 | false | 10 | 6 | `vote_no_increments_no_count` |
| 0 | 0 | true | 1 | 0 | `vote_from_zero` |

## Graph shape test

```rust
#[test]
fn graph_shape() {
    let d = cast_vote_graph();
    let pg = parse_graph(&d).unwrap();
    assert_eq!(pg.header().num_inputs(), 3);  // yes_count, no_count, vote
    assert_eq!(pg.header().num_outputs(), 2); // new_yes, new_no
}
```

The graph has 3 inputs (two counters + one boolean vote) and 2 outputs (updated counters). This catches signature changes.

## Running tests

```bash
# Unit tests only (no SBF build needed)
cargo test -p encrypt-voting-anchor

# All example tests
just test-examples

# E2E with LiteSVM
just build-sbf-examples
just test-examples-litesvm
```

## E2E tests

The `e2e/` directory contains integration tests that deploy the program, create a proposal, cast multiple votes, close, decrypt, and verify the tallies match. These require the SBF binary and exercise the full Encrypt CPI flow.
