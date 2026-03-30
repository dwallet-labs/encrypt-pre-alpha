# Testing the Coin Flip

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What you'll learn

- Unit testing the FHE graph with mock compute
- How the mock evaluator works
- What each test case validates

## Graph unit tests

The `#[encrypt_fn]` macro generates a function that returns the graph bytecode. You can test the graph logic without deploying to Solana by running it through a mock evaluator:

```rust
#[test]
fn xor_same_side_b_wins() {
    let r = run_mock(
        coin_flip_graph,
        &[0, 0],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 0, "0^0=0 -> side_b wins");
}

#[test]
fn xor_diff_side_a_wins() {
    let r = run_mock(
        coin_flip_graph,
        &[0, 1],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 1, "0^1=1 -> side_a wins");
}
```

The `run_mock` helper parses the graph bytecode and evaluates each node using mock digest encoding/decoding. This simulates exactly what the executor does, but with plaintext values encoded as mock identifiers.

## Test matrix

| Inputs | XOR | Winner | Test |
|--------|-----|--------|------|
| 0, 0 | 0 | Side B | `xor_same_side_b_wins` |
| 0, 1 | 1 | Side A | `xor_diff_side_a_wins` |
| 1, 1 | 0 | Side B | `xor_both_one_side_b_wins` |
| 1, 0 | 1 | Side A | `xor_one_zero_side_a_wins` |

## Graph shape test

```rust
#[test]
fn graph_shape() {
    let d = coin_flip_graph();
    let pg = parse_graph(&d).unwrap();
    assert_eq!(pg.header().num_inputs(), 2, "commit_a + commit_b");
    assert_eq!(pg.header().num_outputs(), 1, "single flip result");
}
```

Validates that the compiled graph has exactly 2 inputs and 1 output. This catches accidental changes to the graph signature.

## Running tests

```bash
# Unit tests only (no SBF build needed)
cargo test -p encrypt-coin-flip-anchor

# Or run all example tests
just test-examples
```

## E2E tests

The `e2e/` directory contains integration tests that deploy the program to a local validator (LiteSVM or solana-program-test), run the full flow (create game, play, decrypt, reveal), and verify the winner gets paid. These require the SBF binary:

```bash
just build-sbf-examples
just test-examples-litesvm
```
