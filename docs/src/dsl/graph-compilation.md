# Graph Compilation

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Binary Format

The `#[encrypt_fn]` macro compiles your function into a binary graph at compile time:

```
[Header 13B] [Nodes N×9B] [Constants section]
```

### Header (13 bytes)

```
version(1) | num_inputs(2) | num_plaintext_inputs(2) | num_constants(2) | num_ops(2) | num_outputs(2) | constants_len(2)
```

Counts are ordered by node kind. `num_nodes` is derived (sum of all counts).

### Nodes (9 bytes each)

```
kind(1) | op_type(1) | fhe_type(1) | input_a(2) | input_b(2) | input_c(2)
```

| Kind | Value | Description |
|------|-------|-------------|
| Input | 0 | Encrypted ciphertext account |
| PlaintextInput | 1 | Plaintext value in instruction data |
| Constant | 2 | Literal value in constants section |
| Op | 3 | FHE operation |
| Output | 4 | Graph result |

Nodes are topologically sorted — every node's operands appear earlier in the list.

### Constants Section

Variable-length byte blob. Constant nodes reference it by byte offset (`input_a`). Values stored as little-endian bytes at `fhe_type.byte_width()`.

## Example

```rust
#[encrypt_fn]
fn add(a: EUint64, b: EUint64) -> EUint64 { a + b }
```

Produces 4 nodes:
- Node 0: Input (EUint64) — `a`
- Node 1: Input (EUint64) — `b`
- Node 2: Op (Add, EUint64, inputs: 0, 1)
- Node 3: Output (EUint64, source: 2)

Header: `version=1, num_inputs=2, num_constants=0, num_ops=1, num_outputs=1, constants_len=0`

## Registered Graphs

For frequently used graphs, register them on-chain to avoid re-sending graph data:

```rust
ctx.register_graph(graph_pda, bump, &graph_hash, &graph_data)?;
ctx.execute_registered_graph(graph_pda, ix_data, remaining)?;
```

Registered graphs enable exact per-op fee calculation (no max-charge gap).
