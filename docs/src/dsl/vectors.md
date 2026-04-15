# Vectors

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


Encrypt supports SIMD-style encrypted vectors — fixed-size arrays of encrypted integers where every element-wise operation runs in a single FHE computation. Vectors enable batch processing (e.g., updating 2048 balances in one graph execution).

## Vector Types

All arithmetic vectors are exactly **8,192 bytes** (65,536 bits). The element count depends on element size:

| Type | Element | Elements | FHE Type ID |
|------|---------|----------|-------------|
| `EUint8Vector` | `u8` | 8,192 | 32 |
| `EUint16Vector` | `u16` | 4,096 | 33 |
| `EUint32Vector` | `u32` | 2,048 | 34 |
| `EUint64Vector` | `u64` | 1,024 | 35 |
| `EUint128Vector` | `u128` | 512 | 36 |
| ... up to `EUint32768Vector` | 4,096 bytes | 2 | 44 |

Boolean vectors (`EBitVector2` through `EBitVector65536`) store packed boolean arrays.

## Using Vectors in `#[encrypt_fn]`

Vectors work like scalars in the DSL — all operations are element-wise:

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint32Vector;

#[encrypt_fn]
fn add_vectors(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    a + b  // element-wise: result[i] = a[i] + b[i]
}
```

### Scalar Operations

Literals auto-promote to scalar operations that broadcast across all elements:

```rust
#[encrypt_fn]
fn scale_and_shift(v: EUint32Vector) -> EUint32Vector {
    v * 3 + 7  // each element: result[i] = v[i] * 3 + 7
}
```

This generates `MultiplyScalar` and `AddScalar` ops — the constant `3` is stored as a single scalar, not replicated 2,048 times.

### All Arithmetic Operations

Every operation that works on scalars also works element-wise on vectors:

```rust
#[encrypt_fn]
fn all_ops(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    let sum = a + b;
    let diff = a - b;
    let prod = a * b;
    let quot = a / b;
    let rem = a % b;
    let neg = -a;
    let and = a & b;
    let or = a | b;
    let xor = a ^ b;
    let not = !a;
    let min = a.min(&b);
    let max = a.max(&b);
    sum  // return any of these
}
```

### Comparisons

Comparisons return a vector of 0/1 values (same type, not `EBool`):

```rust
#[encrypt_fn]
fn compare(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    a == b  // result[i] = 1 if a[i] == b[i], else 0
}
```

All comparison operators work: `==`, `!=`, `<`, `<=`, `>`, `>=`.

### Conditionals

Use `if cond { a } else { b }` with a scalar `EBool` to select entire vectors:

```rust
use encrypt_types::encrypted::EBool;

#[encrypt_fn]
fn conditional(cond: EBool, a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    if cond { a } else { b }  // selects entire vector a or b
}
```

For element-wise selection (different condition per element), use `select_scalar`:

```rust
#[encrypt_fn]
fn elementwise_select(
    mask: EUint32Vector,  // 0 or nonzero per element
    a: EUint32Vector,
    b: EUint32Vector,
) -> EUint32Vector {
    mask.select_scalar(&a, &b)  // result[i] = mask[i] != 0 ? a[i] : b[i]
}
```

### Multiple Outputs

A single graph can produce multiple output vectors:

```rust
#[encrypt_fn]
fn sum_and_diff(a: EUint32Vector, b: EUint32Vector) -> (EUint32Vector, EUint32Vector) {
    (a + b, a - b)
}
```

## Vector-Specific Operations

### Gather

Index-based lookup: `result[i] = source[indices[i]]`

```rust
#[encrypt_fn]
fn permute(data: EUint32Vector, indices: EUint32Vector) -> EUint32Vector {
    data.gather(&indices)
}
```

### Scatter

Inverse of gather: `result[indices[i]] = data[i]`

```rust
#[encrypt_fn]
fn scatter(data: EUint32Vector, indices: EUint32Vector) -> EUint32Vector {
    data.scatter(&indices)
}
```

### Assign

Overwrite elements at specific positions: `result = base; result[indices[i]] = values[i]`

```rust
#[encrypt_fn]
fn update_positions(
    base: EUint32Vector,
    indices: EUint32Vector,
    values: EUint32Vector,
) -> EUint32Vector {
    base.assign(&indices, &values)
}
```

### Copy

Copy entire vector:

```rust
#[encrypt_fn]
fn clone_vec(a: EUint32Vector, src: EUint32Vector) -> EUint32Vector {
    a.copy(&src)  // returns src
}
```

### Get

Extract a single element by index (result at position 0):

```rust
#[encrypt_fn]
fn extract(data: EUint32Vector, index: EUint32Vector) -> EUint32Vector {
    data.get(&index)  // result[0] = data[index[0]], rest = 0
}
```

## Chained Operations

Multiple operations compose naturally in a single graph:

```rust
#[encrypt_fn]
fn dot_product_pair(
    a: EUint32Vector, b: EUint32Vector,
    c: EUint32Vector, d: EUint32Vector,
) -> EUint32Vector {
    a * b + c * d  // (a[i]*b[i]) + (c[i]*d[i])
}

#[encrypt_fn]
fn linear_transform(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    a * 5 + b * 3 + 7
}

#[encrypt_fn]
fn conditional_accumulate(
    cond: EBool,
    acc: EUint32Vector,
    val: EUint32Vector,
) -> EUint32Vector {
    let added = acc + val;
    if cond { added } else { acc }
}
```

## Creating Vectors

Vectors are **8,192 bytes** — too large for Solana instruction data (max ~1,232 bytes). They must be created off-chain via gRPC `CreateInput`:

### Rust Client

```rust
use encrypt_solana_client::grpc::{EncryptClient, TypedInput};
use encrypt_types::types::FheType;

// Build 8192-byte vector with elements at the start, rest zeros
let mut bytes = vec![0u8; 8192];
bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
bytes[4..8].copy_from_slice(&200u32.to_le_bytes());

let ct_pubkey = client
    .create_inputs(
        &[TypedInput::from_raw(FheType::EVectorU32, bytes)],
        &authorized_pubkey,
        &network_key,
    )
    .await?;
```

### TypeScript Client

```typescript
const bytes = new Uint8Array(8192);
new DataView(bytes.buffer).setUint32(0, 100, true);
new DataView(bytes.buffer).setUint32(4, 200, true);

const [ctPubkey] = await client.createInput({
  fheType: 34, // EVectorU32
  plaintextBytes: bytes,
  authorized: programId,
  networkKey,
});
```

## Testing Vectors

The test harness provides vector-specific helpers:

```rust
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::types::FheType;

let mut ctx = EncryptTestContext::new_default();

// Create a vector with specific elements
let mut bytes = vec![0u8; 8192];
bytes[0..4].copy_from_slice(&42u32.to_le_bytes());
bytes[4..8].copy_from_slice(&99u32.to_le_bytes());

let ct = ctx.create_input_bytes(FheType::EVectorU32, &bytes, &program_id);

// After graph execution + commit:
let result = ctx.decrypt_bytes(&ct);
let elem0 = u32::from_le_bytes(result[0..4].try_into().unwrap());
assert_eq!(elem0, 42);
```

## Decryption

Vector decryption responses are automatically chunked — the 8,192-byte plaintext is split across multiple transactions (~12 txs at 700 bytes each). The on-chain `DecryptionRequest` account tracks `bytes_written` / `total_len` and the executor writes chunks until complete. This is transparent to the developer.

## On-Chain Representation

Vectors use the same 98-byte `Ciphertext` account as scalars:

```
ciphertext_digest(32) + authorized(32) + network_encryption_public_key(32) + fhe_type(1) + status(1)
```

The 32-byte digest commits to the full 8,192-byte value. The actual encrypted data lives off-chain in the executor. The `fhe_type` field (e.g., `34` for `EVectorU32`) tells the executor how to interpret the data.

## Limitations

- **No on-chain plaintext creation**: `create_plaintext_ciphertext` can't handle 8,192 bytes in instruction data. Use gRPC `CreateInput` instead.
- **No cross-type extraction**: You can't extract a scalar `EUint32` from an `EUint32Vector` in a single graph (use `get` which returns a vector with the value at position 0).
- **No reductions**: There are no `sum`, `min_reduce`, or `max_reduce` operations yet that collapse a vector to a scalar. These are on the roadmap.
- **Index range**: For `EVectorU8`, indices are `u8` values (max 255) but the vector has 8,192 elements — only the first 256 are addressable by gather/scatter/assign.
