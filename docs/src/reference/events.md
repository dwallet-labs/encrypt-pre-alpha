# Event Reference

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


The Encrypt program emits 5 event types via Anchor-compatible self-CPI. Each event is prefixed with `EVENT_IX_TAG_LE` (8 bytes, `0xe4a545ea51cb9a1d` in LE) followed by a 1-byte event discriminator.

## Event Discriminators

| Discriminator | Event |
|---------------|-------|
| 0 | CiphertextCreated |
| 1 | CiphertextCommitted |
| 2 | GraphExecuted |
| 3 | DecryptionRequested |
| 4 | DecryptionResponded |

---

## CiphertextCreated (disc 0)

Emitted when a new ciphertext account is created (`create_input_ciphertext` or `create_plaintext_ciphertext`).

| Field | Size | Description |
|-------|------|-------------|
| ciphertext | 32 | Ciphertext account pubkey |
| ciphertext_digest | 32 | Initial digest (zero for plaintext, real for input) |
| fhe_type | 1 | FHE type discriminant |

**Data size: 65 bytes**

Used by the executor to detect new ciphertexts that need processing (plaintext ciphertexts need encryption and commit).

---

## CiphertextCommitted (disc 1)

Emitted when an authority commits a ciphertext digest (`commit_ciphertext`), transitioning status from PENDING to VERIFIED.

| Field | Size | Description |
|-------|------|-------------|
| ciphertext | 32 | Ciphertext account pubkey |
| ciphertext_digest | 32 | The committed digest |

**Data size: 64 bytes**

Used by off-chain services to track when ciphertexts become usable as inputs.

---

## GraphExecuted (disc 2)

Emitted when a computation graph is executed (`execute_graph` or `execute_registered_graph`). Output ciphertext accounts are created/updated with status=PENDING.

| Field | Size | Description |
|-------|------|-------------|
| num_outputs | 2 | Number of output ciphertexts (LE u16) |
| num_inputs | 2 | Number of input ciphertexts (LE u16) |
| caller_program | 32 | Program that invoked execute_graph via CPI |

**Data size: 36 bytes**

This is the primary event the executor listens for. Upon detection, the executor:
1. Reads the graph data from the transaction
2. Fetches the input ciphertext blobs
3. Evaluates the computation graph using FHE
4. Calls `commit_ciphertext` for each output

---

## DecryptionRequested (disc 3)

Emitted when a decryption request is created (`request_decryption`).

| Field | Size | Description |
|-------|------|-------------|
| ciphertext | 32 | Ciphertext account pubkey |
| requester | 32 | Who requested decryption |

**Data size: 64 bytes**

The decryptor listens for this event and:
1. Performs threshold MPC decryption (or mock decryption locally)
2. Calls `respond_decryption` to write the plaintext result

---

## DecryptionResponded (disc 4)

Emitted when the decryptor writes the plaintext result (`respond_decryption`).

| Field | Size | Description |
|-------|------|-------------|
| ciphertext | 32 | Ciphertext account pubkey |
| requester | 32 | Who requested decryption |

**Data size: 64 bytes**

Off-chain clients listen for this event to know when a decryption result is ready to read.

---

## Event Wire Format

Each event is emitted as a self-CPI instruction with the following data layout:

```
EVENT_IX_TAG_LE(8) | event_discriminator(1) | event_data(N)
```

Total on-wire size per event = 9 + data size.

| Event | On-Wire Size |
|-------|-------------|
| CiphertextCreated | 9 + 65 = 74 bytes |
| CiphertextCommitted | 9 + 64 = 73 bytes |
| GraphExecuted | 9 + 36 = 45 bytes |
| DecryptionRequested | 9 + 64 = 73 bytes |
| DecryptionResponded | 9 + 64 = 73 bytes |

## Parsing Events

Events are emitted as inner instructions in the transaction. To parse them:

1. Find inner instructions targeting the Encrypt program with discriminator `228` (EmitEvent)
2. Skip the first 8 bytes (`EVENT_IX_TAG_LE`)
3. Read the 1-byte event discriminator
4. Deserialize the remaining bytes according to the event schema

The `chains/solana/dev` crate provides an event parser for use in tests and off-chain services.
