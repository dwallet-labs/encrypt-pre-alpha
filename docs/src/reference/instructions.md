# Instruction Reference

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


All 22 instructions in the Encrypt Solana program. The first byte of instruction data is the discriminator.

## Instruction Groups

| Group | Disc Range | Instructions |
|-------|-----------|--------------|
| Setup | 0 | initialize |
| Executor | 1--6 | create_input_ciphertext, create_plaintext_ciphertext, commit_ciphertext, execute_graph, register_graph, execute_registered_graph |
| Ownership | 7--9 | transfer_ciphertext, copy_ciphertext, make_public |
| Gateway | 10--12 | request_decryption, respond_decryption, close_decryption_request |
| Fees | 13--18 | create_deposit, top_up, withdraw, update_config_fees, reimburse, request_withdraw |
| Authority | 19--21 | add_authority, remove_authority, register_network_encryption_key |
| Event | 228 | emit_event |

---

## Setup

### `initialize` (disc 0)

One-time program initialization. Creates the EncryptConfig and initial Authority PDAs.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | yes | no | EncryptConfig PDA (must be empty) |
| 1 | authority_pda | yes | no | Authority PDA (must be empty) |
| 2 | initializer | no | yes | Initial authority signer |
| 3 | payer | yes | yes | Rent payer |
| 4 | system_program | no | no | System program |

**Data (2 bytes):** `config_bump(1) | authority_bump(1)`

---

## Executor

### `create_input_ciphertext` (disc 1)

Authority-driven: creates a verified ciphertext from off-chain encrypted data + ZK proof. Status = VERIFIED immediately.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | authority_pda | no | no | Authority PDA |
| 1 | signer | no | yes | Authority signer |
| 2 | config | no | no | EncryptConfig |
| 3 | deposit | yes | no | EncryptDeposit (fee source) |
| 4 | ciphertext | yes | no | New Ciphertext account (must be empty) |
| 5 | creator | no | no | Who gets authorized |
| 6 | network_encryption_key | no | no | NetworkEncryptionKey PDA |
| 7 | payer | yes | yes | Rent payer |
| 8 | system_program | no | no | System program |
| 9 | event_authority | no | no | Event authority PDA |
| 10 | program | no | no | Encrypt program |

**Data (33 bytes):** `fhe_type(1) | ciphertext_digest(32)`

---

### `create_plaintext_ciphertext` (disc 2)

User-signed: creates a ciphertext from a plaintext value. The executor encrypts off-chain and commits later. Status = PENDING.

Supports both signer and CPI (program) callers. CPI path inserts `cpi_authority` at position 4.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | no | no | EncryptConfig |
| 1 | deposit | yes | no | EncryptDeposit |
| 2 | ciphertext | yes | no | New Ciphertext account (must be empty) |
| 3 | creator | no | yes | Signer (gets authorized) |
| 4 | network_encryption_key | no | no | NetworkEncryptionKey PDA |
| 5 | payer | yes | yes | Rent payer |
| 6 | system_program | no | no | System program |
| 7 | event_authority | no | no | Event authority PDA |
| 8 | program | no | no | Encrypt program |

**Accounts (CPI path):** Same as above but `cpi_authority` is inserted at position 4, shifting positions 4--8 to 5--9.

**Data (1+ bytes):** `fhe_type(1) | [plaintext_bytes(N)]`

---

### `commit_ciphertext` (disc 3)

Authority writes the ciphertext digest after off-chain FHE evaluation. Sets status from PENDING to VERIFIED.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | authority_pda | no | no | Authority PDA |
| 1 | signer | no | yes | Authority signer |
| 2 | ciphertext | yes | no | Ciphertext account |
| 3 | event_authority | no | no | Event authority PDA |
| 4 | program | no | no | Encrypt program |

**Data (32 bytes):** `ciphertext_digest(32)`

---

### `execute_graph` (disc 4)

Execute a computation graph. Creates/updates output ciphertext accounts. Emits `GraphExecuted` event.

Supports both signer and CPI callers. CPI path inserts `cpi_authority` at position 3.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | no | no | EncryptConfig |
| 1 | deposit | yes | no | EncryptDeposit |
| 2 | caller | no | yes | Signer |
| 3 | network_encryption_key | no | no | NetworkEncryptionKey PDA |
| 4 | payer | yes | yes | Rent payer |
| 5 | event_authority | no | no | Event authority PDA |
| 6 | program | no | no | Encrypt program |
| 7..7+N | input ciphertexts | no | no | Input ciphertext accounts |
| 7+N..7+N+M | output ciphertexts | yes | no | Output ciphertext accounts |

**Accounts (CPI path):** `cpi_authority` at position 3, remaining shifted by 1. Fixed accounts = 8 instead of 7.

**Data:** `graph_data_len(2) | graph_data(N) | num_inputs(2)`

---

### `register_graph` (disc 5)

Register a reusable computation graph on-chain. Creates a RegisteredGraph PDA.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | graph_pda | yes | no | RegisteredGraph PDA (must be empty) |
| 1 | registrar | no | yes | Signer |
| 2 | payer | yes | yes | Rent payer |
| 3 | system_program | no | no | System program |

**Data (35+ bytes):** `bump(1) | graph_hash(32) | graph_data_len(2) | graph_data(N)`

---

### `execute_registered_graph` (disc 6)

Execute a previously registered graph. Uses the on-chain graph data (no need to re-send).

Supports both signer and CPI callers.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | no | no | EncryptConfig |
| 1 | deposit | yes | no | EncryptDeposit |
| 2 | graph_pda | no | no | RegisteredGraph PDA |
| 3 | caller | no | yes | Signer |
| 4 | network_encryption_key | no | no | NetworkEncryptionKey PDA |
| 5 | payer | yes | yes | Rent payer |
| 6 | event_authority | no | no | Event authority PDA |
| 7 | program | no | no | Encrypt program |
| 8+ | remaining | varies | no | Input + output ciphertexts |

**Accounts (CPI path):** `cpi_authority` at position 4, fixed = 9.

**Data (2 bytes):** `num_inputs(2)`

---

## Ownership

### `transfer_ciphertext` (disc 7)

Transfer authorization to a new party by updating the `authorized` field.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | ciphertext | yes | no | Ciphertext account |
| 1 | current_authorized | no | yes | Current authorized signer |
| 2 | new_authorized | no | no | New authorized party |

**Accounts (CPI path):** `cpi_authority` at position 2, `new_authorized` at position 3.

**Data:** none

---

### `copy_ciphertext` (disc 8)

Create a copy of a ciphertext with a different authorized party.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | source_ciphertext | no | no | Source Ciphertext |
| 1 | new_ciphertext | yes | no | New Ciphertext account (must be empty) |
| 2 | current_authorized | no | yes | Current authorized signer |
| 3 | new_authorized | no | no | New authorized party |
| 4 | payer | yes | yes | Rent payer |
| 5 | system_program | no | no | System program |

**Accounts (CPI path):** `cpi_authority` at position 3, remaining shifted.

**Data (1 byte):** `transient(1)` (0 = permanent/rent-exempt, 1 = transient/0 lamports)

---

### `make_public` (disc 9)

Set `authorized` to zero (public). Irreversible and idempotent.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | ciphertext | yes | no | Ciphertext account |
| 1 | caller | no | yes | Current authorized signer |

**Accounts (CPI path):** `cpi_authority` at position 2.

**Data (32 bytes):** `ciphertext_id(32)`

---

## Gateway

### `request_decryption` (disc 10)

Request decryption of a ciphertext. Creates a DecryptionRequest account and stores a digest snapshot.

Supports both signer and CPI callers.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | no | no | EncryptConfig |
| 1 | deposit | yes | no | EncryptDeposit |
| 2 | request_acct | yes | no | DecryptionRequest account (must be empty) |
| 3 | caller | no | yes | Signer |
| 4 | ciphertext | no | no | Ciphertext to decrypt |
| 5 | payer | yes | yes | Rent payer |
| 6 | system_program | no | no | System program |
| 7 | event_authority | no | no | Event authority PDA |
| 8 | program | no | no | Encrypt program |

**Accounts (CPI path):** `cpi_authority` at position 4, remaining shifted. Fixed = 10.

**Data:** none

---

### `respond_decryption` (disc 11)

Authority writes the decrypted plaintext bytes into the DecryptionRequest account.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | authority_pda | no | no | Authority PDA |
| 1 | request_acct | yes | no | DecryptionRequest account |
| 2 | signer | no | yes | Authority signer |
| 3 | event_authority | no | no | Event authority PDA |
| 4 | program | no | no | Encrypt program |

**Data (variable):** plaintext bytes chunk to write

---

### `close_decryption_request` (disc 12)

Close a decryption request and reclaim rent. Only the original requester can close.

**Accounts (signer path):**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | request | yes | no | DecryptionRequest account |
| 1 | caller | no | yes | Requester signer |
| 2 | destination | yes | no | Rent destination |

**Accounts (CPI path):** `cpi_authority` at position 2, `destination` at position 3.

**Data:** none

---

## Fees

### `create_deposit` (disc 13)

Create an EncryptDeposit PDA for a user. Transfers initial ENC tokens and SOL gas.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | deposit | yes | no | EncryptDeposit PDA (must be empty) |
| 1 | config | no | no | EncryptConfig |
| 2 | user | no | yes | Deposit owner |
| 3 | payer | yes | yes | Rent payer |
| 4 | user_ata | yes | no | User's ENC token account |
| 5 | vault | yes | no | Program's ENC vault token account |
| 6 | token_program | no | no | SPL Token program |
| 7 | system_program | no | no | System program |

**Data (17 bytes):** `bump(1) | initial_enc_amount(8) | initial_gas_amount(8)`

---

### `top_up` (disc 14)

Add ENC tokens and/or SOL gas to an existing deposit.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | deposit | yes | no | EncryptDeposit PDA |
| 1 | config | no | no | EncryptConfig |
| 2 | user | no | yes | Deposit owner |
| 3 | user_ata | yes | no | User's ENC token account |
| 4 | vault | yes | no | ENC vault |
| 5 | token_program | no | no | SPL Token program |
| 6 | system_program | no | no | System program |

**Data (16 bytes):** `enc_amount(8) | gas_amount(8)`

---

### `withdraw` (disc 15)

Execute a pending withdrawal. Available when `current_epoch >= withdrawal_epoch`.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | deposit | yes | no | EncryptDeposit PDA |
| 1 | config | no | no | EncryptConfig |
| 2 | user | no | yes | Deposit owner |
| 3 | user_ata | yes | no | User's ENC token account |
| 4 | vault | yes | no | ENC vault |
| 5 | vault_authority | no | no | Vault authority PDA |
| 6 | token_program | no | no | SPL Token program |

**Data:** none

---

### `update_config_fees` (disc 16)

Authority updates the fee schedule in EncryptConfig.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | config | yes | no | EncryptConfig PDA |
| 1 | authority_pda | no | no | Authority PDA |
| 2 | signer | no | yes | Authority signer |

**Data (58 bytes):** `enc_per_input(8) | enc_per_output(8) | max_enc_per_op(8) | max_ops_per_graph(2) | gas_base(8) | gas_per_input(8) | gas_per_output(8) | gas_per_byte(8)`

---

### `reimburse` (disc 17)

Authority credits back the per-op max-charge overcharge after computing actual costs.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | authority_pda | no | no | Authority PDA |
| 1 | signer | no | yes | Authority signer |
| 2 | deposit | yes | no | EncryptDeposit PDA |

**Data (16 bytes):** `enc_amount(8) | gas_amount(8)`

---

### `request_withdraw` (disc 18)

Set pending withdrawal amounts. Actual withdrawal available next epoch.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | deposit | yes | no | EncryptDeposit PDA |
| 1 | config | no | no | EncryptConfig |
| 2 | user | no | yes | Deposit owner |

**Data (16 bytes):** `enc_amount(8) | gas_amount(8)`

---

## Authority

### `add_authority` (disc 19)

Add a new authority. Must be signed by an existing authority.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | new_auth | yes | no | New Authority PDA (must be empty) |
| 1 | existing_auth | no | no | Existing Authority PDA |
| 2 | signer | no | yes | Existing authority signer |
| 3 | payer | yes | yes | Rent payer |
| 4 | system_program | no | no | System program |

**Data (33 bytes):** `bump(1) | new_pubkey(32)`

---

### `remove_authority` (disc 20)

Deactivate an authority.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | target_auth | yes | no | Authority PDA to deactivate |
| 1 | signer_auth | no | no | Signer's Authority PDA |
| 2 | signer | no | yes | Authority signer |

**Data:** none

---

### `register_network_encryption_key` (disc 21)

Register a new FHE network encryption public key.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | network_encryption_key_pda | yes | no | NetworkEncryptionKey PDA (must be empty) |
| 1 | authority_pda | no | no | Authority PDA |
| 2 | signer | no | yes | Authority signer |
| 3 | payer | yes | yes | Rent payer |
| 4 | system_program | no | no | System program |

**Data (33 bytes):** `bump(1) | network_public_key(32)`

---

## Event

### `emit_event` (disc 228)

Self-CPI event handler. Called internally by the Encrypt program to emit Anchor-compatible events. Not called by external programs.

**Accounts:**

| # | Account | W | S | Description |
|---|---------|---|---|-------------|
| 0 | event_authority | no | no | Event authority PDA (must match) |
| 1 | program | no | no | Encrypt program |

**Data:** Event payload (prefixed with `EVENT_IX_TAG_LE`)
