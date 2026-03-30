# Decrypt Results

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


After the proposal is closed, the authority requests decryption of the tally ciphertexts, then reads and verifies the results.

## Close the Proposal

First, the authority closes voting:

```rust
fn close_proposal(accounts: &[AccountView]) -> ProgramResult {
    let [proposal_acct, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let prop_data = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop = Proposal::from_bytes_mut(prop_data)?;

    if authority.address().as_array() != &prop.authority {
        return Err(ProgramError::InvalidArgument);
    }
    if prop.is_open == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    prop.is_open = 0;
    Ok(())
}
```

## Request Decryption

The authority calls `request_tally_decryption` for each tally (yes and no separately):

```rust
fn request_tally_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, request_acct, ciphertext, encrypt_program, config,
         deposit, cpi_authority, caller_program, network_encryption_key,
         payer, event_authority, system_program, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let cpi_authority_bump = data[0];
    let is_yes = data[1] != 0;

    // Verify proposal is closed
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if prop.is_open != 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    // request_decryption returns the ciphertext_digest -- store it
    let digest = ctx.request_decryption(request_acct, ciphertext)?;

    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    if is_yes {
        prop_mut.pending_yes_digest = digest;
    } else {
        prop_mut.pending_no_digest = digest;
    }

    Ok(())
}
```

### What `request_decryption` Does

1. Creates a `DecryptionRequest` keypair account
2. Stores a snapshot of the ciphertext's current `ciphertext_digest`
3. Returns the digest as `[u8; 32]`
4. Emits a `DecryptionRequested` event

The decryptor detects the event, performs threshold MPC decryption (or mock decryption locally), and calls `respond_decryption` to write the plaintext result into the request account.

### Why Store the Digest?

The ciphertext could be updated between request and response (e.g., another vote sneaks in). By storing the digest at request time and verifying it at reveal time, you ensure the decrypted value corresponds to the exact ciphertext you requested.

## Reveal the Tally

Once the decryptor has responded, the authority reads the result:

```rust
fn reveal_tally(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, request_acct, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let is_yes = data[0] != 0;

    // Verify authority and closed status
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if authority.address().as_array() != &prop.authority {
        return Err(ProgramError::InvalidArgument);
    }
    if prop.is_open != 0 {
        return Err(ProgramError::InvalidArgument);
    }

    // Get the digest stored at request time
    let expected_digest = if is_yes {
        &prop.pending_yes_digest
    } else {
        &prop.pending_no_digest
    };

    // Verify and read the decrypted value
    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, expected_digest)?;

    // Write plaintext to proposal
    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    if is_yes {
        prop_mut.revealed_yes = value.to_le_bytes();
    } else {
        prop_mut.revealed_no = value.to_le_bytes();
    }

    Ok(())
}
```

### `read_decrypted_verified`

This function:
1. Reads the `DecryptionRequestHeader` from the request account
2. Verifies `bytes_written == total_len` (decryption is complete)
3. Verifies the stored `ciphertext_digest` matches `expected_digest`
4. Returns a reference to the plaintext value

If the digest does not match, it returns an error -- protecting against stale or tampered values.

## Full Decryption Flow

```
1. close_proposal         -- authority closes voting
2. request_tally_decryption(is_yes=true)   -- store yes digest
3. request_tally_decryption(is_yes=false)  -- store no digest
4. [decryptor responds automatically]
5. reveal_tally(is_yes=true)    -- read yes result, verify digest
6. reveal_tally(is_yes=false)   -- read no result, verify digest
```

After step 6, the proposal's `revealed_yes` and `revealed_no` fields contain the plaintext tallies, readable by anyone.

## Cleanup

After revealing, close the decryption request accounts to reclaim rent:

```rust
ctx.close_decryption_request(request_acct, destination)?;
```

## Next Step

The next chapter covers testing the complete voting flow with `EncryptTestContext`.
