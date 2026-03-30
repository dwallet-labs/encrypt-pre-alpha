# Cast Votes

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


The `cast_vote` instruction is where FHE computation happens. The voter's encrypted vote is combined with the current tallies via the `cast_vote_graph` function, and the tally ciphertext accounts are updated in-place.

## Instruction Layout

```
discriminator: 1
data: vote_record_bump(1) | cpi_authority_bump(1)
accounts: [proposal(w), vote_record_pda(w), voter(s), vote_ct,
           yes_ct(w), no_ct(w),
           encrypt_program, config, deposit(w), cpi_authority,
           caller_program, network_encryption_key, payer(s,w),
           event_authority, system_program]
```

## Implementation

### Parse and Validate

```rust
fn cast_vote(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, vote_record_acct, voter, vote_ct, yes_ct, no_ct,
         encrypt_program, config, deposit, cpi_authority, caller_program,
         network_encryption_key, payer, event_authority, system_program, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !voter.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vote_record_bump = data[0];
    let cpi_authority_bump = data[1];

    // Verify proposal is open
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if prop.is_open == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let proposal_id = prop.proposal_id;
```

### Prevent Double Voting

Create a VoteRecord PDA. If the voter already voted, `CreateAccount` fails because the PDA already exists:

```rust
    let vr_bump_byte = [vote_record_bump];
    let vr_seeds = [
        Seed::from(b"vote" as &[u8]),
        Seed::from(proposal_id.as_ref()),
        Seed::from(voter.address().as_ref()),
        Seed::from(&vr_bump_byte),
    ];
    let vr_signer = [Signer::from(&vr_seeds)];

    CreateAccount {
        from: payer,
        to: vote_record_acct,
        lamports: minimum_balance(VoteRecord::LEN),
        space: VoteRecord::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&vr_signer)?;

    let vr_data = unsafe { vote_record_acct.borrow_unchecked_mut() };
    vr_data[0] = VOTE_RECORD;
    vr_data[1..33].copy_from_slice(voter.address().as_ref());
    vr_data[33] = vote_record_bump;
```

### Execute the FHE Graph

This is the key line -- call the DSL-generated CPI method:

```rust
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.cast_vote_graph(yes_ct, no_ct, vote_ct, yes_ct, no_ct)?;
```

Notice: `yes_ct` and `no_ct` appear as both **inputs** (positions 1-2) and **outputs** (positions 4-5). This is **update mode**.

### Update Mode

When an output account already contains ciphertext data, `execute_graph` operates in update mode:
- The existing ciphertext is **read** as an input
- The same account is **reset** as an output (digest zeroed, status set to PENDING)
- The executor evaluates the graph and commits the new digest

This means the tally accounts keep the same pubkey across all votes. No new accounts are created per vote.

### Increment Total Votes

After the FHE computation, increment the plaintext vote counter for transparency:

```rust
    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    prop_mut.set_total_votes(prop_mut.total_votes() + 1);

    Ok(())
}
```

## The Voter's Vote Ciphertext

The `vote_ct` account is an encrypted boolean (`EBool`) created by the voter before calling `cast_vote`. The voter:

1. Generates a keypair for the ciphertext account
2. Encrypts their vote (1 = yes, 0 = no) off-chain
3. Submits it to the executor via `create_input_ciphertext` (with ZK proof that the value is 0 or 1)
4. The executor verifies the proof and creates the on-chain ciphertext

The vote value is never visible on-chain. The program only sees the ciphertext account pubkey.

## Anchor Equivalent

In Anchor, the same logic uses `to_account_info()` and `.clone()`:

```rust
let yes_ct = ctx.accounts.yes_ct.to_account_info();
let no_ct = ctx.accounts.no_ct.to_account_info();
let vote_ct = ctx.accounts.vote_ct.to_account_info();
encrypt_ctx.cast_vote_graph(
    yes_ct.clone(), no_ct.clone(), vote_ct,
    yes_ct, no_ct,
)?;
```

## Next Step

With voting implemented, the next chapter covers decryption of the final tallies.
