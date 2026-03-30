# Building the Voting Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Step-by-step guide to the Anchor on-chain program.

## What you'll learn

- How to define an FHE graph with conditional logic (if/else compiles to Select)
- Proposal state with encrypted counters
- Update-mode ciphertexts (same account as input and output)
- VoteRecord PDA for double-vote prevention
- The decrypt-then-reveal pattern for tallies

## 1. The cast_vote graph

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::{EBool, EUint64};

#[encrypt_fn]
fn cast_vote_graph(
    yes_count: EUint64,
    no_count: EUint64,
    vote: EBool,
) -> (EUint64, EUint64) {
    let new_yes = if vote { yes_count + 1 } else { yes_count };
    let new_no = if vote { no_count } else { no_count + 1 };
    (new_yes, new_no)
}
```

This graph takes three encrypted inputs and produces two encrypted outputs:

- `yes_count` / `no_count` -- current encrypted tallies (EUint64)
- `vote` -- the voter's encrypted choice (EBool: true = yes, false = no)

The `if vote { ... } else { ... }` syntax compiles to a `Select` operation in the FHE graph. Select is a ternary: `Select(condition, if_true, if_false)`. The executor evaluates this homomorphically -- it never learns whether the voter chose yes or no.

The graph returns a tuple `(new_yes, new_no)`. If vote = true, `new_yes = yes_count + 1` and `new_no = no_count` (unchanged). If vote = false, the reverse.

`#[encrypt_fn]` generates a `CastVoteGraphCpi` trait with a `cast_vote_graph()` method on `EncryptContext`. The method takes 3 input accounts and 2 output accounts.

## 2. Proposal state

```rust
#[account]
#[derive(InitSpace)]
pub struct Proposal {
    pub authority: Pubkey,            // who can close + reveal
    pub proposal_id: [u8; 32],
    pub yes_count: [u8; 32],         // ciphertext account pubkey
    pub no_count: [u8; 32],          // ciphertext account pubkey
    pub is_open: bool,
    pub total_votes: u64,            // plaintext counter (for UI)
    pub revealed_yes: u64,           // written at reveal time
    pub revealed_no: u64,            // written at reveal time
    pub pending_yes_digest: [u8; 32],
    pub pending_no_digest: [u8; 32],
    pub bump: u8,
}
```

`yes_count` and `no_count` store ciphertext account pubkeys. These are the encrypted counters that get updated with every vote. `pending_yes_digest` and `pending_no_digest` are set when decryption is requested, used to verify the reveal.

```rust
#[account]
#[derive(InitSpace)]
pub struct VoteRecord {
    pub voter: Pubkey,
    pub bump: u8,
}
```

VoteRecord is a PDA derived from `["vote", proposal_id, voter_pubkey]`. If it already exists, Anchor's `init` constraint fails, preventing double votes.

## 3. create_proposal -- initialize encrypted zero counters

```rust
pub fn create_proposal(
    ctx: Context<CreateProposal>,
    proposal_id: [u8; 32],
    initial_yes_id: [u8; 32],
    initial_no_id: [u8; 32],
) -> Result<()> {
    let prop = &mut ctx.accounts.proposal;
    prop.authority = ctx.accounts.authority.key();
    prop.proposal_id = proposal_id;
    prop.yes_count = initial_yes_id;
    prop.no_count = initial_no_id;
    prop.is_open = true;
    prop.total_votes = 0;
    prop.bump = ctx.bumps.proposal;
    Ok(())
}
```

The `initial_yes_id` and `initial_no_id` are ciphertext accounts pre-created with `create_plaintext_typed::<Uint64>(0)`. They start as encrypted zeros. The frontend creates these keypair accounts and passes their pubkeys.

Account validation:

```rust
#[derive(Accounts)]
#[instruction(proposal_id: [u8; 32])]
pub struct CreateProposal<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Proposal::INIT_SPACE,
        seeds = [b"proposal", proposal_id.as_ref()],
        bump,
    )]
    pub proposal: Account<'info, Proposal>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## 4. cast_vote -- encrypted vote with update-mode ciphertexts

```rust
pub fn cast_vote(
    ctx: Context<CastVote>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let prop = &ctx.accounts.proposal;
    require!(prop.is_open, VotingError::ProposalClosed);

    let encrypt_ctx = EncryptContext {
        encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
        config: ctx.accounts.config.to_account_info(),
        deposit: ctx.accounts.deposit.to_account_info(),
        cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
        caller_program: ctx.accounts.caller_program.to_account_info(),
        network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
        payer: ctx.accounts.payer.to_account_info(),
        event_authority: ctx.accounts.event_authority.to_account_info(),
        system_program: ctx.accounts.system_program.to_account_info(),
        cpi_authority_bump,
    };

    let yes_ct = ctx.accounts.yes_ct.to_account_info();
    let no_ct = ctx.accounts.no_ct.to_account_info();
    let vote_ct = ctx.accounts.vote_ct.to_account_info();
    encrypt_ctx.cast_vote_graph(
        yes_ct.clone(), no_ct.clone(), vote_ct,
        yes_ct, no_ct,
    )?;

    let prop = &mut ctx.accounts.proposal;
    prop.total_votes += 1;

    let vr = &mut ctx.accounts.vote_record;
    vr.voter = ctx.accounts.voter.key();
    vr.bump = ctx.bumps.vote_record;

    Ok(())
}
```

**Update mode:** Notice that `yes_ct` and `no_ct` appear as both inputs and outputs:

```rust
encrypt_ctx.cast_vote_graph(
    yes_ct.clone(), no_ct.clone(), vote_ct,  // inputs: yes, no, vote
    yes_ct, no_ct,                            // outputs: yes, no
)?;
```

The same ciphertext accounts are read (current tally) and written (new tally). The executor reads the current encrypted value, computes the graph, and writes the result back to the same account. This avoids creating new ciphertext accounts for every vote.

**The vote ciphertext** (`vote_ct`) is created before this instruction. The browser encrypts the vote locally via `encryptValue()` and sends the ciphertext directly to the executor via gRPC-Web `createInput`. It's an encrypted boolean authorized to the voting program.

**Double-vote prevention:** The `vote_record` account uses Anchor's `init` constraint:

```rust
#[account(
    init,
    payer = payer,
    space = 8 + VoteRecord::INIT_SPACE,
    seeds = [b"vote", proposal.proposal_id.as_ref(), voter.key().as_ref()],
    bump,
)]
pub vote_record: Account<'info, VoteRecord>,
```

If the voter has already voted on this proposal, the PDA already exists and `init` fails. Simple and gas-efficient.

## 5. close_proposal -- lock voting

```rust
pub fn close_proposal(ctx: Context<CloseProposal>) -> Result<()> {
    let prop = &mut ctx.accounts.proposal;
    require!(
        prop.authority == ctx.accounts.authority.key(),
        VotingError::Unauthorized
    );
    require!(prop.is_open, VotingError::ProposalClosed);
    prop.is_open = false;
    Ok(())
}
```

Only the authority can close. After closing, no more votes can be cast (the `cast_vote` guard checks `is_open`). Decryption can only be requested after closing.

## 6. request_tally_decryption -- two separate requests

```rust
pub fn request_tally_decryption(
    ctx: Context<RequestTallyDecryption>,
    is_yes: bool,
    cpi_authority_bump: u8,
) -> Result<()> {
    let prop = &ctx.accounts.proposal;
    require!(!prop.is_open, VotingError::ProposalStillOpen);

    let encrypt_ctx = EncryptContext { /* ... */ };

    let digest = encrypt_ctx.request_decryption(
        &ctx.accounts.request_acct.to_account_info(),
        &ctx.accounts.ciphertext.to_account_info(),
    )?;

    let prop = &mut ctx.accounts.proposal;
    if is_yes {
        prop.pending_yes_digest = digest;
    } else {
        prop.pending_no_digest = digest;
    }
    Ok(())
}
```

Each ciphertext (yes_count, no_count) needs its own decryption request. The `is_yes` flag determines which digest to store. You call this instruction twice -- once for yes, once for no.

The `request_acct` is a fresh keypair account that the decryptor network will write the plaintext into.

## 7. reveal_tally -- read decrypted values

```rust
pub fn reveal_tally(ctx: Context<RevealTally>, is_yes: bool) -> Result<()> {
    let prop = &mut ctx.accounts.proposal;
    require!(
        prop.authority == ctx.accounts.authority.key(),
        VotingError::Unauthorized
    );
    require!(!prop.is_open, VotingError::ProposalStillOpen);

    let expected_digest = if is_yes {
        &prop.pending_yes_digest
    } else {
        &prop.pending_no_digest
    };

    let req_data = ctx.accounts.request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
        &req_data, expected_digest,
    ).map_err(|_| VotingError::DecryptionNotComplete)?;

    if is_yes {
        prop.revealed_yes = *value;
    } else {
        prop.revealed_no = *value;
    }
    Ok(())
}
```

`read_decrypted_verified` checks that the decrypted value's digest matches what was stored at request time. This prevents reading stale or tampered values. Called twice -- once for yes, once for no. Only the authority can reveal.

## Instruction summary

| Disc | Instruction | Who | When |
|------|-------------|-----|------|
| 0 | `create_proposal` | Authority | Start -- creates encrypted zero counters |
| 1 | `cast_vote` | Any voter | While open -- encrypted vote, graph updates counters |
| 2 | `close_proposal` | Authority | After voting ends -- locks further votes |
| 3 | `request_tally_decryption` | Anyone | After close -- one call per counter (yes/no) |
| 4 | `reveal_tally` | Authority | After decryption -- writes plaintext to proposal |
