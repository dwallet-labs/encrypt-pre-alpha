# Building the Coin Flip Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Step-by-step guide to the Anchor on-chain program.

## What you'll learn

- How to define an FHE graph with `#[encrypt_fn]`
- Game state design with escrow
- CPI to Encrypt for graph execution and decryption
- The full instruction set: create, play, decrypt, reveal, cancel

## 1. The XOR graph

The entire fairness mechanism is a single line:

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}
```

`#[encrypt_fn]` compiles this into a binary graph that the Encrypt executor evaluates using FHE. The function itself never runs on-chain -- it generates a static graph at compile time. The macro also generates an extension trait (`CoinFlipGraphCpi`) with a method `coin_flip_graph()` on `EncryptContext` that handles the CPI.

**Why XOR is fair:** If both sides pick the same value (0^0 or 1^1), result = 0 (side B wins). If they differ (0^1 or 1^0), result = 1 (side A wins). Neither side can predict the other's encrypted value, so both have a 50/50 chance.

## 2. Game state

```rust
#[account]
#[derive(InitSpace)]
pub struct Game {
    pub side_a: Pubkey,              // game creator
    pub game_id: [u8; 32],          // unique identifier
    pub commit_a: [u8; 32],         // side A's ciphertext account pubkey
    pub result_ct: [u8; 32],        // result ciphertext account pubkey
    pub side_b: Pubkey,             // joiner (zeroed until play)
    pub is_active: bool,
    pub played: bool,               // false=waiting, true=both committed
    pub pending_digest: [u8; 32],   // decryption digest for verification
    pub revealed_result: u8,        // 0=unknown, 1=side_a wins, 2=side_b wins
    pub bet_lamports: u64,
    pub bump: u8,
}
```

Key design choices:
- `commit_a` and `result_ct` store ciphertext account pubkeys (32 bytes each). These are keypair accounts in Encrypt, so pubkey = identifier.
- `pending_digest` is set when decryption is requested. At reveal time, we verify the decrypted value matches this digest -- preventing stale or tampered results.
- `bet_lamports` is the per-side bet. The PDA holds both deposits.

## 3. create_game -- side A deposits and commits

```rust
pub fn create_game(
    ctx: Context<CreateGame>,
    game_id: [u8; 32],
    commit_a_id: [u8; 32],
    result_ct_id: [u8; 32],
    bet_lamports: u64,
) -> Result<()> {
    // Side A deposits bet
    if bet_lamports > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.game.to_account_info(),
                },
            ),
            bet_lamports,
        )?;
    }

    let game = &mut ctx.accounts.game;
    game.side_a = ctx.accounts.side_a.key();
    game.game_id = game_id;
    game.commit_a = commit_a_id;
    game.result_ct = result_ct_id;
    game.side_b = Pubkey::default();
    game.is_active = true;
    game.played = false;
    game.pending_digest = [0u8; 32];
    game.revealed_result = 0;
    game.bet_lamports = bet_lamports;
    game.bump = ctx.bumps.game;
    Ok(())
}
```

The game PDA is derived from `["game", game_id]`. Side A's encrypted commit (`commit_a_id`) is created before this instruction via gRPC `createInput`. The `result_ct_id` is a pre-created plaintext ciphertext (initialized to 0) that will hold the XOR output.

**Why pre-create result_ct:** Encrypt's `execute_graph` writes results into existing ciphertext accounts. The output account must exist before the graph runs. Side A creates it during `create_game` so it's ready when side B triggers the XOR.

Account validation:

```rust
#[derive(Accounts)]
#[instruction(game_id: [u8; 32])]
pub struct CreateGame<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Game::INIT_SPACE,
        seeds = [b"game", game_id.as_ref()],
        bump,
    )]
    pub game: Account<'info, Game>,
    pub side_a: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## 4. play -- side B matches bet and triggers XOR

```rust
pub fn play(ctx: Context<Play>, cpi_authority_bump: u8) -> Result<()> {
    let game = &ctx.accounts.game;
    require!(game.is_active, CoinFlipError::GameClosed);
    require!(!game.played, CoinFlipError::AlreadyPlayed);

    // Verify ciphertext accounts match game state
    require!(
        ctx.accounts.commit_a_ct.key().to_bytes() == game.commit_a,
        CoinFlipError::InvalidAccount
    );
    require!(
        ctx.accounts.result_ct.key().to_bytes() == game.result_ct,
        CoinFlipError::InvalidAccount
    );

    // Side B matches bet
    let bet = game.bet_lamports;
    if bet > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.side_b.to_account_info(),
                    to: ctx.accounts.game.to_account_info(),
                },
            ),
            bet,
        )?;
    }

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

    let commit_a = ctx.accounts.commit_a_ct.to_account_info();
    let commit_b = ctx.accounts.commit_b_ct.to_account_info();
    let result = ctx.accounts.result_ct.to_account_info();
    encrypt_ctx.coin_flip_graph(commit_a, commit_b, result)?;

    let game = &mut ctx.accounts.game;
    game.side_b = ctx.accounts.side_b.key();
    game.played = true;
    Ok(())
}
```

The `coin_flip_graph()` method is auto-generated by `#[encrypt_fn]`. It CPIs into the Encrypt program with the graph bytecode, input ciphertext accounts (`commit_a`, `commit_b`), and output account (`result`). The executor picks this up off-chain, computes the encrypted XOR, and writes the result back to `result_ct`.

The `EncryptContext` bundles all the Encrypt program accounts needed for CPI. The `cpi_authority` is a PDA derived from your program's ID -- it authorizes your program to call Encrypt.

## 5. request_result_decryption

```rust
pub fn request_result_decryption(
    ctx: Context<RequestResultDecryption>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let game = &ctx.accounts.game;
    require!(game.played, CoinFlipError::NotPlayed);

    let encrypt_ctx = EncryptContext { /* ... same fields ... */ };

    let digest = encrypt_ctx.request_decryption(
        &ctx.accounts.request_acct.to_account_info(),
        &ctx.accounts.result_ciphertext.to_account_info(),
    )?;

    let game = &mut ctx.accounts.game;
    game.pending_digest = digest;
    Ok(())
}
```

`request_decryption` creates a decryption request account (keypair, not PDA) and returns a 32-byte digest. This digest is a snapshot of the ciphertext's current state. Storing it in the game ensures that `reveal_result` verifies against the exact value that was requested for decryption.

Anyone can call this after both sides have played.

## 6. reveal_result -- verify and pay winner

```rust
pub fn reveal_result(ctx: Context<RevealResult>) -> Result<()> {
    let game = &ctx.accounts.game;
    require!(game.played, CoinFlipError::NotPlayed);
    require!(game.revealed_result == 0, CoinFlipError::AlreadyRevealed);

    let expected_digest = &game.pending_digest;

    let req_data = ctx.accounts.request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        expected_digest,
    )
    .map_err(|_| CoinFlipError::DecryptionNotComplete)?;

    let side_a_wins = *value == 1;
    let expected_winner = if side_a_wins { game.side_a } else { game.side_b };
    require!(
        ctx.accounts.winner.key() == expected_winner,
        CoinFlipError::WrongWinner
    );

    // Pay winner
    let payout = game.bet_lamports * 2;
    if payout > 0 {
        let game_info = ctx.accounts.game.to_account_info();
        let winner_info = ctx.accounts.winner.to_account_info();
        **game_info.lamports.borrow_mut() -= payout;
        **winner_info.lamports.borrow_mut() += payout;
    }

    let game = &mut ctx.accounts.game;
    game.revealed_result = if side_a_wins { 1 } else { 2 };
    game.is_active = false;
    Ok(())
}
```

`read_decrypted_verified::<Uint64>` reads the decrypted value from the request account and verifies it against the stored digest. If the ciphertext was modified after the decryption request, the digest won't match and this fails.

The payout uses direct lamport manipulation -- the game PDA is program-owned, so we can debit it directly.

## 7. cancel_game -- refund before play

```rust
pub fn cancel_game(ctx: Context<CancelGame>) -> Result<()> {
    let game = &ctx.accounts.game;
    require!(game.is_active, CoinFlipError::GameClosed);
    require!(!game.played, CoinFlipError::AlreadyPlayed);
    require!(
        ctx.accounts.side_a.key() == game.side_a,
        CoinFlipError::Unauthorized
    );

    let bet = game.bet_lamports;
    if bet > 0 {
        let game_info = ctx.accounts.game.to_account_info();
        let side_a_info = ctx.accounts.side_a.to_account_info();
        **game_info.lamports.borrow_mut() -= bet;
        **side_a_info.lamports.borrow_mut() += bet;
    }

    let game = &mut ctx.accounts.game;
    game.is_active = false;
    Ok(())
}
```

Only side A can cancel, and only before side B joins. This prevents griefing -- side A can always recover their funds if no opponent shows up.

## Instruction summary

| Disc | Instruction | Who | When |
|------|-------------|-----|------|
| 0 | `create_game` | Side A | Start -- deposit bet, commit encrypted value |
| 1 | `play` | Side B | After create -- match bet, commit, XOR executes |
| 2 | `request_result_decryption` | Anyone | After play -- triggers MPC decryption |
| 3 | `reveal_result` | Anyone | After decryption -- pays winner 2x from escrow |
| 4 | `cancel_game` | Side A | Before play -- refund bet |
