# On-Chain Escrow Deep Dive

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

How SOL flows through the coin flip game.

## What you'll learn

- How the game PDA acts as a trustless escrow
- System transfer CPI for deposits vs direct lamport manipulation for payouts
- Cancel refund logic
- Why this design is secure

## SOL flow

```
Side A wallet ──(system transfer)──> Game PDA ──(lamport manipulation)──> Winner wallet
Side B wallet ──(system transfer)──> Game PDA
```

1. **Side A deposits** during `create_game` via system program transfer CPI:

```rust
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
```

2. **Side B matches** during `play` with the same pattern:

```rust
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
```

3. **Winner withdraws** during `reveal_result` via direct lamport manipulation:

```rust
let payout = game.bet_lamports * 2;
if payout > 0 {
    let game_info = ctx.accounts.game.to_account_info();
    let winner_info = ctx.accounts.winner.to_account_info();
    **game_info.lamports.borrow_mut() -= payout;
    **winner_info.lamports.borrow_mut() += payout;
}
```

## Why two different transfer methods

**Deposits use system program CPI** because the source is a user wallet (system-owned account). Only the system program can debit a system-owned account.

**Payouts use direct lamport manipulation** because the game PDA is owned by our program. The Solana runtime allows a program to freely debit accounts it owns. This is cheaper (no CPI overhead) and simpler.

## Cancel refund

Side A can cancel before side B joins:

```rust
pub fn cancel_game(ctx: Context<CancelGame>) -> Result<()> {
    let game = &ctx.accounts.game;
    require!(game.is_active, CoinFlipError::GameClosed);
    require!(!game.played, CoinFlipError::AlreadyPlayed);
    require!(ctx.accounts.side_a.key() == game.side_a, CoinFlipError::Unauthorized);

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

Guards:
- `is_active` -- can't cancel an already-finished game
- `!played` -- can't cancel after side B committed (funds are locked for the outcome)
- `side_a == signer` -- only the creator can cancel

## Security properties

**Neither side can cheat.** Both values are encrypted before the other side commits. The XOR graph is deterministic and computed by the executor under FHE -- there's no way to influence the result after committing.

**Funds cannot be stolen.** The game PDA is program-owned. Only the program's instructions can debit it. `reveal_result` requires a valid decrypted value matching the stored digest. The `winner` account is validated against the game state.

**No griefing.** Side A can cancel and recover funds if no opponent joins. Once both sides play, the game must resolve -- anyone can call `request_result_decryption` and `reveal_result`.

**No double-payout.** `revealed_result` is checked to be 0 (unknown) before reveal. After payout, it's set to 1 or 2, preventing replay.
