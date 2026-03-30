// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Counter — Anchor version.
//!
//! Same FHE counter logic as the Pinocchio example, but uses the Anchor
//! framework and `EncryptContext` for CPI.

use anchor_lang::prelude::*;
use encrypt_anchor::EncryptContext;
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

declare_id!("CntAnchr111111111111111111111111111111111111");

// ── FHE Graphs ──

/// Increment: value + 1
#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

/// Decrement: value - 1
#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}

// ── State ──

#[account]
#[derive(InitSpace)]
pub struct Counter {
    pub authority: Pubkey,
    pub counter_id: [u8; 32],
    pub value: [u8; 32],          // ciphertext account pubkey
    pub pending_digest: [u8; 32],
    pub revealed_value: u64,
    pub bump: u8,
}

// ── Instructions ──

#[program]
pub mod confidential_counter {
    use super::*;

    pub fn create_counter(
        ctx: Context<CreateCounter>,
        counter_id: [u8; 32],
        initial_value_id: [u8; 32],
    ) -> Result<()> {
        let ctr = &mut ctx.accounts.counter;
        ctr.authority = ctx.accounts.authority.key();
        ctr.counter_id = counter_id;
        ctr.value = initial_value_id;
        ctr.pending_digest = [0u8; 32];
        ctr.revealed_value = 0;
        ctr.bump = ctx.bumps.counter;
        Ok(())
    }

    pub fn increment(ctx: Context<Increment>, cpi_authority_bump: u8) -> Result<()> {
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

        let value_ct = ctx.accounts.value_ct.to_account_info();
        encrypt_ctx.increment_graph(value_ct.clone(), value_ct)?;

        Ok(())
    }

    pub fn decrement(ctx: Context<Decrement>, cpi_authority_bump: u8) -> Result<()> {
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

        let value_ct = ctx.accounts.value_ct.to_account_info();
        encrypt_ctx.decrement_graph(value_ct.clone(), value_ct)?;

        Ok(())
    }

    pub fn request_value_decryption(
        ctx: Context<RequestValueDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let ctr = &ctx.accounts.counter;
        require!(
            ctr.authority == ctx.accounts.payer.key(),
            CounterError::Unauthorized
        );

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

        // request_decryption returns the digest — store for reveal verification
        let digest = encrypt_ctx.request_decryption(
            &ctx.accounts.request_acct.to_account_info(),
            &ctx.accounts.ciphertext.to_account_info(),
        )?;

        let ctr = &mut ctx.accounts.counter;
        ctr.pending_digest = digest;

        Ok(())
    }

    pub fn reveal_value(ctx: Context<RevealValue>) -> Result<()> {
        let ctr = &mut ctx.accounts.counter;
        require!(
            ctr.authority == ctx.accounts.authority.key(),
            CounterError::Unauthorized
        );

        // Verify against digest stored at request_decryption time
        let expected_digest = &ctr.pending_digest;

        let req_data = ctx.accounts.request_acct.try_borrow_data()?;
        use encrypt_types::encrypted::Uint64;
        let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
            &req_data,
            expected_digest,
        )
        .map_err(|_| CounterError::DecryptionNotComplete)?;

        ctr.revealed_value = *value;
        Ok(())
    }
}

// ── Accounts ──

#[derive(Accounts)]
#[instruction(counter_id: [u8; 32])]
pub struct CreateCounter<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Counter::INIT_SPACE,
        seeds = [b"counter", counter_id.as_ref()],
        bump,
    )]
    pub counter: Account<'info, Counter>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Value ciphertext account
    #[account(mut)]
    pub value_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Decrement<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Value ciphertext account
    #[account(mut)]
    pub value_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RequestValueDecryption<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Decryption request account
    #[account(mut)]
    pub request_acct: UncheckedAccount<'info>,
    /// CHECK: Ciphertext account
    pub ciphertext: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealValue<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

// ── Errors ──

#[error_code]
pub enum CounterError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Decryption not complete")]
    DecryptionNotComplete,
}

#[cfg(test)]
mod tests {
    use encrypt_dsl::prelude::*;
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::{decrement_graph, increment_graph};

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn();
        let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num);
        let mut inp = 0usize;

        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint64);

            let d = match n.kind() {
                k if k == GraphNodeKind::Input as u8 => {
                    let v = inputs[inp];
                    let t = fhe_types[inp];
                    inp += 1;
                    encode_mock_digest(t, v)
                }
                k if k == GraphNodeKind::Constant as u8 => {
                    let bw = ft.byte_width().min(16);
                    let off = n.const_offset() as usize;
                    let mut buf = [0u8; 16];
                    buf[..bw].copy_from_slice(&pg.constants()[off..off + bw]);
                    encode_mock_digest(ft, u128::from_le_bytes(buf))
                }
                k if k == GraphNodeKind::Op as u8 => {
                    let (a, b, c) = (
                        n.input_a() as usize,
                        n.input_b() as usize,
                        n.input_c() as usize,
                    );
                    if n.op_type() == 60 {
                        mock_select(&digests[a], &digests[b], &digests[c])
                    } else if b == 0xFFFF {
                        mock_unary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            &digests[b],
                            ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| {
                get_node(pg.node_bytes(), i as u16).unwrap().kind()
                    == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn increment_from_zero() {
        let r = run_mock(increment_graph, &[0], &[FheType::EUint64]);
        assert_eq!(r[0], 1, "0 + 1 = 1");
    }

    #[test]
    fn increment_from_ten() {
        let r = run_mock(increment_graph, &[10], &[FheType::EUint64]);
        assert_eq!(r[0], 11, "10 + 1 = 11");
    }

    #[test]
    fn decrement_from_ten() {
        let r = run_mock(decrement_graph, &[10], &[FheType::EUint64]);
        assert_eq!(r[0], 9, "10 - 1 = 9");
    }

    #[test]
    fn graph_shapes() {
        let inc = increment_graph();
        let pg = parse_graph(&inc).unwrap();
        assert_eq!(pg.header().num_inputs(), 1, "increment has 1 input");
        assert_eq!(pg.header().num_outputs(), 1, "increment has 1 output");

        let dec = decrement_graph();
        let pg = parse_graph(&dec).unwrap();
        assert_eq!(pg.header().num_inputs(), 1, "decrement has 1 input");
        assert_eq!(pg.header().num_outputs(), 1, "decrement has 1 output");
    }
}
