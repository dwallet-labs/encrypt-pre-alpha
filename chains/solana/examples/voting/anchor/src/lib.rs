// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Voting — Anchor version.
//!
//! Same FHE voting logic as the Pinocchio example, but uses the Anchor
//! framework and `EncryptContext` for CPI.

use anchor_lang::prelude::*;
use encrypt_anchor::EncryptContext;
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::{EBool, EUint64};

declare_id!("VotingAnchor1111111111111111111111111111111");

// ── FHE Graph ──

/// Cast vote: conditionally increment yes or no counter.
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

// ── State ──

#[account]
#[derive(InitSpace)]
pub struct Proposal {
    pub authority: Pubkey,
    pub proposal_id: [u8; 32],
    pub yes_count: [u8; 32],           // ciphertext account pubkey
    pub no_count: [u8; 32],            // ciphertext account pubkey
    pub is_open: bool,
    pub total_votes: u64,
    pub revealed_yes: u64,
    pub revealed_no: u64,
    pub pending_yes_digest: [u8; 32],  // stored at request_decryption time
    pub pending_no_digest: [u8; 32],   // stored at request_decryption time
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct VoteRecord {
    pub voter: Pubkey,
    pub bump: u8,
}

// ── Instructions ──

#[program]
pub mod confidential_voting {
    use super::*;

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

        // Remaining accounts: inputs [yes_ct, no_ct, vote_ct] + outputs [yes_ct, no_ct] (update mode)
        let yes_ct = ctx.accounts.yes_ct.to_account_info();
        let no_ct = ctx.accounts.no_ct.to_account_info();
        let vote_ct = ctx.accounts.vote_ct.to_account_info();
        encrypt_ctx.cast_vote_graph(
            yes_ct.clone(), no_ct.clone(), vote_ct,
            yes_ct, no_ct,
        )?;

        // Increment total votes — yes/no ciphertext accounts unchanged
        let prop = &mut ctx.accounts.proposal;
        prop.total_votes += 1;

        // Vote record created by Anchor init — prevents double voting
        let vr = &mut ctx.accounts.vote_record;
        vr.voter = ctx.accounts.voter.key();
        vr.bump = ctx.bumps.vote_record;

        Ok(())
    }

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

    /// Authority requests decryption of yes or no tally after closing.
    pub fn request_tally_decryption(
        ctx: Context<RequestTallyDecryption>,
        is_yes: bool,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let prop = &ctx.accounts.proposal;
        require!(!prop.is_open, VotingError::ProposalStillOpen);

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

        // request_decryption returns the digest — store it for reveal verification
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

    /// Authority reads completed decryption and writes plaintext to proposal.
    pub fn reveal_tally(ctx: Context<RevealTally>, is_yes: bool) -> Result<()> {
        let prop = &mut ctx.accounts.proposal;
        require!(
            prop.authority == ctx.accounts.authority.key(),
            VotingError::Unauthorized
        );
        require!(!prop.is_open, VotingError::ProposalStillOpen);

        // Verify against digest stored at request_decryption time
        let expected_digest = if is_yes {
            &prop.pending_yes_digest
        } else {
            &prop.pending_no_digest
        };

        let req_data = ctx.accounts.request_acct.try_borrow_data()?;
        use encrypt_types::encrypted::Uint64;
        let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(&req_data, expected_digest)
            .map_err(|_| VotingError::DecryptionNotComplete)?;

        if is_yes {
            prop.revealed_yes = *value;
        } else {
            prop.revealed_no = *value;
        }
        Ok(())
    }
}

// ── Accounts ──

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

#[derive(Accounts)]
pub struct CastVote<'info> {
    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
    #[account(
        init,
        payer = payer,
        space = 8 + VoteRecord::INIT_SPACE,
        seeds = [b"vote", proposal.proposal_id.as_ref(), voter.key().as_ref()],
        bump,
    )]
    pub vote_record: Account<'info, VoteRecord>,
    pub voter: Signer<'info>,
    /// CHECK: Vote ciphertext account
    #[account(mut)]
    pub vote_ct: UncheckedAccount<'info>,
    /// CHECK: Yes count ciphertext account
    #[account(mut)]
    pub yes_ct: UncheckedAccount<'info>,
    /// CHECK: No count ciphertext account
    #[account(mut)]
    pub no_ct: UncheckedAccount<'info>,
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
pub struct CloseProposal<'info> {
    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RequestTallyDecryption<'info> {
    pub proposal: Account<'info, Proposal>,
    /// CHECK: Decryption request PDA (created by encrypt program)
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
pub struct RevealTally<'info> {
    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

// ── Errors ──

#[error_code]
pub enum VotingError {
    #[msg("Proposal is closed")]
    ProposalClosed,
    #[msg("Proposal is still open")]
    ProposalStillOpen,
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

    use super::cast_vote_graph;

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
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], &digests[b], ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8)
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn vote_yes_increments_yes_count() {
        let r = run_mock(cast_vote_graph, &[10, 5, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 11);
        assert_eq!(r[1], 5);
    }

    #[test]
    fn vote_no_increments_no_count() {
        let r = run_mock(cast_vote_graph, &[10, 5, 0],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 10);
        assert_eq!(r[1], 6);
    }

    #[test]
    fn vote_from_zero() {
        let r = run_mock(cast_vote_graph, &[0, 0, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 1);
        assert_eq!(r[1], 0);
    }

    #[test]
    fn graph_shape() {
        let d = cast_vote_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 3);
        assert_eq!(pg.header().num_outputs(), 2);
    }
}
