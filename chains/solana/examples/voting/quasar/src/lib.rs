// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Voting (Quasar version).
//!
//! On-chain voting where individual votes are encrypted. Nobody can see
//! how anyone voted, but the final tally is computed via FHE and can be
//! decrypted by the proposal authority.
//!
//! This is the Quasar equivalent of the Pinocchio `confidential-voting` program.

#![cfg_attr(not(test), no_std)]
#![allow(unexpected_cfgs)]

extern crate alloc;
use alloc::vec::Vec;



use encrypt_dsl::prelude::encrypt_fn;
use encrypt_quasar::accounts;
use encrypt_quasar::EncryptContext;
use encrypt_types::encrypted::{EBool, EUint64, Uint64};
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("99999999999999999999999999999998999999999999");

// ── FHE Graphs ──

/// Cast vote: conditionally increment yes or no counter.
///
/// If vote is true: yes += 1, no unchanged.
/// If vote is false: no += 1, yes unchanged.
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

// ── Program ──

#[program]
mod confidential_voting_quasar {
    use super::*;

    /// Create a new proposal with zeroed encrypted tallies.
    #[instruction(discriminator = 0)]
    pub fn create_proposal(
        ctx: Ctx<CreateProposal>,
        proposal_id: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(proposal_id, cpi_authority_bump)
    }

    /// Cast an encrypted vote on the proposal.
    #[instruction(discriminator = 1)]
    pub fn cast_vote(
        ctx: Ctx<CastVote>,
        proposal_id: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(proposal_id, cpi_authority_bump)
    }

    /// Close the proposal (authority only).
    #[instruction(discriminator = 2)]
    pub fn close_proposal(ctx: Ctx<CloseProposal>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }

    /// Request decryption of yes or no tally.
    #[instruction(discriminator = 3)]
    pub fn request_tally_decryption(
        ctx: Ctx<RequestTallyDecryption>,
        cpi_authority_bump: u8,
        is_yes: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump, is_yes)
    }

    /// Reveal the decrypted tally on-chain.
    #[instruction(discriminator = 4)]
    pub fn reveal_tally(
        ctx: Ctx<RevealTally>,
        is_yes: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(is_yes)
    }
}

// ── State ──

#[account(discriminator = 1, set_inner)]
#[seeds(b"proposal", proposal_id: Address)]
pub struct Proposal {
    pub authority: Address,
    pub proposal_id: Address,
    pub yes_count: [u8; 32],
    pub no_count: [u8; 32],
    pub is_open: u8,
    pub total_votes: u32,
    pub revealed_yes: [u8; 8],
    pub revealed_no: [u8; 8],
    pub pending_yes_digest: [u8; 32],
    pub pending_no_digest: [u8; 32],
    pub bump: u8,
}

#[account(discriminator = 2, set_inner)]
#[seeds(b"vote", proposal_id: Address, voter: Address)]
pub struct VoteRecord {
    pub voter: Address,
    pub bump: u8,
}

// ── Errors ──

#[error_code]
pub enum VotingError {
    ProposalClosed = 6000,
    ProposalOpen,
    NotAuthority,
    ArithmeticOverflow,
}

// ── Accounts: create_proposal ──

#[derive(Accounts)]
#[instruction(proposal_id: Address)]
pub struct CreateProposal {
    #[account(init, payer = payer, seeds = Proposal::seeds(proposal_id), bump)]
    pub proposal: Account<Proposal>,

    pub authority: Signer,

    /// Ciphertext for yes_count.
    #[account(mut)]
    pub yes_ct: UncheckedAccount,

    /// Ciphertext for no_count.
    #[account(mut)]
    pub no_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl CreateProposal {
    pub fn handler(&mut self, proposal_id: Address, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.create_plaintext_typed::<Uint64>(&0u64, self.yes_ct.to_account_view())?;
        ctx.create_plaintext_typed::<Uint64>(&0u64, self.no_ct.to_account_view())?;

        self.proposal.set_inner(ProposalInner {
            authority: *self.authority.address(),
            proposal_id,
            yes_count: *self.yes_ct.address().as_array(),
            no_count: *self.no_ct.address().as_array(),
            is_open: 1,
            total_votes: 0,
            revealed_yes: [0u8; 8],
            revealed_no: [0u8; 8],
            pending_yes_digest: [0u8; 32],
            pending_no_digest: [0u8; 32],
            bump: 0,
        });
        Ok(())
    }
}

// ── Accounts: cast_vote ──

#[derive(Accounts)]
#[instruction(proposal_id: Address)]
pub struct CastVote {
    #[account(mut, seeds = Proposal::seeds(proposal_id), bump)]
    pub proposal: Account<Proposal>,

    #[account(init, payer = payer, seeds = VoteRecord::seeds(proposal_id, voter), bump)]
    pub vote_record: Account<VoteRecord>,

    pub voter: Signer,

    /// Encrypted vote ciphertext (EBool).
    pub vote_ct: UncheckedAccount,

    /// Ciphertext for yes_count.
    #[account(mut)]
    pub yes_ct: UncheckedAccount,

    /// Ciphertext for no_count.
    #[account(mut)]
    pub no_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl CastVote {
    pub fn handler(&mut self, _proposal_id: Address, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(self.proposal.is_open == 1, VotingError::ProposalClosed);

        self.vote_record.set_inner(VoteRecordInner {
            voter: *self.voter.address(),
            bump: 0,
        });

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.cast_vote_graph(
            self.yes_ct.to_account_view(),
            self.no_ct.to_account_view(),
            self.vote_ct.to_account_view(),
            self.yes_ct.to_account_view(),
            self.no_ct.to_account_view(),
        )?;

        self.proposal.total_votes = self
            .proposal
            .total_votes
            .checked_add(1u32)
            .ok_or(VotingError::ArithmeticOverflow)?
            .into();

        Ok(())
    }
}

// ── Accounts: close_proposal ──

#[derive(Accounts)]
pub struct CloseProposal {
    #[account(mut)]
    pub proposal: Account<Proposal>,

    pub authority: Signer,
}

impl CloseProposal {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(
            self.authority.address() == &self.proposal.authority,
            VotingError::NotAuthority
        );
        require!(self.proposal.is_open == 1, VotingError::ProposalClosed);

        self.proposal.is_open = 0;
        Ok(())
    }
}

// ── Accounts: request_tally_decryption ──

#[derive(Accounts)]
pub struct RequestTallyDecryption {
    #[account(mut)]
    pub proposal: Account<Proposal>,

    /// Decryption request account (created by CPI).
    #[account(mut)]
    pub request_acct: UncheckedAccount,

    /// Ciphertext to decrypt (yes_ct or no_ct).
    pub ciphertext: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl RequestTallyDecryption {
    pub fn handler(&mut self, cpi_authority_bump: u8, is_yes: u8) -> Result<(), ProgramError> {
        require!(self.proposal.is_open == 0, VotingError::ProposalOpen);

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        let digest = ctx.request_decryption(
            self.request_acct.to_account_view(),
            self.ciphertext.to_account_view(),
        )?;

        if is_yes != 0 {
            self.proposal.pending_yes_digest = digest;
        } else {
            self.proposal.pending_no_digest = digest;
        }
        Ok(())
    }
}

// ── Accounts: reveal_tally ──

#[derive(Accounts)]
pub struct RevealTally {
    #[account(mut)]
    pub proposal: Account<Proposal>,

    /// Completed decryption request.
    pub request_acct: UncheckedAccount,

    pub authority: Signer,
}

impl RevealTally {
    pub fn handler(&mut self, is_yes: u8) -> Result<(), ProgramError> {
        require!(
            self.authority.address() == &self.proposal.authority,
            VotingError::NotAuthority
        );
        require!(self.proposal.is_open == 0, VotingError::ProposalOpen);

        let expected_digest = if is_yes != 0 {
            &self.proposal.pending_yes_digest
        } else {
            &self.proposal.pending_no_digest
        };

        let req_data = unsafe {
            core::slice::from_raw_parts(
                self.request_acct.to_account_view().data_ptr(),
                256,
            )
        };
        let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, expected_digest)?;

        if is_yes != 0 {
            self.proposal.revealed_yes = value.to_le_bytes();
        } else {
            self.proposal.revealed_no = value.to_le_bytes();
        }
        Ok(())
    }
}
