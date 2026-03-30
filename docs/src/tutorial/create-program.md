# Create the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


## Cargo.toml

Create a new Solana program crate with Encrypt dependencies:

```toml
[package]
name = "confidential-voting-pinocchio"
version = "0.1.0"
edition = "2024"

[dependencies]
encrypt-types = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-dsl = { package = "encrypt-solana-dsl", git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
encrypt-pinocchio = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }
pinocchio = "0.10"
pinocchio-system = "0.5"

[dev-dependencies]
encrypt-solana-test = { git = "https://github.com/dwallet-labs/encrypt-pre-alpha" }

[lib]
crate-type = ["cdylib", "lib"]
```

Key crates:
- **`encrypt-dsl`** (actually `encrypt-solana-dsl`) -- the `#[encrypt_fn]` macro that generates both the computation graph and the CPI extension trait
- **`encrypt-pinocchio`** -- `EncryptContext` and account helpers for Pinocchio programs
- **`encrypt-types`** -- FHE types (`EUint64`, `EBool`, `Uint64`) and graph utilities

## lib.rs Skeleton

```rust
#![allow(unexpected_cfgs)]

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::accounts::{self, DecryptionRequestStatus};
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EBool, EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([3u8; 32]);
```

## Account Discriminators

Define discriminators for your program's account types:

```rust
const PROPOSAL: u8 = 1;
const VOTE_RECORD: u8 = 2;
```

## Proposal Account

The proposal stores the authority, proposal ID, references to the encrypted tally ciphertexts, voting status, and fields for decryption verification:

```rust
#[repr(C)]
pub struct Proposal {
    pub discriminator: u8,
    pub authority: [u8; 32],
    pub proposal_id: [u8; 32],
    pub yes_count: EUint64,              // ciphertext account pubkey
    pub no_count: EUint64,               // ciphertext account pubkey
    pub is_open: u8,
    pub total_votes: [u8; 8],            // plaintext total for transparency
    pub revealed_yes: [u8; 8],           // written after decryption
    pub revealed_no: [u8; 8],            // written after decryption
    pub pending_yes_digest: [u8; 32],    // stored at request_decryption time
    pub pending_no_digest: [u8; 32],     // stored at request_decryption time
    pub bump: u8,
}
```

The `yes_count` and `no_count` fields store the **pubkeys** of the ciphertext accounts. Since `EUint64` is a 32-byte type alias, this works naturally -- the ciphertext account's Solana pubkey IS the ciphertext identifier.

The `pending_*_digest` fields are critical for the [store-and-verify pattern](../on-chain/decryption.md). When requesting decryption, `request_decryption` returns the current `ciphertext_digest`. You store it here and verify it at reveal time to ensure the ciphertext was not modified between request and response.

```rust
impl Proposal {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != PROPOSAL {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    pub fn total_votes(&self) -> u64 {
        u64::from_le_bytes(self.total_votes)
    }

    pub fn set_total_votes(&mut self, val: u64) {
        self.total_votes = val.to_le_bytes();
    }
}
```

## VoteRecord Account

The vote record is a PDA seeded by `["vote", proposal_id, voter]`. Its existence proves the voter already voted. It contains no vote data -- the vote is only in the encrypted tally.

```rust
#[repr(C)]
pub struct VoteRecord {
    pub discriminator: u8,
    pub voter: [u8; 32],
    pub bump: u8,
}

impl VoteRecord {
    pub const LEN: usize = core::mem::size_of::<Self>();
}
```

## Instruction Dispatch

```rust
fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_proposal(program_id, accounts, rest),
        Some((&1, rest)) => cast_vote(program_id, accounts, rest),
        Some((&2, _rest)) => close_proposal(accounts),
        Some((&3, rest)) => request_tally_decryption(accounts, rest),
        Some((&4, rest)) => reveal_tally(accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
```

## Next Step

With the program skeleton in place, the next chapter writes the FHE computation logic.
