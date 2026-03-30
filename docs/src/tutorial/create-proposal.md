# Create Proposal

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


The `create_proposal` instruction creates the proposal PDA and initializes two ciphertext accounts to encrypted zero.

## Instruction Layout

```
discriminator: 0
data: proposal_bump(1) | cpi_authority_bump(1) | proposal_id(32)
accounts: [proposal_pda(w), authority(s),
           yes_ct(w), no_ct(w),
           encrypt_program, config, deposit(w), cpi_authority,
           caller_program, network_encryption_key, payer(s,w),
           event_authority, system_program]
```

## Implementation

### Create the Proposal PDA

```rust
fn create_proposal(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [proposal_acct, authority, yes_ct, no_ct, encrypt_program, config,
         deposit, cpi_authority, caller_program, network_encryption_key,
         payer, event_authority, system_program, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let proposal_bump = data[0];
    let cpi_authority_bump = data[1];
    let proposal_id: [u8; 32] = data[2..34].try_into().unwrap();

    // Create proposal PDA
    let bump_byte = [proposal_bump];
    let seeds = [
        Seed::from(b"proposal" as &[u8]),
        Seed::from(proposal_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: proposal_acct,
        lamports: minimum_balance(Proposal::LEN),
        space: Proposal::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;
```

### Create Encrypted Zeros

This is where Encrypt comes in. Create two ciphertext accounts initialized to encrypted zero using `create_plaintext_typed`:

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

    ctx.create_plaintext_typed::<Uint64>(&0u64, yes_ct)?;
    ctx.create_plaintext_typed::<Uint64>(&0u64, no_ct)?;
```

`create_plaintext_typed::<Uint64>` is a type-safe helper that:
1. Serializes the value (`0u64`) as little-endian bytes
2. Calls `create_plaintext_ciphertext` with `fhe_type = EUint64`
3. Creates a Ciphertext account with `status = PENDING` and `authorized` set to the calling program

The executor detects the `CiphertextCreated` event, encrypts the plaintext value off-chain, and calls `commit_ciphertext` to write the digest and set `status = VERIFIED`.

### Write Proposal State

```rust
    let d = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop = Proposal::from_bytes_mut(d)?;
    prop.discriminator = PROPOSAL;
    prop.authority.copy_from_slice(authority.address().as_ref());
    prop.proposal_id.copy_from_slice(&proposal_id);
    prop.yes_count = EUint64::from_le_bytes(*yes_ct.address().as_array());
    prop.no_count = EUint64::from_le_bytes(*no_ct.address().as_array());
    prop.is_open = 1;
    prop.set_total_votes(0);
    prop.bump = proposal_bump;
    Ok(())
}
```

The ciphertext account pubkeys are stored in the proposal so that later instructions can verify the correct accounts are passed.

## EncryptContext Fields

Every CPI to the Encrypt program requires an `EncryptContext`. Here is what each field is:

| Field | Description |
|-------|-------------|
| `encrypt_program` | The Encrypt program account |
| `config` | EncryptConfig PDA (fee schedule, epoch) |
| `deposit` | EncryptDeposit PDA for fee payment |
| `cpi_authority` | PDA derived from `["__encrypt_cpi_authority", caller_program_id]` |
| `caller_program` | Your program's account (the executable that invokes CPI) |
| `network_encryption_key` | NetworkEncryptionKey PDA (the FHE public key) |
| `payer` | Signer who pays for new account rent |
| `event_authority` | Encrypt program's event authority PDA |
| `system_program` | System program |
| `cpi_authority_bump` | PDA bump for the CPI authority |

## Next Step

With the proposal and encrypted tallies created, the next chapter implements vote casting.
