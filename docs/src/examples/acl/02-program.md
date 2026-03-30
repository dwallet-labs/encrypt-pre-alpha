# Encrypted ACL: Building the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## 1. Cargo.toml

```toml
[package]
name = "encrypted-acl-anchor"
edition.workspace = true

[dependencies]
encrypt-types = { workspace = true }
encrypt-dsl = { package = "encrypt-solana-dsl", path = "../../../program-sdk/dsl" }
encrypt-anchor = { workspace = true }
anchor-lang = { workspace = true }

[lib]
crate-type = ["cdylib", "lib"]
```

Same three Encrypt crates as the counter example.

## 2. FHE Graphs

Three graphs, all operating on `EUint64` bitmasks:

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

/// Grant: permissions = permissions | permission_bit
#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
}

/// Revoke: permissions = permissions & revoke_mask
#[encrypt_fn]
fn revoke_permission_graph(permissions: EUint64, revoke_mask: EUint64) -> EUint64 {
    permissions & revoke_mask
}

/// Check: result = permissions & permission_bit
#[encrypt_fn]
fn check_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions & permission_bit
}
```

Each `#[encrypt_fn]` generates:
- A function returning the serialized graph bytes (e.g. `grant_permission_graph() -> Vec<u8>`)
- A CPI trait method on `EncryptContext` (e.g. `encrypt_ctx.grant_permission_graph(in1, in2, out)`)

All three graphs have 2 inputs and 1 output. The graph nodes are:
`Input(0)`, `Input(1)`, `Op(BitOr or BitAnd)`, `Output`.

## 3. State Accounts

### Resource

```rust
#[account]
#[derive(InitSpace)]
pub struct Resource {
    pub admin: Pubkey,              // who can grant/revoke
    pub resource_id: [u8; 32],     // unique ID, PDA seed
    pub permissions: [u8; 32],      // ciphertext account pubkey
    pub pending_digest: [u8; 32],  // for permissions decryption
    pub revealed_permissions: u64,  // plaintext after admin decrypts
    pub bump: u8,
}
```

`permissions` stores the pubkey of a ciphertext account holding the encrypted
bitmask. Only the `admin` can grant, revoke, or decrypt.

### AccessCheck

```rust
#[account]
#[derive(InitSpace)]
pub struct AccessCheck {
    pub checker: Pubkey,            // who requested the check
    pub result_ct: [u8; 32],       // ciphertext account pubkey (AND result)
    pub pending_digest: [u8; 32],  // for check decryption
    pub revealed_result: u64,       // nonzero = has permission
    pub bump: u8,
}
```

Created per-check. The PDA is seeded by `["check", resource_id, checker_pubkey]`.
The `result_ct` holds the encrypted AND result. After decryption,
`revealed_result > 0` means the permission is granted.

## 4. Instructions Walkthrough

### create_resource

```rust
pub fn create_resource(
    ctx: Context<CreateResource>,
    resource_id: [u8; 32],
    permissions_ct_id: [u8; 32],
) -> Result<()> {
    let res = &mut ctx.accounts.resource;
    res.admin = ctx.accounts.admin.key();
    res.resource_id = resource_id;
    res.permissions = permissions_ct_id;
    res.pending_digest = [0u8; 32];
    res.revealed_permissions = 0;
    res.bump = ctx.bumps.resource;
    Ok(())
}
```

The caller creates an encrypted zero off-chain and passes its pubkey as
`permissions_ct_id`. The PDA seeds are `["resource", resource_id]`.

### grant_permission

```rust
pub fn grant_permission(
    ctx: Context<GrantPermission>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let res = &ctx.accounts.resource;
    require!(
        res.admin == ctx.accounts.admin.key(),
        AclError::Unauthorized
    );

    let encrypt_ctx = EncryptContext { /* ... */ };

    let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
    let permission_bit_ct = ctx.accounts.permission_bit_ct.to_account_info();
    encrypt_ctx.grant_permission_graph(
        permissions_ct.clone(),  // input: current permissions
        permission_bit_ct,       // input: bit to grant
        permissions_ct,          // output: updated permissions (in-place)
    )?;

    Ok(())
}
```

Admin-only. The `permission_bit_ct` is an encrypted ciphertext containing the
bit value to grant (e.g., encrypted `1` for READ, encrypted `2` for WRITE).
The output overwrites the input -- in-place update via `permissions | bit`.

### revoke_permission

```rust
pub fn revoke_permission(
    ctx: Context<RevokePermission>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let res = &ctx.accounts.resource;
    require!(
        res.admin == ctx.accounts.admin.key(),
        AclError::Unauthorized
    );

    let encrypt_ctx = EncryptContext { /* ... */ };

    let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
    let revoke_mask_ct = ctx.accounts.revoke_mask_ct.to_account_info();
    encrypt_ctx.revoke_permission_graph(
        permissions_ct.clone(),  // input: current permissions
        revoke_mask_ct,          // input: inverse mask
        permissions_ct,          // output: updated permissions (in-place)
    )?;

    Ok(())
}
```

### The Revoke Mask Pattern

To revoke a permission, the caller passes an **inverse mask** -- all bits set
except the one to revoke. For example:

- Revoke READ (bit 0): mask = `0xFFFFFFFFFFFFFFFE`
- Revoke WRITE (bit 1): mask = `0xFFFFFFFFFFFFFFFD`
- Revoke EXECUTE (bit 2): mask = `0xFFFFFFFFFFFFFFFB`

The FHE operation is `permissions & mask`, which clears exactly the target bit
while preserving all others.

Why not use NOT + AND? Because FHE NOT on the permission bit would require an
extra graph node and the caller already knows which bit to revoke. Passing the
inverse mask is simpler and more gas-efficient.

### check_permission

```rust
pub fn check_permission(
    ctx: Context<CheckPermission>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let encrypt_ctx = EncryptContext { /* ... */ };

    let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
    let permission_bit_ct = ctx.accounts.permission_bit_ct.to_account_info();
    let result_ct = ctx.accounts.result_ct.to_account_info();
    encrypt_ctx.check_permission_graph(
        permissions_ct,      // input: current permissions (read-only)
        permission_bit_ct,   // input: bit to check
        result_ct,           // output: AND result (separate account)
    )?;

    let chk = &mut ctx.accounts.access_check;
    chk.checker = ctx.accounts.checker.key();
    chk.result_ct = ctx.accounts.result_ct.key().to_bytes();
    chk.pending_digest = [0u8; 32];
    chk.revealed_result = 0;
    chk.bump = ctx.bumps.access_check;

    Ok(())
}
```

Unlike grant/revoke, check uses a **separate output account** (`result_ct`)
so the permissions bitmask is not modified. Anyone can check -- no admin
requirement.

The `AccessCheck` PDA is created in the same instruction:

```rust
#[derive(Accounts)]
pub struct CheckPermission<'info> {
    pub resource: Account<'info, Resource>,
    #[account(
        init,
        payer = payer,
        space = 8 + AccessCheck::INIT_SPACE,
        seeds = [b"check", resource.resource_id.as_ref(), checker.key().as_ref()],
        bump,
    )]
    pub access_check: Account<'info, AccessCheck>,
    pub checker: Signer<'info>,
    // ... encrypt CPI accounts ...
}
```

### request_check_decryption

```rust
pub fn request_check_decryption(
    ctx: Context<RequestCheckDecryption>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let encrypt_ctx = EncryptContext { /* ... */ };

    let digest = encrypt_ctx.request_decryption(
        &ctx.accounts.request_acct.to_account_info(),
        &ctx.accounts.result_ciphertext.to_account_info(),
    )?;

    let chk = &mut ctx.accounts.access_check;
    chk.pending_digest = digest;

    Ok(())
}
```

Same digest pattern as the counter. The checker requests decryption of the
AND result, stores the digest, then waits for the decryptor.

### reveal_check

```rust
pub fn reveal_check(ctx: Context<RevealCheck>) -> Result<()> {
    let chk = &ctx.accounts.access_check;
    require!(
        chk.checker == ctx.accounts.checker.key(),
        AclError::Unauthorized
    );

    let expected_digest = &chk.pending_digest;
    let req_data = ctx.accounts.request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        expected_digest,
    )
    .map_err(|_| AclError::DecryptionNotComplete)?;

    let chk = &mut ctx.accounts.access_check;
    chk.revealed_result = *value;

    Ok(())
}
```

After reveal, `revealed_result > 0` means the user has the checked permission.
`revealed_result == 0` means they don't.

### request_permissions_decryption / reveal_permissions

Admin-only decryption of the full permissions bitmask. Same pattern as
`request_check_decryption` / `reveal_check`, but writes to
`resource.revealed_permissions`.

```rust
pub fn request_permissions_decryption(
    ctx: Context<RequestPermissionsDecryption>,
    cpi_authority_bump: u8,
) -> Result<()> {
    let encrypt_ctx = EncryptContext { /* ... */ };

    let digest = encrypt_ctx.request_decryption(
        &ctx.accounts.request_acct.to_account_info(),
        &ctx.accounts.permissions_ciphertext.to_account_info(),
    )?;

    let res = &mut ctx.accounts.resource;
    res.pending_digest = digest;
    Ok(())
}

pub fn reveal_permissions(ctx: Context<RevealPermissions>) -> Result<()> {
    let res = &ctx.accounts.resource;
    require!(
        res.admin == ctx.accounts.admin.key(),
        AclError::Unauthorized
    );

    let expected_digest = &res.pending_digest;
    let req_data = ctx.accounts.request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        expected_digest,
    )
    .map_err(|_| AclError::DecryptionNotComplete)?;

    let res = &mut ctx.accounts.resource;
    res.revealed_permissions = *value;
    Ok(())
}
```

## 5. Instruction Summary

| # | Instruction | Who | FHE Op | Modifies permissions? |
|---|------------|-----|--------|----------------------|
| 1 | create_resource | admin | none | initializes |
| 2 | grant_permission | admin | OR | yes (in-place) |
| 3 | revoke_permission | admin | AND | yes (in-place) |
| 4 | check_permission | anyone | AND | no (separate output) |
| 5 | request_check_decryption | checker | none | no |
| 6 | reveal_check | checker | none | no |
| 7 | request_permissions_decryption | admin | none | no |
| 8 | reveal_permissions | admin | none | no |

## 6. Error Codes

```rust
#[error_code]
pub enum AclError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Decryption not complete")]
    DecryptionNotComplete,
}
```
