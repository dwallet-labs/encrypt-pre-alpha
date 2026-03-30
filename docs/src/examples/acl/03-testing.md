# Encrypted ACL: Testing

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## 1. Unit Tests (Graph Logic)

Verify the FHE graphs produce correct bitwise results using a mock evaluator.
No SBF build needed.

```bash
cargo test -p encrypted-acl-anchor --lib
```

```rust
#[test]
fn grant_single_permission() {
    let r = run_mock(
        grant_permission_graph,
        &[0, 1],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 1, "granting READ (bit 0) to 0 should yield 1");
}

#[test]
fn grant_multiple_permissions() {
    let r = run_mock(
        grant_permission_graph,
        &[1, 2],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 3, "granting WRITE (bit 1) to READ (1) should yield 3");
}

#[test]
fn revoke_permission() {
    let r = run_mock(
        revoke_permission_graph,
        &[3, 0xFFFFFFFFFFFFFFFE],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 2, "revoking READ (bit 0) from 3 should yield 2");
}

#[test]
fn check_has_permission() {
    let r = run_mock(
        check_permission_graph,
        &[5, 1],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 1, "checking READ on 5 (READ|EXECUTE) should yield 1");
}

#[test]
fn check_missing_permission() {
    let r = run_mock(
        check_permission_graph,
        &[4, 1],
        &[FheType::EUint64, FheType::EUint64],
    );
    assert_eq!(r[0], 0, "checking READ on 4 (EXECUTE only) should yield 0");
}

#[test]
fn graph_shapes() {
    let d = grant_permission_graph();
    let pg = parse_graph(&d).unwrap();
    assert_eq!(pg.header().num_inputs(), 2);
    assert_eq!(pg.header().num_outputs(), 1);
    // Same shape for revoke and check
}
```

## 2. LiteSVM Integration Tests (E2E)

Full lifecycle tests using LiteSVM with `EncryptTestContext`. Tests the
complete flow: create resource, grant, revoke, check, and decrypt.

```bash
just build-sbf-examples
cargo test -p encrypted-acl-anchor --test litesvm
```

The test helpers abstract common patterns:

```rust
// Create a resource with encrypted-zero permissions
fn create_resource(ctx, program_id, admin) -> (resource_pda, permissions_ct, resource_id)

// Grant a permission: create encrypted bit, CPI, evaluate graph
fn do_grant(ctx, program_id, ..., permission_value: u128)

// Revoke a permission: create encrypted mask, CPI, evaluate graph
fn do_revoke(ctx, program_id, ..., revoke_mask: u128)

// Check a permission: create encrypted bit + result, CPI, evaluate, decrypt
fn do_check(ctx, program_id, ..., permission_value: u128) -> u128
```

Full lifecycle test:

```rust
#[test]
fn test_full_acl_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    // 1. Create resource
    let (resource_pda, perm_ct, resource_id) =
        create_resource(&mut ctx, &program_id, &admin);

    // 2. Grant READ (bit 0 = 1)
    do_grant(&mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 1);

    // 3. Grant WRITE (bit 1 = 2)
    do_grant(&mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 2);

    // 4. Check READ -- should pass
    let checker1 = ctx.new_funded_keypair();
    let result = do_check(&mut ctx, &program_id, &cpi_authority, cpi_bump,
        &checker1, &resource_pda, &perm_ct, &resource_id, 1);
    assert_eq!(result, 1, "should have READ after granting");

    // 5. Revoke READ (mask = 0xFFFFFFFFFFFFFFFE)
    do_revoke(&mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 0xFFFFFFFFFFFFFFFE);

    // 6. Check READ -- should fail
    let checker2 = ctx.new_funded_keypair();
    let result = do_check(&mut ctx, &program_id, &cpi_authority, cpi_bump,
        &checker2, &resource_pda, &perm_ct, &resource_id, 1);
    assert_eq!(result, 0, "should NOT have READ after revoking");

    // 7. Decrypt permissions to verify = 2 (WRITE only)
    let perm_value = ctx.decrypt_from_store(&perm_ct);
    assert_eq!(perm_value, 2, "permissions should be 2 (WRITE only)");
}
```

## 3. Mollusk Instruction-Level Tests

Mollusk tests `reveal_check` and `reveal_permissions` in isolation. No CPI or
Encrypt program needed -- just raw account data and instruction processing.

```bash
just build-sbf-examples
cargo test -p encrypted-acl-anchor --test mollusk
```

Tests cover:
- `reveal_check` succeeds with matching digest
- `reveal_check` rejects wrong checker
- `reveal_check` rejects digest mismatch
- `reveal_permissions` succeeds with matching digest
- `reveal_permissions` rejects wrong admin

```rust
#[test]
fn test_reveal_check_success() {
    let (mollusk, pid) = setup();
    let checker = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let check_data = build_anchor_access_check(&checker, &Pubkey::new_unique(), &digest, 0);
    let request_data = build_decryption_request_data(&digest, 1);

    let result = mollusk.process_instruction(/* ... */);
    assert!(result.program_result.is_ok());
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[104..112].try_into().unwrap(),
    );
    assert_eq!(revealed, 1);
}

#[test]
fn test_reveal_permissions_success() {
    // Same pattern, checks resource.revealed_permissions at offset 136..144
}
```

## 4. Running All Tests

```bash
# Everything (build + all test types)
just test-examples

# Just LiteSVM e2e
just test-examples-litesvm

# Just Mollusk
just test-examples-mollusk

# Just program-test
just test-examples-program-test

# Single crate, all tests
cargo test -p encrypted-acl-anchor
```
