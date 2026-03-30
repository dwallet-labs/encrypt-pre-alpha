// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Voting E2E Demo — Rust
//!
//! Same flow as the TypeScript demos. Uses gRPC to submit encrypted inputs
//! to the executor, and Solana RPC for all on-chain transactions.

use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, thread};

use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

use encrypt_solana_client::grpc::EncryptClient;
use encrypt_types::encrypted::Bool;

// ── ANSI colors ──

const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";

fn log(step: &str, msg: &str) {
    println!("{CYAN}[{step}]{RESET} {msg}");
}
fn ok(msg: &str) {
    println!("{GREEN}  \u{2713}{RESET} {msg}");
}
fn val(label: &str, v: impl std::fmt::Display) {
    println!("{YELLOW}  \u{2192}{RESET} {label}: {v}");
}

// ── Helpers ──

fn pda(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, program_id)
}

fn send_tx(
    client: &RpcClient,
    payer: &Keypair,
    ixs: Vec<Instruction>,
    extra_signers: &[&Keypair],
) {
    let blockhash = client.get_latest_blockhash().expect("get blockhash");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &signers, blockhash);
    let b = bincode::serialize(&tx).unwrap();
    let v: solana_transaction::versioned::VersionedTransaction =
        bincode::deserialize(&b).unwrap();

    client
        .send_and_confirm_transaction(&v)
        .expect("send and confirm");
}

fn poll_until(
    client: &RpcClient,
    account: &Pubkey,
    check: impl Fn(&[u8]) -> bool,
    timeout: Duration,
    interval: Duration,
) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("timeout waiting for {account}");
        }
        if let Ok(acct) = client.get_account(account) {
            if check(&acct.data) {
                return acct.data;
            }
        }
        thread::sleep(interval);
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: e2e-voting <ENCRYPT_PROGRAM_ID> <VOTING_PROGRAM_ID>");
        std::process::exit(1);
    }

    let encrypt_program = Pubkey::from_str(&args[1]).expect("invalid encrypt program id");
    let voting_program = Pubkey::from_str(&args[2]).expect("invalid voting program id");

    let client = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );

    println!("\n{BOLD}\u{2550}\u{2550}\u{2550} Confidential Voting E2E \u{2014} Rust \u{2550}\u{2550}\u{2550}{RESET}\n");

    // Connect to pre-alpha devnet executor gRPC
    let mut encrypt = EncryptClient::connect().await?;
    log("Setup", &format!("Connected to executor gRPC at {}", encrypt_solana_client::grpc::GRPC_URL));

    // Generate and fund payer
    let payer = Keypair::new();
    log("Setup", "Funding payer...");
    let sig = client
        .request_airdrop(&payer.pubkey(), 100_000_000_000)
        .expect("airdrop");
    for _ in 0..60 {
        if let Ok(true) = client.confirm_transaction(&sig) {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    ok(&format!("Payer: {}", payer.pubkey()));

    // Derive encrypt PDAs
    let (config_pda, _) = pda(&[b"encrypt_config"], &encrypt_program);
    let (event_authority, _) = pda(&[b"__event_authority"], &encrypt_program);
    let (deposit_pda, deposit_bump) = pda(
        &[b"encrypt_deposit", payer.pubkey().as_ref()],
        &encrypt_program,
    );
    let network_key = [0x55u8; 32];
    let (network_key_pda, _) = pda(
        &[b"network_encryption_key", &network_key],
        &encrypt_program,
    );

    // Read enc_vault from config
    let config_info = client
        .get_account(&config_pda)
        .expect("Config not initialized. Is the executor running?");
    let enc_vault =
        Pubkey::try_from(&config_info.data[100..132]).unwrap_or(Pubkey::new_from_array([0u8; 32]));
    let vault_is_payer =
        enc_vault == Pubkey::new_from_array([0u8; 32]) || enc_vault == Pubkey::default();
    let vault_pk = if vault_is_payer {
        payer.pubkey()
    } else {
        enc_vault
    };

    // Create deposit
    log("Setup", "Creating deposit...");
    let mut deposit_data = vec![0u8; 18];
    deposit_data[0] = 14;
    deposit_data[1] = deposit_bump;

    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: encrypt_program,
            data: deposit_data,
            accounts: vec![
                AccountMeta::new(deposit_pda, false),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(vault_pk, vault_is_payer),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
            ],
        }],
        &[],
    );
    ok("Deposit created");

    // Derive voting PDAs
    let proposal_id = Keypair::new().pubkey().to_bytes();
    let (proposal_pda, proposal_bump) =
        pda(&[b"proposal", &proposal_id], &voting_program);
    let (cpi_authority, cpi_bump) =
        pda(&[b"__encrypt_cpi_authority"], &voting_program);

    // ── 1. Create Proposal ──
    log("1/6", "Creating proposal...");
    let yes_ct = Keypair::new();
    let no_ct = Keypair::new();

    let mut create_proposal_data = vec![0u8, proposal_bump, cpi_bump];
    create_proposal_data.extend_from_slice(&proposal_id);

    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: create_proposal_data,
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(yes_ct.pubkey(), true),
                AccountMeta::new(no_ct.pubkey(), true),
                AccountMeta::new_readonly(encrypt_program, false),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new(deposit_pda, false),
                AccountMeta::new_readonly(cpi_authority, false),
                AccountMeta::new_readonly(voting_program, false),
                AccountMeta::new_readonly(network_key_pda, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
            ],
        }],
        &[&yes_ct, &no_ct],
    );
    ok(&format!("Proposal: {proposal_pda}"));
    ok(&format!("Yes CT:   {}", yes_ct.pubkey()));
    ok(&format!("No CT:    {}", no_ct.pubkey()));

    // ── 2. Cast Votes ──
    let votes = [
        ("Alice", 1u8),
        ("Bob", 1),
        ("Charlie", 1),
        ("Dave", 0),
        ("Eve", 0),
    ];

    for (name, vote) in &votes {
        let label = if *vote == 1 {
            "YES \u{270b}"
        } else {
            "NO  \u{270b}"
        };
        log("2/6", &format!("{name} votes {label}..."));

        let voter = Keypair::new();
        let airdrop_sig = client
            .request_airdrop(&voter.pubkey(), 1_000_000_000)
            .expect("airdrop voter");
        client
            .confirm_transaction(&airdrop_sig)
            .expect("confirm voter airdrop");

        // Submit encrypted vote via gRPC → executor creates ciphertext on-chain
        let vote_ct = encrypt
            .create_input::<Bool>(
                *vote != 0,
                &voting_program,
                &network_key,
            )
            .await
            .expect("create_input via gRPC");
        ok(&format!("Vote CT: {vote_ct} (via gRPC)"));

        // Cast vote on voting program
        let (vote_record, vr_bump) = pda(
            &[b"vote", &proposal_id, voter.pubkey().as_ref()],
            &voting_program,
        );

        send_tx(
            &client,
            &payer,
            vec![Instruction {
                program_id: voting_program,
                data: vec![1, vr_bump, cpi_bump],
                accounts: vec![
                    AccountMeta::new(proposal_pda, false),
                    AccountMeta::new(vote_record, false),
                    AccountMeta::new_readonly(voter.pubkey(), true),
                    AccountMeta::new(vote_ct, false),
                    AccountMeta::new(yes_ct.pubkey(), false),
                    AccountMeta::new(no_ct.pubkey(), false),
                    AccountMeta::new_readonly(encrypt_program, false),
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new(deposit_pda, false),
                    AccountMeta::new_readonly(cpi_authority, false),
                    AccountMeta::new_readonly(voting_program, false),
                    AccountMeta::new_readonly(network_key_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(event_authority, false),
                    AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
                ],
            }],
            &[&voter],
        );

        let result = if *vote == 1 { "YES" } else { "NO" };
        ok(&format!("{name} voted {result}"));

        log("2/6", "  Waiting for executor to commit results...");
        poll_until(
            &client,
            &yes_ct.pubkey(),
            |d| d.len() >= 100 && d[99] == 1,
            Duration::from_secs(60),
            Duration::from_secs(1),
        );
        ok("Graph outputs committed by executor");
    }

    // ── 3. Close Proposal ──
    log("3/6", "Closing proposal...");
    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: vec![2],
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        }],
        &[],
    );
    ok("Proposal closed \u{2014} no more votes accepted");

    // ── 4. Request Decryption ──
    log("4/6", "Requesting decryption of tallies...");

    let yes_req = Keypair::new();
    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: vec![3, cpi_bump, 1],
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new(yes_req.pubkey(), true),
                AccountMeta::new_readonly(yes_ct.pubkey(), false),
                AccountMeta::new_readonly(encrypt_program, false),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new(deposit_pda, false),
                AccountMeta::new_readonly(cpi_authority, false),
                AccountMeta::new_readonly(voting_program, false),
                AccountMeta::new_readonly(network_key_pda, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
            ],
        }],
        &[&yes_req],
    );
    ok(&format!(
        "Yes decryption requested: {}",
        yes_req.pubkey()
    ));

    let no_req = Keypair::new();
    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: vec![3, cpi_bump, 0],
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new(no_req.pubkey(), true),
                AccountMeta::new_readonly(no_ct.pubkey(), false),
                AccountMeta::new_readonly(encrypt_program, false),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new(deposit_pda, false),
                AccountMeta::new_readonly(cpi_authority, false),
                AccountMeta::new_readonly(voting_program, false),
                AccountMeta::new_readonly(network_key_pda, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
            ],
        }],
        &[&no_req],
    );
    ok(&format!("No decryption requested: {}", no_req.pubkey()));

    // ── 5. Wait for Executor ──
    log("5/6", "Waiting for executor to decrypt...");

    poll_until(
        &client,
        &yes_req.pubkey(),
        |d| {
            d.len() >= 107 && {
                let total = read_u32_le(d, 99);
                let written = read_u32_le(d, 103);
                written == total && total > 0
            }
        },
        Duration::from_secs(120),
        Duration::from_secs(1),
    );
    ok("Yes tally decrypted");

    poll_until(
        &client,
        &no_req.pubkey(),
        |d| {
            d.len() >= 107 && {
                let total = read_u32_le(d, 99);
                let written = read_u32_le(d, 103);
                written == total && total > 0
            }
        },
        Duration::from_secs(120),
        Duration::from_secs(1),
    );
    ok("No tally decrypted");

    // ── 6. Reveal Results ──
    log("6/6", "Revealing tallies on-chain...");

    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: vec![4, 1],
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new_readonly(yes_req.pubkey(), false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        }],
        &[],
    );
    send_tx(
        &client,
        &payer,
        vec![Instruction {
            program_id: voting_program,
            data: vec![4, 0],
            accounts: vec![
                AccountMeta::new(proposal_pda, false),
                AccountMeta::new_readonly(no_req.pubkey(), false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        }],
        &[],
    );

    let prop_data = client
        .get_account(&proposal_pda)
        .expect("read proposal")
        .data;
    let total_votes = read_u64_le(&prop_data, 130);
    let revealed_yes = read_u64_le(&prop_data, 138);
    let revealed_no = read_u64_le(&prop_data, 146);

    println!("\n{BOLD}\u{2550}\u{2550}\u{2550} Results \u{2550}\u{2550}\u{2550}{RESET}\n");
    val("Total votes", total_votes);
    val("Yes votes", revealed_yes);
    val("No votes", revealed_no);

    if revealed_yes > revealed_no {
        println!("\n  {GREEN}Proposal PASSED{RESET} ({revealed_yes} yes / {revealed_no} no)\n");
    } else {
        println!("\n  {RED}Proposal REJECTED{RESET} ({revealed_yes} yes / {revealed_no} no)\n");
    }

    Ok(())
}
