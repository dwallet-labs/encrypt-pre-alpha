// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Multi-op vector E2E with value verification.
//!
//! Tests chained operations inside single FHE graphs through the full
//! gRPC → on-chain CPI → off-chain executor → commit → decrypt pipeline.
//! Reads decrypted plaintext back from on-chain DecryptionRequest accounts
//! and asserts element values.

use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, thread};

use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

use encrypt_solana_client::grpc::{EncryptClient, TypedInput};
use encrypt_types::types::FheType;

const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn pda(seeds: &[&[u8]], pid: &Pubkey) -> (Pubkey, u8) { Pubkey::find_program_address(seeds, pid) }

fn send_tx(c: &RpcClient, p: &Keypair, ixs: Vec<Instruction>, extra: &[&Keypair]) {
    let bh = c.get_latest_blockhash().unwrap();
    let mut s: Vec<&Keypair> = vec![p]; s.extend(extra);
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&p.pubkey()), &s, bh);
    let b = bincode::serialize(&tx).unwrap();
    let v: solana_transaction::versioned::VersionedTransaction = bincode::deserialize(&b).unwrap();
    c.send_and_confirm_transaction(&v).unwrap();
}

/// Poll until ciphertext is committed (status=1 and digest != zero)
fn poll_committed(c: &RpcClient, pk: &Pubkey) {
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(60) { panic!("timeout waiting for commit: {pk}"); }
        if let Ok(a) = c.get_account(pk) {
            if a.data.len() >= 100 && a.data[99] == 1 && a.data[2..34] != [0u8; 32] { return; }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Poll until decryption response is complete, then read plaintext bytes
fn poll_decrypted(c: &RpcClient, req_pk: &Pubkey) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(120) { panic!("timeout waiting for decryption: {req_pk}"); }
        if let Ok(a) = c.get_account(req_pk) {
            if a.data.len() >= 107 {
                let total = u32::from_le_bytes(a.data[99..103].try_into().unwrap()) as usize;
                let written = u32::from_le_bytes(a.data[103..107].try_into().unwrap()) as usize;
                if total > 0 && written == total {
                    return a.data[107..107 + total].to_vec();
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn make_vec(ft: FheType, elems: &[u128]) -> Vec<u8> {
    let bw = ft.byte_width(); let ebw = ft.element_byte_width();
    let mut buf = vec![0u8; bw];
    for (i, &v) in elems.iter().enumerate() {
        let off = i * ebw; let bytes = v.to_le_bytes();
        buf[off..off + ebw.min(16)].copy_from_slice(&bytes[..ebw.min(16)]);
    }
    buf
}

fn read_u32(buf: &[u8], idx: usize) -> u32 {
    u32::from_le_bytes(buf[idx*4..(idx+1)*4].try_into().unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 { eprintln!("Usage: e2e-vector <ENCRYPT_ID> <VECTOR_ID>"); std::process::exit(1); }
    let encrypt_program = Pubkey::from_str(&args[1])?;
    let vector_program = Pubkey::from_str(&args[2])?;
    let client = RpcClient::new_with_commitment("http://127.0.0.1:8899".to_string(), solana_commitment_config::CommitmentConfig::confirmed());

    println!("\n{BOLD}=== Multi-Op Vector E2E (with value verification) ==={RESET}\n");

    let mut encrypt = EncryptClient::connect_mock("http://localhost:50051").await?;
    let payer = Keypair::new();
    let sig = client.request_airdrop(&payer.pubkey(), 100_000_000_000)?;
    for _ in 0..60 { if client.confirm_transaction(&sig).unwrap_or(false) { break; } thread::sleep(Duration::from_millis(500)); }

    let (config_pda, _) = pda(&[b"encrypt_config"], &encrypt_program);
    let (event_authority, _) = pda(&[b"__event_authority"], &encrypt_program);
    let (deposit_pda, deposit_bump) = pda(&[b"encrypt_deposit", payer.pubkey().as_ref()], &encrypt_program);
    let nk = [0x55u8; 32];
    let (nk_pda, _) = pda(&[b"network_encryption_key", &nk], &encrypt_program);
    let (cpi_authority, cpi_bump) = pda(&[b"__encrypt_cpi_authority"], &vector_program);

    let ci = client.get_account(&config_pda)?;
    let ev = Pubkey::try_from(&ci.data[100..132]).unwrap_or_default();
    let vp = if ev == Pubkey::default() || ev == Pubkey::new_from_array([0u8;32]) { payer.pubkey() } else { ev };
    let vi = ev == Pubkey::default() || ev == Pubkey::new_from_array([0u8;32]);

    // Create deposit
    let mut dd = vec![0u8;18]; dd[0]=14; dd[1]=deposit_bump;
    send_tx(&client, &payer, vec![Instruction { program_id: encrypt_program, data: dd, accounts: vec![
        AccountMeta::new(deposit_pda,false), AccountMeta::new_readonly(config_pda,false),
        AccountMeta::new_readonly(payer.pubkey(),true), AccountMeta::new(payer.pubkey(),true),
        AccountMeta::new(payer.pubkey(),true), AccountMeta::new(vp,vi),
        AccountMeta::new_readonly(Pubkey::default(),false), AccountMeta::new_readonly(Pubkey::default(),false),
    ]}], &[]);
    println!("{GREEN}  \u{2713}{RESET} Setup done");

    let ft = FheType::EVectorU32;

    let enc_accts = |extra: Vec<AccountMeta>| -> Vec<AccountMeta> {
        let mut a = extra;
        a.extend(vec![
            AccountMeta::new_readonly(encrypt_program,false), AccountMeta::new(config_pda,false),
            AccountMeta::new(deposit_pda,false), AccountMeta::new_readonly(cpi_authority,false),
            AccountMeta::new_readonly(vector_program,false), AccountMeta::new_readonly(nk_pda,false),
            AccountMeta::new(payer.pubkey(),true), AccountMeta::new_readonly(event_authority,false),
            AccountMeta::new_readonly(Pubkey::default(),false),
        ]);
        a
    };

    /// Create vector via gRPC authorized to vector_program (for inputs) + wait for commit
    async fn cv(encrypt: &mut EncryptClient<encrypt_compute::mock_crypto::MockEncryptor>,
                client: &RpcClient, ft: FheType, elems: &[u128],
                authorized: &Pubkey, nk: &[u8; 32]) -> Pubkey {
        let pk = encrypt.create_inputs(&[TypedInput::from_raw(ft, make_vec(ft, elems))], authorized, nk)
            .await.unwrap().into_iter().next().unwrap();
        poll_committed(client, &pk);
        pk
    }

    /// Make a ciphertext public (disc=10) so anyone can request decryption.
    /// Must be called by the current authorized party (via signer path).
    /// For CPI-created ciphertexts, authorized=program, so we can't call this directly.
    /// Instead we use the vector program's dispatcher or the executor's authority.
    /// Make ciphertext public via vector program CPI (disc=99)
    fn make_public(client: &RpcClient, payer: &Keypair, vector_program: &Pubkey,
                   encrypt_program: &Pubkey, cpi_authority: &Pubkey, cpi_bump: u8,
                   ct_pk: &Pubkey) {
        send_tx(client, payer, vec![Instruction {
            program_id: *vector_program,
            data: vec![99, cpi_bump],
            accounts: vec![
                AccountMeta::new(*ct_pk, false),
                AccountMeta::new_readonly(*encrypt_program, false),
                AccountMeta::new_readonly(*cpi_authority, false),
                AccountMeta::new_readonly(*vector_program, false),
            ],
        }], &[]);
    }

    /// Decrypt: make_public + request_decryption + poll response
    fn decrypt_vec(client: &RpcClient, payer: &Keypair,
                   vector_program: &Pubkey, encrypt_program: &Pubkey,
                   config_pda: &Pubkey, deposit_pda: &Pubkey,
                   event_authority: &Pubkey, cpi_authority: &Pubkey,
                   cpi_bump: u8, ct_pk: &Pubkey) -> Vec<u8> {
        make_public(client, payer, vector_program, encrypt_program, cpi_authority, cpi_bump, ct_pk);
        let req = request_decrypt(client, payer, encrypt_program, config_pda, deposit_pda, ct_pk, event_authority);
        poll_decrypted(client, &req)
    }

    /// Request decryption on-chain (disc=11). Ciphertext must be public.
    fn request_decrypt(client: &RpcClient, payer: &Keypair, encrypt_program: &Pubkey,
                       config: &Pubkey, deposit: &Pubkey, ct_pk: &Pubkey,
                       event_authority: &Pubkey) -> Pubkey {
        let req_kp = Keypair::new();
        let req_pk = req_kp.pubkey();
        send_tx(client, payer, vec![Instruction {
            program_id: *encrypt_program,
            data: vec![11], // disc: request_decryption
            accounts: vec![
                AccountMeta::new_readonly(*config, false),
                AccountMeta::new(*deposit, false),
                AccountMeta::new(req_pk, true),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(*ct_pk, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(*event_authority, false),
                AccountMeta::new_readonly(*encrypt_program, false),
            ],
        }], &[&req_kp]);
        req_pk
    }

    let mut passed = 0u32;
    let mut failed = 0u32;

    fn check(passed: &mut u32, failed: &mut u32, name: &str, actual: u32, expected: u32) {
        if actual == expected {
            *passed += 1;
        } else {
            *failed += 1;
            println!("{RED}  \u{2717}{RESET} {name}: expected {expected}, got {actual}");
        }
    }

    // ── 1. dot2: (a*b)+(c*d) ──
    // [10,20]*[2,3]+[1,1]*[5,10] = [25,70]
    {
        println!("{CYAN}[1/6]{RESET} dot2: (a*b)+(c*d)");
        let a = cv(&mut encrypt, &client, ft, &[10,20], &vector_program, &nk).await;
        let b = cv(&mut encrypt, &client, ft, &[2,3], &vector_program, &nk).await;
        let c = cv(&mut encrypt, &client, ft, &[1,1], &vector_program, &nk).await;
        let d = cv(&mut encrypt, &client, ft, &[5,10], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![50, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(b,false), AccountMeta::new(c,false), AccountMeta::new(d,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "dot2[0]", read_u32(&plaintext, 0), 25);
        check(&mut passed, &mut failed, "dot2[1]", read_u32(&plaintext, 1), 70);
        println!("{GREEN}  \u{2713}{RESET} dot2: [25,70] verified");
    }

    // ── 2. linear: a*5+b*3+7 ──
    // [10,20]*5+[1,2]*3+7 = [60,113]
    {
        println!("{CYAN}[2/6]{RESET} linear: a*5+b*3+7");
        let a = cv(&mut encrypt, &client, ft, &[10,20], &vector_program, &nk).await;
        let b = cv(&mut encrypt, &client, ft, &[1,2], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![51, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(b,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "linear[0]", read_u32(&plaintext, 0), 60);
        check(&mut passed, &mut failed, "linear[1]", read_u32(&plaintext, 1), 113);
        check(&mut passed, &mut failed, "linear[2]", read_u32(&plaintext, 2), 7);
        println!("{GREEN}  \u{2713}{RESET} linear: [60,113,7] verified");
    }

    // ── 3. mask_sum: (a&mask)+(b|mask) ──
    // a=[0xFF,0x0F], b=[0xF0,0], mask=[0x0F,0xFF]
    // = [0x0F+0xFF, 0x0F+0xFF] = [270, 270]
    {
        println!("{CYAN}[3/6]{RESET} mask_sum: (a&mask)+(b|mask)");
        let a = cv(&mut encrypt, &client, ft, &[0xFF,0x0F], &vector_program, &nk).await;
        let b = cv(&mut encrypt, &client, ft, &[0xF0,0], &vector_program, &nk).await;
        let mask = cv(&mut encrypt, &client, ft, &[0x0F,0xFF], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![52, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(b,false), AccountMeta::new(mask,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "mask_sum[0]", read_u32(&plaintext, 0), 270);
        check(&mut passed, &mut failed, "mask_sum[1]", read_u32(&plaintext, 1), 270);
        println!("{GREEN}  \u{2713}{RESET} mask_sum: [270,270] verified");
    }

    // ── 4. cond_add: if true {acc+val} else {acc} ──
    // acc=[100,200], val=[5,10] → [105,210]
    {
        println!("{CYAN}[4/6]{RESET} cond_add: if true {{acc+val}}");
        let cond = encrypt.create_inputs(&[TypedInput::from_raw(FheType::EBool, vec![1])], &vector_program, &nk)
            .await?.into_iter().next().unwrap();
        poll_committed(&client, &cond);
        let acc = cv(&mut encrypt, &client, ft, &[100,200], &vector_program, &nk).await;
        let val = cv(&mut encrypt, &client, ft, &[5,10], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![53, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(cond,false), AccountMeta::new(acc,false), AccountMeta::new(val,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "cond_add[0]", read_u32(&plaintext, 0), 105);
        check(&mut passed, &mut failed, "cond_add[1]", read_u32(&plaintext, 1), 210);
        println!("{GREEN}  \u{2713}{RESET} cond_add: [105,210] verified");
    }

    // ── 5. chain4: ((a+b)*2-c)/2 ──
    // a=[10,20], b=[1,2], c=[4,8] → [9,18]
    {
        println!("{CYAN}[5/6]{RESET} chain4: ((a+b)*2-c)/2");
        let a = cv(&mut encrypt, &client, ft, &[10,20], &vector_program, &nk).await;
        let b = cv(&mut encrypt, &client, ft, &[1,2], &vector_program, &nk).await;
        let c = cv(&mut encrypt, &client, ft, &[4,8], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![54, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(b,false), AccountMeta::new(c,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "chain4[0]", read_u32(&plaintext, 0), 9);
        check(&mut passed, &mut failed, "chain4[1]", read_u32(&plaintext, 1), 18);
        println!("{GREEN}  \u{2713}{RESET} chain4: [9,18] verified");
    }

    // ── 6. sum_diff: (a+b, a-b) dual output ──
    // a=[50,30], b=[10,5] → sum=[60,35], diff=[40,25]
    {
        println!("{CYAN}[6/6]{RESET} sum_diff: (a+b, a-b) dual output");
        let a = cv(&mut encrypt, &client, ft, &[50,30], &vector_program, &nk).await;
        let b = cv(&mut encrypt, &client, ft, &[10,5], &vector_program, &nk).await;
        let o0 = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        let o1 = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![55, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(b,false), AccountMeta::new(o0,false), AccountMeta::new(o1,false)]) }], &[]);
        poll_committed(&client, &o0); poll_committed(&client, &o1);
        let sum = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o0);
        let diff = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o1);
        check(&mut passed, &mut failed, "sum[0]", read_u32(&sum, 0), 60);
        check(&mut passed, &mut failed, "sum[1]", read_u32(&sum, 1), 35);
        check(&mut passed, &mut failed, "diff[0]", read_u32(&diff, 0), 40);
        check(&mut passed, &mut failed, "diff[1]", read_u32(&diff, 1), 25);
        println!("{GREEN}  \u{2713}{RESET} sum_diff: sum=[60,35] diff=[40,25] verified");
    }

    // ═══════════════════════════════════════════════
    // Vector-specific structural ops
    // ═══════════════════════════════════════════════

    // ── 7. gather: result[i] = a[indices[i]] ──
    // a=[10,20,30,40], indices=[2,0,3,1] → [30,10,40,20]
    {
        println!("{CYAN}[7/10]{RESET} gather: result[i] = a[indices[i]]");
        let a = cv(&mut encrypt, &client, ft, &[10,20,30,40], &vector_program, &nk).await;
        let idx = cv(&mut encrypt, &client, ft, &[2,0,3,1], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![60, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(idx,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "gather[0]", read_u32(&plaintext, 0), 30);
        check(&mut passed, &mut failed, "gather[1]", read_u32(&plaintext, 1), 10);
        check(&mut passed, &mut failed, "gather[2]", read_u32(&plaintext, 2), 40);
        check(&mut passed, &mut failed, "gather[3]", read_u32(&plaintext, 3), 20);
        println!("{GREEN}  \u{2713}{RESET} gather: [30,10,40,20] verified");
    }

    // ── 8. copy: result = src ──
    // a=ignored, src=[77,88,99] → [77,88,99]
    {
        println!("{CYAN}[8/10]{RESET} copy: result = src");
        let a = cv(&mut encrypt, &client, ft, &[1,2,3], &vector_program, &nk).await;
        let src = cv(&mut encrypt, &client, ft, &[77,88,99], &vector_program, &nk).await;
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![62, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(src,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "copy[0]", read_u32(&plaintext, 0), 77);
        check(&mut passed, &mut failed, "copy[1]", read_u32(&plaintext, 1), 88);
        check(&mut passed, &mut failed, "copy[2]", read_u32(&plaintext, 2), 99);
        println!("{GREEN}  \u{2713}{RESET} copy: [77,88,99] verified");
    }

    // ── 9. assign: a.assign(indices, values) → a with a[indices[i]] = values[i] ──
    // base=[100,200,300,400], indices=[1,3,4,5,...], values=[11,22,0,...]
    // → [100,11,300,22,0,...]
    {
        println!("{CYAN}[9/10]{RESET} assign: a[indices] = values");
        let count = ft.element_count();
        // Build full index vector: first 2 target pos 1,3; rest identity shifted to >= 4
        let mut idx_elems: Vec<u128> = (0..count as u128).collect();
        idx_elems[0] = 1; idx_elems[1] = 3;
        for i in 2..count { idx_elems[i] = (i + 2) as u128; }
        let mut val_elems: Vec<u128> = vec![0; count];
        val_elems[0] = 11; val_elems[1] = 22;

        let base = cv(&mut encrypt, &client, ft, &[100,200,300,400], &vector_program, &nk).await;
        let idx = encrypt.create_inputs(&[TypedInput::from_raw(ft, make_vec(ft, &idx_elems))], &vector_program, &nk)
            .await?.into_iter().next().unwrap();
        poll_committed(&client, &idx);
        let vals = encrypt.create_inputs(&[TypedInput::from_raw(ft, make_vec(ft, &val_elems))], &vector_program, &nk)
            .await?.into_iter().next().unwrap();
        poll_committed(&client, &vals);
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;

        // disc=63: ternary (base, indices, values, output)
        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![63, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(base,false), AccountMeta::new(idx,false), AccountMeta::new(vals,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "assign[0]", read_u32(&plaintext, 0), 100);
        check(&mut passed, &mut failed, "assign[1]", read_u32(&plaintext, 1), 11);
        check(&mut passed, &mut failed, "assign[2]", read_u32(&plaintext, 2), 300);
        check(&mut passed, &mut failed, "assign[3]", read_u32(&plaintext, 3), 22);
        println!("{GREEN}  \u{2713}{RESET} assign: [100,11,300,22] verified");
    }

    // ── 10. scatter: result[indices[i]] = a[i] ──
    // Same index trick as assign to avoid overwrites
    {
        println!("{CYAN}[10/10]{RESET} scatter: result[indices[i]] = a[i]");
        let count = ft.element_count();
        let mut val_elems: Vec<u128> = vec![0; count];
        val_elems[0] = 10; val_elems[1] = 20; val_elems[2] = 30;
        let mut idx_elems: Vec<u128> = (0..count as u128).collect();
        idx_elems[0] = 2; idx_elems[1] = 0; idx_elems[2] = 1;
        for i in 3..count { idx_elems[i] = (i + 1) as u128; } // shift to avoid collision

        let a = encrypt.create_inputs(&[TypedInput::from_raw(ft, make_vec(ft, &val_elems))], &vector_program, &nk)
            .await?.into_iter().next().unwrap();
        poll_committed(&client, &a);
        let idx = encrypt.create_inputs(&[TypedInput::from_raw(ft, make_vec(ft, &idx_elems))], &vector_program, &nk)
            .await?.into_iter().next().unwrap();
        poll_committed(&client, &idx);
        let o = cv(&mut encrypt, &client, ft, &[], &vector_program, &nk).await;

        send_tx(&client, &payer, vec![Instruction { program_id: vector_program, data: vec![61, cpi_bump],
            accounts: enc_accts(vec![AccountMeta::new(a,false), AccountMeta::new(idx,false), AccountMeta::new(o,false)]) }], &[]);
        poll_committed(&client, &o);
        let plaintext = decrypt_vec(&client, &payer, &vector_program, &encrypt_program,
            &config_pda, &deposit_pda, &event_authority, &cpi_authority, cpi_bump, &o);
        check(&mut passed, &mut failed, "scatter[0]", read_u32(&plaintext, 0), 20);
        check(&mut passed, &mut failed, "scatter[1]", read_u32(&plaintext, 1), 30);
        check(&mut passed, &mut failed, "scatter[2]", read_u32(&plaintext, 2), 10);
        println!("{GREEN}  \u{2713}{RESET} scatter: [20,30,10] verified");
    }

    // Summary
    println!();
    if failed == 0 {
        println!("{GREEN}{BOLD}\u{2713} All {passed} value assertions passed!{RESET}");
    } else {
        println!("{RED}{BOLD}\u{2717} {passed} passed, {failed} failed{RESET}");
        std::process::exit(1);
    }

    Ok(())
}
