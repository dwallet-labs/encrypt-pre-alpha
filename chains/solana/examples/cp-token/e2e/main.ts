#!/usr/bin/env bun
/**
 * CP-Token E2E Demo — Confidential Performant Token on Solana Devnet
 *
 * Full lifecycle: create mint → create accounts → mint (encrypted) →
 * transfer (encrypted) → decrypt → reveal → verify balances
 *
 * All amounts are client-encrypted via gRPC — plaintext never touches
 * the chain. Balances are always encrypted.
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_TOKEN_PROGRAM_ID>
 */

import {
  Connection,
  Keypair,
  PublicKey,
} from "@solana/web3.js";
import * as fs from "fs";

import {
  setupEncrypt,
  encryptCpiAccounts,
  type EncryptAccounts,
} from "../../_shared/encrypt-setup.ts";
import {
  log,
  ok,
  val,
  sendTx,
  pda,
  pollUntil,
  isVerified,
  isDecrypted,
  mockCiphertext,
} from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import {
  deriveCpTokenPdas,
  deriveMintPda,
  deriveAccountPda,
  initializeMintIx,
  initializeAccountIx,
  mintToIx,
  transferIx,
  requestDecryptIx,
  revealBalanceIx,
} from "./instructions.ts";

const RPC_URL = "https://api.devnet.solana.com";
const FHE_UINT64 = 4;

const [encryptArg, cpTokenArg] = process.argv.slice(2);
if (!encryptArg || !cpTokenArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_TOKEN_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const CP_TOKEN_PROGRAM = new PublicKey(cpTokenArg);
const connection = new Connection(RPC_URL, "confirmed");

// Load local keypair (solana config keypair) or generate one
const KEYPAIR_PATH = process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`;
const payer = (() => {
  try {
    const raw = JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf-8"));
    return Keypair.fromSecretKey(Uint8Array.from(raw));
  } catch {
    return Keypair.generate();
  }
})();

async function main() {
  console.log("\n\x1b[1m═══ CP-Token E2E Demo ═══\x1b[0m\n");
  console.log("  Confidential token: all balances and amounts are encrypted\n");

  // ── Setup ──
  // Setup encrypt accounts (inline — avoids setupEncrypt's 100 SOL airdrop
  // which fails on devnet rate limits when using a pre-funded keypair)
  const grpc = createEncryptClient();
  log("Setup", `Connected to executor gRPC`);
  log("Setup", `Payer: ${payer.publicKey.toBase58()}`);

  const bal = await connection.getBalance(payer.publicKey);
  ok(`Balance: ${bal / 1e9} SOL`);
  if (bal < 1e9) {
    log("Setup", "Airdropping SOL...");
    const sig = await connection.requestAirdrop(payer.publicKey, 2e9);
    await connection.confirmTransaction(sig);
  }

  const [configPda] = pda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = pda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = pda(
    [Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()],
    ENCRYPT_PROGRAM
  );
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = pda(
    [Buffer.from("network_encryption_key"), networkKey],
    ENCRYPT_PROGRAM
  );

  // Create deposit if needed
  const depositInfo = await connection.getAccountInfo(depositPda);
  if (!depositInfo) {
    log("Setup", "Creating deposit...");
    const configInfo = await connection.getAccountInfo(configPda);
    if (!configInfo) throw new Error("Encrypt config not initialized");
    const encVault = new PublicKey((configInfo.data as Buffer).subarray(100, 132));
    const vaultPk = encVault.equals(PublicKey.default) ? payer.publicKey : encVault;

    const depositData = Buffer.alloc(18);
    depositData[0] = 14;
    depositData[1] = depositBump;

    await sendTx(connection, payer, [
      new (await import("@solana/web3.js")).TransactionInstruction({
        programId: ENCRYPT_PROGRAM,
        data: depositData,
        keys: [
          { pubkey: depositPda, isSigner: false, isWritable: true },
          { pubkey: configPda, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultPk, isSigner: vaultPk.equals(payer.publicKey), isWritable: true },
          { pubkey: PublicKey.default, isSigner: false, isWritable: false },
          { pubkey: PublicKey.default, isSigner: false, isWritable: false },
        ],
      }),
    ]);
    ok("Deposit created");
  } else {
    ok("Deposit already exists");
  }

  const enc: EncryptAccounts = {
    encryptProgram: ENCRYPT_PROGRAM,
    configPda,
    eventAuthority,
    depositPda,
    networkKeyPda,
    networkKey,
  };
  const { cpiAuthority, cpiBump } = deriveCpTokenPdas(CP_TOKEN_PROGRAM, payer.publicKey);

  const ctx = {
    programId: CP_TOKEN_PROGRAM,
    enc,
    payer: payer.publicKey,
    cpiAuthority,
    cpiBump,
  };

  // ── 1. Create Mint ──
  log("1/8", "Creating confidential token mint (6 decimals)...");
  const mintAuthority = Keypair.generate();
  const [mintPda, mintBump] = deriveMintPda(CP_TOKEN_PROGRAM, mintAuthority.publicKey);

  await sendTx(connection, payer, [
    initializeMintIx(ctx, mintPda, mintBump, 6, mintAuthority.publicKey),
  ], [mintAuthority]);
  ok(`Mint: ${mintPda.toBase58()}`);

  // ── 2. Create Token Accounts ──
  log("2/8", "Creating token accounts for Alice and Bob...");

  const alice = Keypair.generate();
  const bob = Keypair.generate();

  const [aliceAccount, aliceBump] = deriveAccountPda(CP_TOKEN_PROGRAM, mintPda, alice.publicKey);
  const [bobAccount, bobBump] = deriveAccountPda(CP_TOKEN_PROGRAM, mintPda, bob.publicKey);

  const aliceBalanceCt = Keypair.generate();
  const bobBalanceCt = Keypair.generate();

  await sendTx(connection, payer, [
    initializeAccountIx(ctx, aliceAccount, aliceBump, mintPda, alice.publicKey, aliceBalanceCt.publicKey),
  ], [aliceBalanceCt]);
  ok(`Alice account: ${aliceAccount.toBase58()}`);
  ok(`Alice balance CT: ${aliceBalanceCt.publicKey.toBase58()}`);

  await sendTx(connection, payer, [
    initializeAccountIx(ctx, bobAccount, bobBump, mintPda, bob.publicKey, bobBalanceCt.publicKey),
  ], [bobBalanceCt]);
  ok(`Bob account: ${bobAccount.toBase58()}`);
  ok(`Bob balance CT: ${bobBalanceCt.publicKey.toBase58()}`);

  // ── 3. Mint 10,000 tokens to Alice (encrypted amount via gRPC) ──
  log("3/8", "Minting 10,000,000 (10 tokens, 6 decimals) to Alice...");

  const mintAmount = 10_000_000n; // 10 tokens with 6 decimals
  const { ciphertextIdentifiers: mintCtIds } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(mintAmount), fheType: FHE_UINT64 }],
    authorized: CP_TOKEN_PROGRAM.toBytes(),
    networkEncryptionPublicKey: enc.networkKey,
  });
  const mintAmountCt = new PublicKey(mintCtIds[0]);
  ok(`Mint amount CT: ${mintAmountCt.toBase58()} (encrypted via gRPC)`);

  await sendTx(connection, payer, [
    mintToIx(ctx, mintPda, aliceAccount, aliceBalanceCt.publicKey, mintAmountCt, mintAuthority.publicKey),
  ], [mintAuthority]);
  ok("MintTo instruction sent — waiting for executor...");

  await pollUntil(connection, aliceBalanceCt.publicKey, isVerified, 120_000);
  ok("Executor committed graph output");

  // ── 4. Transfer 3,000,000 from Alice to Bob (encrypted amount) ──
  log("4/8", "Transferring 3,000,000 (3 tokens) from Alice to Bob...");

  const transferAmount = 3_000_000n;
  const { ciphertextIdentifiers: xferCtIds } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(transferAmount), fheType: FHE_UINT64 }],
    authorized: CP_TOKEN_PROGRAM.toBytes(),
    networkEncryptionPublicKey: enc.networkKey,
  });
  const xferAmountCt = new PublicKey(xferCtIds[0]);
  ok(`Transfer amount CT: ${xferAmountCt.toBase58()} (encrypted via gRPC)`);

  await sendTx(connection, payer, [
    transferIx(
      ctx,
      aliceAccount,
      bobAccount,
      aliceBalanceCt.publicKey,
      bobBalanceCt.publicKey,
      xferAmountCt,
      alice.publicKey,
    ),
  ], [alice]);
  ok("Transfer instruction sent — waiting for executor...");

  await pollUntil(connection, aliceBalanceCt.publicKey, isVerified, 120_000);
  ok("Executor committed graph outputs");

  // Fund Alice and Bob for decrypt rent (they're owners/payers in CPI)
  const { SystemProgram, Transaction } = await import("@solana/web3.js");
  const fundTx = new Transaction().add(
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: alice.publicKey, lamports: 0.05e9 }),
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: bob.publicKey, lamports: 0.05e9 }),
  );
  const { sendAndConfirmTransaction } = await import("@solana/web3.js");
  await sendAndConfirmTransaction(connection, fundTx, [payer]);
  ok("Funded Alice and Bob for decrypt rent");

  // ── 5. Decrypt Alice's balance ──
  log("5/8", "Alice requests balance decryption...");

  const aliceDecReq = Keypair.generate();
  await sendTx(connection, payer, [
    requestDecryptIx(ctx, aliceAccount, aliceDecReq.publicKey, aliceBalanceCt.publicKey, alice.publicKey),
  ], [alice, aliceDecReq]);
  ok(`Decryption requested: ${aliceDecReq.publicKey.toBase58()}`);

  log("5/8", "Waiting for executor to decrypt...");
  await pollUntil(connection, aliceDecReq.publicKey, isDecrypted, 120_000);
  ok("Alice's balance decrypted");

  // ── 6. Decrypt Bob's balance ──
  log("6/8", "Bob requests balance decryption...");

  const bobDecReq = Keypair.generate();
  await sendTx(connection, payer, [
    requestDecryptIx(ctx, bobAccount, bobDecReq.publicKey, bobBalanceCt.publicKey, bob.publicKey),
  ], [bob, bobDecReq]);
  ok(`Decryption requested: ${bobDecReq.publicKey.toBase58()}`);

  log("6/8", "Waiting for executor to decrypt...");
  await pollUntil(connection, bobDecReq.publicKey, isDecrypted, 120_000);
  ok("Bob's balance decrypted");

  // ── 7. Reveal balances on-chain ──
  log("7/8", "Revealing balances on-chain...");

  await sendTx(connection, payer, [
    revealBalanceIx(CP_TOKEN_PROGRAM, aliceAccount, aliceDecReq.publicKey, alice.publicKey),
  ], [alice]);
  ok("Alice's balance revealed");

  await sendTx(connection, payer, [
    revealBalanceIx(CP_TOKEN_PROGRAM, bobAccount, bobDecReq.publicKey, bob.publicKey),
  ], [bob]);
  ok("Bob's balance revealed");

  // ── 8. Read and verify ──
  log("8/8", "Reading revealed balances...");

  const aliceData = (await connection.getAccountInfo(aliceAccount))!.data as Buffer;
  const bobData = (await connection.getAccountInfo(bobAccount))!.data as Buffer;

  // revealed_balance is at offset: mint(32) + owner(32) + balance(32) + delegate_flag(4) +
  // delegate(32) + state(1) + allowance(32) + close_authority_flag(4) + close_authority(32) +
  // pending_digest(32) = 233
  const REVEALED_OFFSET = 233;
  const aliceBalance = aliceData.readBigUInt64LE(REVEALED_OFFSET);
  const bobBalance = bobData.readBigUInt64LE(REVEALED_OFFSET);

  console.log("\n\x1b[1m═══ Results ═══\x1b[0m\n");
  val("Alice balance", `${aliceBalance} (${Number(aliceBalance) / 1_000_000} tokens)`);
  val("Bob balance", `${bobBalance} (${Number(bobBalance) / 1_000_000} tokens)`);

  const expectedAlice = mintAmount - transferAmount;
  const expectedBob = transferAmount;

  if (aliceBalance === expectedAlice && bobBalance === expectedBob) {
    console.log(`\n  \x1b[32m✓ All balances correct!\x1b[0m`);
    console.log(`    Alice: ${expectedAlice} (minted ${mintAmount} - transferred ${transferAmount})`);
    console.log(`    Bob:   ${expectedBob} (received ${transferAmount})\n`);
  } else {
    console.log(`\n  \x1b[31m✗ Balance mismatch!\x1b[0m`);
    console.log(`    Alice: expected ${expectedAlice}, got ${aliceBalance}`);
    console.log(`    Bob:   expected ${expectedBob}, got ${bobBalance}\n`);
  }

  grpc.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
