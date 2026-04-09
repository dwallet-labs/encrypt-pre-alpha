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

import { setupEncrypt } from "../../../_shared/encrypt-setup.ts";
import {
  log,
  ok,
  val,
  sendTx,
  pollUntil,
  isVerified,
  isDecrypted,
  mockCiphertext,
} from "../../../_shared/helpers.ts";
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
const payer = Keypair.generate();

async function main() {
  console.log("\n\x1b[1m═══ CP-Token E2E Demo ═══\x1b[0m\n");
  console.log("  Confidential token: all balances and amounts are encrypted\n");

  // ── Setup ──
  const { accounts: enc, encrypt } = await setupEncrypt(
    connection,
    payer,
    ENCRYPT_PROGRAM
  );

  const grpc = createEncryptClient();
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
  const [mintPda, mintBump] = deriveMintPda(CP_TOKEN_PROGRAM, payer.publicKey);

  await sendTx(connection, payer, [
    initializeMintIx(ctx, mintPda, mintBump, 6, payer.publicKey),
  ]);
  ok(`Mint: ${mintPda.toBase58()}`);

  // ── 2. Create Token Accounts ──
  log("2/8", "Creating token accounts for Alice and Bob...");

  const alice = Keypair.generate();
  const bob = Keypair.generate();
  const airdropA = await connection.requestAirdrop(alice.publicKey, 1e9);
  const airdropB = await connection.requestAirdrop(bob.publicKey, 1e9);
  await connection.confirmTransaction(airdropA);
  await connection.confirmTransaction(airdropB);

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
    mintToIx(ctx, mintPda, aliceAccount, aliceBalanceCt.publicKey, mintAmountCt, payer.publicKey),
  ]);
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

  encrypt.close();
  grpc.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
