#!/usr/bin/env bun
/**
 * CP-Token E2E Demo — USDC → cpUSDC → USDC on Solana Devnet
 *
 *   1. Create mock USDC + mint 10 USDC to Alice
 *   2. Create cpUSDC mint + vault + token accounts
 *   3. Alice wraps 10 USDC → 10 cpUSDC
 *   4. Alice sends 5 cpUSDC to Bob (encrypted)
 *   5. Bob unwraps 5 cpUSDC → 5 USDC
 *   6. Alice sends 3 cpUSDC to Mark (encrypted)
 *   7. Mark unwraps 2 cpUSDC → 2 USDC
 *   8. Alice unwraps 1 cpUSDC → 1 USDC
 *   9. Alice still has 1 cpUSDC
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_TOKEN_PROGRAM_ID>
 */

import {
  Connection, Keypair, PublicKey, SystemProgram, Transaction,
  TransactionInstruction, sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as fs from "fs";

import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import {
  log, ok, val, sendTx, pda, pollUntil, isVerified, isDecrypted, mockCiphertext,
} from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import {
  type CpTokenContext, deriveCpTokenPdas, deriveMintPda, deriveAccountPda,
  deriveVaultPda, initializeMintIx, initializeAccountIx, initializeVaultIx,
  transferIx, wrapIx, unwrapIx, requestDecryptIx, revealBalanceIx,
} from "./instructions.ts";
import {
  TOKEN_PROGRAM_ID, createSplMint, createSplTokenAccount,
  splMintToIx, readSplBalance,
} from "./spl-helpers.ts";

const RPC_URL = "https://api.devnet.solana.com";
const FHE_UINT64 = 4;
const DECIMALS = 6;
const USDC = (n: number) => BigInt(n) * 1_000_000n;
const REVEALED_OFFSET = 233; // TokenAccount.revealed_balance offset

const [encryptArg, cpTokenArg] = process.argv.slice(2);
if (!encryptArg || !cpTokenArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_TOKEN_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const CP_TOKEN_PROGRAM = new PublicKey(cpTokenArg);
const connection = new Connection(RPC_URL, "confirmed");

const KEYPAIR_PATH = process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`;
const payer = (() => {
  try {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf-8"))));
  } catch { return Keypair.generate(); }
})();

// ── Helpers ──

async function createEncryptedAmount(
  grpc: ReturnType<typeof createEncryptClient>,
  amount: bigint, networkKey: Buffer
): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(amount), fheType: FHE_UINT64 }],
    authorized: CP_TOKEN_PROGRAM.toBytes(),
    networkEncryptionPublicKey: networkKey,
  });
  return new PublicKey(ciphertextIdentifiers[0]);
}

/** Decrypt + reveal + unwrap. Full exit from confidential domain. */
async function doUnwrap(
  grpc: ReturnType<typeof createEncryptClient>,
  ctx: CpTokenContext,
  cpMint: PublicKey, vault: PublicKey, vaultAta: PublicKey,
  tokenAccount: PublicKey, balanceCt: PublicKey, userAta: PublicKey,
  owner: Keypair, amount: bigint, label: string,
) {
  // 1. Request decryption
  log(label, "Decrypting balance...");
  const decReq = Keypair.generate();
  await sendTx(connection, payer, [
    requestDecryptIx(ctx, tokenAccount, decReq.publicKey, balanceCt, owner.publicKey),
  ], [owner, decReq]);

  await pollUntil(connection, decReq.publicKey, isDecrypted, 120_000);

  // Debug: read raw decrypted value from request account

  ok("Balance decrypted");

  // 2. Reveal balance on-chain
  await sendTx(connection, payer, [
    revealBalanceIx(CP_TOKEN_PROGRAM, tokenAccount, decReq.publicKey, owner.publicKey),
  ], [owner]);

  const taData = (await connection.getAccountInfo(tokenAccount))!.data as Buffer;
  const revealed = taData.readBigUInt64LE(REVEALED_OFFSET);
  val("  Revealed balance", `${Number(revealed) / 1e6} cpUSDC`);

  // 3. Unwrap (burn + SPL transfer in one step)
  log(label, `Unwrapping ${Number(amount) / 1e6} cpUSDC → USDC...`);
  const amountCt = await createEncryptedAmount(grpc, amount, ctx.enc.networkKey);
  await sendTx(connection, payer, [
    unwrapIx(ctx, vault, cpMint, tokenAccount, vaultAta, userAta,
      balanceCt, amountCt, owner.publicKey, amount),
  ], [owner]);

  await pollUntil(connection, balanceCt, isVerified, 120_000);
  ok("Unwrap complete — USDC released from vault");
}

// ── Main ──

async function main() {
  console.log("\n\x1b[1m═══ CP-Token E2E: USDC → cpUSDC → USDC ═══\x1b[0m\n");

  const grpc = createEncryptClient();
  log("Setup", `Payer: ${payer.publicKey.toBase58()}`);
  const bal = await connection.getBalance(payer.publicKey);
  ok(`Balance: ${bal / 1e9} SOL`);

  // Encrypt setup
  const [configPda] = pda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = pda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = pda(
    [Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()], ENCRYPT_PROGRAM);
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = pda([Buffer.from("network_encryption_key"), networkKey], ENCRYPT_PROGRAM);

  const depositInfo = await connection.getAccountInfo(depositPda);
  if (!depositInfo) {
    log("Setup", "Creating Encrypt deposit...");
    const configInfo = await connection.getAccountInfo(configPda);
    if (!configInfo) throw new Error("Encrypt config not initialized");
    const encVault = new PublicKey((configInfo.data as Buffer).subarray(100, 132));
    const vaultPk = encVault.equals(PublicKey.default) ? payer.publicKey : encVault;
    const dd = Buffer.alloc(18); dd[0] = 14; dd[1] = depositBump;
    await sendTx(connection, payer, [new TransactionInstruction({
      programId: ENCRYPT_PROGRAM, data: dd,
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
    })]);
    ok("Deposit created");
  } else { ok("Deposit exists"); }

  const enc: EncryptAccounts = {
    encryptProgram: ENCRYPT_PROGRAM, configPda, eventAuthority,
    depositPda, networkKeyPda, networkKey,
  };
  const { cpiAuthority, cpiBump } = deriveCpTokenPdas(CP_TOKEN_PROGRAM, payer.publicKey);
  const ctx: CpTokenContext = {
    programId: CP_TOKEN_PROGRAM, enc, payer: payer.publicKey, cpiAuthority, cpiBump,
  };

  // Fund users
  const alice = Keypair.generate();
  const bob = Keypair.generate();
  const mark = Keypair.generate();
  await sendAndConfirmTransaction(connection, new Transaction().add(
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: alice.publicKey, lamports: 0.1e9 }),
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: bob.publicKey, lamports: 0.1e9 }),
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: mark.publicKey, lamports: 0.1e9 }),
  ), [payer]);

  // ═══════════════════════════════════════════
  // 1. Create mock USDC + mint 10 to Alice
  // ═══════════════════════════════════════════
  log("1/9", "Creating mock USDC...");
  const usdcMint = await createSplMint(connection, payer, DECIMALS, payer.publicKey);
  ok(`USDC Mint: ${usdcMint.publicKey.toBase58()}`);

  const aliceAta = await createSplTokenAccount(connection, payer, usdcMint.publicKey, alice.publicKey);
  const bobAta = await createSplTokenAccount(connection, payer, usdcMint.publicKey, bob.publicKey);
  const markAta = await createSplTokenAccount(connection, payer, usdcMint.publicKey, mark.publicKey);

  await sendTx(connection, payer, [splMintToIx(usdcMint.publicKey, aliceAta.publicKey, payer.publicKey, USDC(10))]);
  val("Alice USDC", "10");

  // ═══════════════════════════════════════════
  // 2. Create cpUSDC mint + vault + accounts
  // ═══════════════════════════════════════════
  log("2/9", "Creating cpUSDC mint, vault, accounts...");
  const mintAuth = Keypair.generate();
  const [cpMint, cpMintBump] = deriveMintPda(CP_TOKEN_PROGRAM, mintAuth.publicKey);
  await sendTx(connection, payer, [initializeMintIx(ctx, cpMint, cpMintBump, DECIMALS, mintAuth.publicKey)], [mintAuth]);
  ok(`cpUSDC Mint: ${cpMint.toBase58()}`);

  const [vaultPda, vaultBump] = deriveVaultPda(CP_TOKEN_PROGRAM, cpMint);
  await sendTx(connection, payer, [initializeVaultIx(ctx, vaultPda, vaultBump, cpMint, usdcMint.publicKey)]);
  const vaultAta = await createSplTokenAccount(connection, payer, usdcMint.publicKey, vaultPda);
  ok(`Vault: ${vaultPda.toBase58()}`);

  const [aliceCp, aliceBump] = deriveAccountPda(CP_TOKEN_PROGRAM, cpMint, alice.publicKey);
  const aliceBal = Keypair.generate();
  await sendTx(connection, payer, [initializeAccountIx(ctx, aliceCp, aliceBump, cpMint, alice.publicKey, aliceBal.publicKey)], [aliceBal]);

  const [bobCp, bobBump] = deriveAccountPda(CP_TOKEN_PROGRAM, cpMint, bob.publicKey);
  const bobBal = Keypair.generate();
  await sendTx(connection, payer, [initializeAccountIx(ctx, bobCp, bobBump, cpMint, bob.publicKey, bobBal.publicKey)], [bobBal]);

  const [markCp, markBump] = deriveAccountPda(CP_TOKEN_PROGRAM, cpMint, mark.publicKey);
  const markBal = Keypair.generate();
  await sendTx(connection, payer, [initializeAccountIx(ctx, markCp, markBump, cpMint, mark.publicKey, markBal.publicKey)], [markBal]);
  ok("Alice, Bob, Mark accounts created");

  // ═══════════════════════════════════════════
  // 3. Alice wraps 10 USDC → 10 cpUSDC
  // ═══════════════════════════════════════════
  log("3/9", "Alice wraps 10 USDC → 10 cpUSDC...");
  const wrapAmountCt = await createEncryptedAmount(grpc, USDC(10), networkKey);
  ok(`Wrap amount CT: ${wrapAmountCt.toBase58()} (via gRPC)`);

  await sendTx(connection, payer, [
    wrapIx(ctx, vaultPda, aliceCp, aliceAta.publicKey, vaultAta.publicKey,
      aliceBal.publicKey, wrapAmountCt, alice.publicKey, USDC(10)),
  ], [alice]);
  await pollUntil(connection, aliceBal.publicKey, isVerified, 120_000);
  ok("Alice: 10 cpUSDC (encrypted)");
  val("Vault USDC", `${Number(await readSplBalance(connection, vaultAta.publicKey)) / 1e6}`);

  // ═══════════════════════════════════════════
  // 4. Alice sends 5 cpUSDC to Bob
  // ═══════════════════════════════════════════
  log("4/9", "Alice → Bob: 5 cpUSDC (encrypted)...");
  const xfer1 = await createEncryptedAmount(grpc, USDC(5), networkKey);
  await sendTx(connection, payer, [
    transferIx(ctx, aliceCp, bobCp, aliceBal.publicKey, bobBal.publicKey, xfer1, alice.publicKey),
  ], [alice]);
  await pollUntil(connection, aliceBal.publicKey, isVerified, 120_000);
  await pollUntil(connection, bobBal.publicKey, isVerified, 120_000);
  ok("Transfer committed");

  // ═══════════════════════════════════════════
  // 5. Bob unwraps 5 cpUSDC → 5 USDC
  // ═══════════════════════════════════════════
  await doUnwrap(grpc, ctx, cpMint, vaultPda, vaultAta.publicKey,
    bobCp, bobBal.publicKey, bobAta.publicKey, bob, USDC(5), "5/9");
  val("Bob USDC", `${Number(await readSplBalance(connection, bobAta.publicKey)) / 1e6}`);
  val("Vault USDC", `${Number(await readSplBalance(connection, vaultAta.publicKey)) / 1e6}`);

  // ═══════════════════════════════════════════
  // 6. Alice sends 3 cpUSDC to Mark
  // ═══════════════════════════════════════════
  log("6/9", "Alice → Mark: 3 cpUSDC (encrypted)...");
  const xfer2 = await createEncryptedAmount(grpc, USDC(3), networkKey);
  await sendTx(connection, payer, [
    transferIx(ctx, aliceCp, markCp, aliceBal.publicKey, markBal.publicKey, xfer2, alice.publicKey),
  ], [alice]);
  await pollUntil(connection, aliceBal.publicKey, isVerified, 120_000);
  await pollUntil(connection, markBal.publicKey, isVerified, 120_000);
  ok("Transfer committed");

  // ═══════════════════════════════════════════
  // 7. Mark unwraps 2 cpUSDC → 2 USDC
  // ═══════════════════════════════════════════
  await doUnwrap(grpc, ctx, cpMint, vaultPda, vaultAta.publicKey,
    markCp, markBal.publicKey, markAta.publicKey, mark, USDC(2), "7/9");
  val("Mark USDC", `${Number(await readSplBalance(connection, markAta.publicKey)) / 1e6}`);
  val("Vault USDC", `${Number(await readSplBalance(connection, vaultAta.publicKey)) / 1e6}`);

  // ═══════════════════════════════════════════
  // 8. Alice unwraps 1 cpUSDC → 1 USDC
  // ═══════════════════════════════════════════
  await doUnwrap(grpc, ctx, cpMint, vaultPda, vaultAta.publicKey,
    aliceCp, aliceBal.publicKey, aliceAta.publicKey, alice, USDC(1), "8/9");
  val("Alice USDC", `${Number(await readSplBalance(connection, aliceAta.publicKey)) / 1e6}`);
  val("Vault USDC", `${Number(await readSplBalance(connection, vaultAta.publicKey)) / 1e6}`);

  // ═══════════════════════════════════════════
  // 9. Final state
  // ═══════════════════════════════════════════
  const aliceUsdc = await readSplBalance(connection, aliceAta.publicKey);
  const bobUsdc = await readSplBalance(connection, bobAta.publicKey);
  const markUsdc = await readSplBalance(connection, markAta.publicKey);
  const vaultUsdc = await readSplBalance(connection, vaultAta.publicKey);

  console.log("\n\x1b[1m═══ Final State ═══\x1b[0m\n");
  console.log("  SPL USDC (public):");
  val("  Alice", `${Number(aliceUsdc) / 1e6} USDC`);
  val("  Bob  ", `${Number(bobUsdc) / 1e6} USDC`);
  val("  Mark ", `${Number(markUsdc) / 1e6} USDC`);
  val("  Vault", `${Number(vaultUsdc) / 1e6} USDC (locked for remaining cpUSDC)`);
  console.log("\n  cpUSDC (encrypted — values hidden on-chain):");
  console.log("    Alice: 1 cpUSDC");
  console.log("    Mark:  1 cpUSDC");

  const allCorrect = aliceUsdc === USDC(1) && bobUsdc === USDC(5) && markUsdc === USDC(2) && vaultUsdc === USDC(2);
  console.log(allCorrect
    ? `\n  \x1b[32m✓ All balances correct! 10 USDC conserved.\x1b[0m\n`
    : `\n  \x1b[31m✗ Balance mismatch!\x1b[0m\n`);

  grpc.close();
}

main().catch((err) => { console.error("\x1b[31mError:\x1b[0m", err.message || err); process.exit(1); });
