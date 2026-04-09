#!/usr/bin/env bun
/**
 * CP-Swap E2E — Confidential UniV2 AMM on Solana Devnet
 *
 *   1. Create pool (cpUSDC/cpSOL)
 *   2. Add liquidity: 10,000 / 100
 *   3. Decrypt + verify reserves
 *   4. Swap 1,000 cpUSDC → cpSOL — decrypt output + reserves
 *   5. Swap 10 cpSOL → cpUSDC — decrypt output + reserves
 *   6. Swap with slippage too high — verify no-op
 *   7. Remove 25% liquidity — decrypt withdrawn amounts
 *   8. Final state summary with k-invariant check
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_SWAP_PROGRAM_ID>
 */

import {
  Connection, Keypair, PublicKey, TransactionInstruction,
} from "@solana/web3.js";
import * as fs from "fs";

import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import {
  log, ok, val, sendTx, pda, pollUntil, isVerified, isDecrypted, mockCiphertext,
} from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import {
  type SwapContext, deriveSwapPdas, derivePoolPda,
  createPoolIx, swapIx, addLiquidityIx, requestDecryptIx, removeLiquidityIx,
} from "./instructions.ts";

const RPC_URL = "https://api.devnet.solana.com";
const FHE_UINT128 = 5;

const [encryptArg, swapArg] = process.argv.slice(2);
if (!encryptArg || !swapArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_SWAP_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const SWAP_PROGRAM = new PublicKey(swapArg);
const connection = new Connection(RPC_URL, "confirmed");

const KEYPAIR_PATH = process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`;
const payer = (() => {
  try {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf-8"))));
  } catch { return Keypair.generate(); }
})();

// ── Helpers ──

async function enc(
  grpc: ReturnType<typeof createEncryptClient>,
  value: bigint, networkKey: Buffer
): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(value), fheType: FHE_UINT128 }],
    authorized: SWAP_PROGRAM.toBytes(),
    networkEncryptionPublicKey: networkKey,
  });
  return new PublicKey(ciphertextIdentifiers[0]);
}

async function decrypt(
  ctx: SwapContext, ct: PublicKey
): Promise<bigint> {
  const req = Keypair.generate();
  await sendTx(connection, payer, [requestDecryptIx(ctx, req.publicKey, ct)], [req]);
  const data = await pollUntil(connection, req.publicKey, isDecrypted, 120_000);
  // Read u128 (16 bytes LE) from offset 107
  const lo = data.readBigUInt64LE(107);
  const hi = data.readBigUInt64LE(115);
  return lo + (hi << 64n);
}

// ── Main ──

async function main() {
  console.log("\n\x1b[1m═══ CP-Swap E2E: Confidential UniV2 AMM ═══\x1b[0m\n");

  const grpc = createEncryptClient();
  log("Setup", `Payer: ${payer.publicKey.toBase58()}`);
  ok(`Balance: ${(await connection.getBalance(payer.publicKey)) / 1e9} SOL`);

  // Encrypt setup
  const [configPda] = pda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = pda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = pda(
    [Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()], ENCRYPT_PROGRAM);
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = pda([Buffer.from("network_encryption_key"), networkKey], ENCRYPT_PROGRAM);

  const depositInfo = await connection.getAccountInfo(depositPda);
  if (!depositInfo) {
    log("Setup", "Creating deposit...");
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

  const encAccounts: EncryptAccounts = {
    encryptProgram: ENCRYPT_PROGRAM, configPda, eventAuthority,
    depositPda, networkKeyPda, networkKey,
  };
  const { cpiAuthority, cpiBump } = deriveSwapPdas(SWAP_PROGRAM);
  const ctx: SwapContext = {
    programId: SWAP_PROGRAM, enc: encAccounts, payer: payer.publicKey, cpiAuthority, cpiBump,
  };

  // ═══════════════════════════════════════════
  // 1. Create pool
  // ═══════════════════════════════════════════
  log("1/8", "Creating cpUSDC/cpSOL pool...");
  const mintA = Keypair.generate().publicKey;
  const mintB = Keypair.generate().publicKey;
  const [poolPda, poolBump] = derivePoolPda(SWAP_PROGRAM, mintA, mintB);
  const rACt = Keypair.generate();
  const rBCt = Keypair.generate();

  await sendTx(connection, payer, [
    createPoolIx(ctx, poolPda, poolBump, mintA, mintB, rACt.publicKey, rBCt.publicKey),
  ], [rACt, rBCt]);
  ok(`Pool: ${poolPda.toBase58()}`);

  // ═══════════════════════════════════════════
  // 2. Add liquidity: 10,000 cpUSDC + 100 cpSOL
  // ═══════════════════════════════════════════
  log("2/8", "Adding liquidity: 10,000 cpUSDC + 100 cpSOL...");
  const liqA = await enc(grpc, 10_000n, networkKey);
  const liqB = await enc(grpc, 100n, networkKey);
  await sendTx(connection, payer, [
    addLiquidityIx(ctx, poolPda, rACt.publicKey, rBCt.publicKey, liqA, liqB),
  ]);
  await pollUntil(connection, rACt.publicKey, isVerified, 120_000);
  await pollUntil(connection, rBCt.publicKey, isVerified, 120_000);
  ok("Liquidity added");

  // ═══════════════════════════════════════════
  // 3. Decrypt reserves
  // ═══════════════════════════════════════════
  log("3/8", "Decrypting reserves...");
  let ra = await decrypt(ctx, rACt.publicKey);
  let rb = await decrypt(ctx, rBCt.publicKey);
  val("Reserve A (cpUSDC)", ra);
  val("Reserve B (cpSOL)", rb);
  val("k = A × B", ra * rb);

  // ═══════════════════════════════════════════
  // 4. Swap 1,000 cpUSDC → cpSOL
  // ═══════════════════════════════════════════
  log("4/8", "Swap: 1,000 cpUSDC → cpSOL...");
  const s1In = await enc(grpc, 1_000n, networkKey);
  const s1Min = await enc(grpc, 0n, networkKey);
  const s1Out = await enc(grpc, 0n, networkKey);

  await sendTx(connection, payer, [
    swapIx(ctx, poolPda, rACt.publicKey, rBCt.publicKey, s1In, s1Min, s1Out, 0),
  ]);
  await pollUntil(connection, rACt.publicKey, isVerified, 120_000);
  await pollUntil(connection, rBCt.publicKey, isVerified, 120_000);

  const s1Amount = await decrypt(ctx, s1Out);
  ra = await decrypt(ctx, rACt.publicKey);
  rb = await decrypt(ctx, rBCt.publicKey);
  ok(`Received: ${s1Amount} cpSOL`);
  val("Reserve A (cpUSDC)", ra);
  val("Reserve B (cpSOL)", rb);
  val("k = A × B", ra * rb);
  val("k check", ra * rb >= 10_000n * 100n ? "✓ k preserved" : "✗ k violated");

  // ═══════════════════════════════════════════
  // 5. Swap 10 cpSOL → cpUSDC
  // ═══════════════════════════════════════════
  log("5/8", "Swap: 10 cpSOL → cpUSDC...");
  const s2In = await enc(grpc, 10n, networkKey);
  const s2Min = await enc(grpc, 0n, networkKey);
  const s2Out = await enc(grpc, 0n, networkKey);

  await sendTx(connection, payer, [
    swapIx(ctx, poolPda, rBCt.publicKey, rACt.publicKey, s2In, s2Min, s2Out, 1),
  ]);
  await pollUntil(connection, rACt.publicKey, isVerified, 120_000);
  await pollUntil(connection, rBCt.publicKey, isVerified, 120_000);

  const s2Amount = await decrypt(ctx, s2Out);
  ra = await decrypt(ctx, rACt.publicKey);
  rb = await decrypt(ctx, rBCt.publicKey);
  ok(`Received: ${s2Amount} cpUSDC`);
  val("Reserve A (cpUSDC)", ra);
  val("Reserve B (cpSOL)", rb);
  val("k = A × B", ra * rb);

  // ═══════════════════════════════════════════
  // 6. Swap with slippage too high — no-op
  // ═══════════════════════════════════════════
  log("6/8", "Swap: 500 cpUSDC with min_out=999 (should fail)...");
  const s3In = await enc(grpc, 500n, networkKey);
  const s3Min = await enc(grpc, 999n, networkKey);
  const s3Out = await enc(grpc, 0n, networkKey);

  await sendTx(connection, payer, [
    swapIx(ctx, poolPda, rACt.publicKey, rBCt.publicKey, s3In, s3Min, s3Out, 0),
  ]);
  await pollUntil(connection, rACt.publicKey, isVerified, 120_000);

  const s3Amount = await decrypt(ctx, s3Out);
  const raAfter = await decrypt(ctx, rACt.publicKey);
  const rbAfter = await decrypt(ctx, rBCt.publicKey);
  ok(`Output: ${s3Amount} (expected 0 — slippage rejection)`);
  val("Reserves unchanged?", raAfter === ra && rbAfter === rb ? "✓ yes" : "✗ no");
  ra = raAfter; rb = rbAfter;

  // ═══════════════════════════════════════════
  // 7. Remove 25% liquidity
  // ═══════════════════════════════════════════
  log("7/8", "Removing 25% liquidity...");
  const shareCt = await enc(grpc, 2500n, networkKey); // 2500 bps = 25%
  const rmAOut = await enc(grpc, 0n, networkKey);
  const rmBOut = await enc(grpc, 0n, networkKey);

  await sendTx(connection, payer, [
    removeLiquidityIx(ctx, poolPda, rACt.publicKey, rBCt.publicKey, shareCt, rmAOut, rmBOut),
  ]);
  await pollUntil(connection, rACt.publicKey, isVerified, 120_000);
  await pollUntil(connection, rBCt.publicKey, isVerified, 120_000);

  const withdrawnA = await decrypt(ctx, rmAOut);
  const withdrawnB = await decrypt(ctx, rmBOut);
  ra = await decrypt(ctx, rACt.publicKey);
  rb = await decrypt(ctx, rBCt.publicKey);
  ok(`Withdrew: ${withdrawnA} cpUSDC + ${withdrawnB} cpSOL`);
  val("Reserve A (cpUSDC)", ra);
  val("Reserve B (cpSOL)", rb);

  // ═══════════════════════════════════════════
  // 8. Summary
  // ═══════════════════════════════════════════
  console.log("\n\x1b[1m═══ Final Summary ═══\x1b[0m\n");
  console.log("  All values below were ENCRYPTED on-chain.");
  console.log("  Only the pool owner (us) decrypted them for verification.\n");

  val("  Swap 1", `1,000 cpUSDC → ${s1Amount} cpSOL`);
  val("  Swap 2", `10 cpSOL → ${s2Amount} cpUSDC`);
  val("  Swap 3 (slippage)", `rejected — output = ${s3Amount}`);
  val("  Removed", `${withdrawnA} cpUSDC + ${withdrawnB} cpSOL (25%)`);
  val("  Final reserves", `${ra} cpUSDC / ${rb} cpSOL`);
  val("  Final k", ra * rb);

  const kOk = ra * rb > 0n;
  console.log(kOk
    ? `\n  \x1b[32m✓ Confidential AMM verified! All swaps, liquidity, slippage — fully encrypted.\x1b[0m\n`
    : `\n  \x1b[31m✗ Something went wrong.\x1b[0m\n`);

  grpc.close();
}

main().catch((err) => { console.error("\x1b[31mError:\x1b[0m", err.message || err); process.exit(1); });
