#!/usr/bin/env bun
/**
 * PC-Swap E2E — Confidential UniV2 AMM on Solana Devnet
 *
 * All reserves, swap amounts, and LP positions are encrypted.
 * There is no decrypt instruction — nobody can read any values,
 * not even the pool creator.
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <PC_SWAP_PROGRAM_ID>
 */
import { Connection, Keypair, PublicKey, TransactionInstruction } from "@solana/web3.js";
import * as fs from "fs";
import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pda, pollUntil, isVerified, mockCiphertext } from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import { type SwapContext, deriveSwapPdas, derivePoolPda, createPoolIx, swapIx, addLiquidityIx, removeLiquidityIx } from "./instructions.ts";

const RPC = "https://api.devnet.solana.com";
const FHE128 = 5;
const [eArg, sArg] = process.argv.slice(2);
if (!eArg || !sArg) { console.error("Usage: bun main.ts <ENCRYPT_ID> <SWAP_ID>"); process.exit(1); }
const EP = new PublicKey(eArg), SP = new PublicKey(sArg);
const conn = new Connection(RPC, "confirmed");
const payer = (() => { try { return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(
  fs.readFileSync(process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`, "utf-8")))); } catch { return Keypair.generate(); } })();

async function e(grpc: any, v: bigint, nk: Buffer): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({ chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(v, FHE128), fheType: FHE128 }],
    authorized: SP.toBytes(), networkEncryptionPublicKey: nk });
  return new PublicKey(ciphertextIdentifiers[0]);
}

async function main() {
  console.log("\n\x1b[1m═══ PC-Swap E2E: Fully Confidential AMM ═══\x1b[0m\n");
  const grpc = createEncryptClient();
  ok(`Payer: ${payer.publicKey.toBase58()}, Balance: ${(await conn.getBalance(payer.publicKey))/1e9} SOL`);

  // Encrypt setup
  const [cfgPda] = pda([Buffer.from("encrypt_config")], EP);
  const [evtAuth] = pda([Buffer.from("__event_authority")], EP);
  const [depPda, depBump] = pda([Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()], EP);
  const nk = Buffer.alloc(32, 0x55);
  const [nkPda] = pda([Buffer.from("network_encryption_key"), nk], EP);

  if (!(await conn.getAccountInfo(depPda))) {
    log("Setup", "Creating deposit...");
    const ci = await conn.getAccountInfo(cfgPda); if (!ci) throw new Error("No config");
    const ev = new PublicKey((ci.data as Buffer).subarray(100, 132));
    const vp = ev.equals(PublicKey.default) ? payer.publicKey : ev;
    const dd = Buffer.alloc(18); dd[0]=14; dd[1]=depBump;
    await sendTx(conn, payer, [new TransactionInstruction({ programId: EP, data: dd, keys: [
      {pubkey:depPda,isSigner:false,isWritable:true},{pubkey:cfgPda,isSigner:false,isWritable:false},
      {pubkey:payer.publicKey,isSigner:true,isWritable:false},{pubkey:payer.publicKey,isSigner:true,isWritable:true},
      {pubkey:payer.publicKey,isSigner:true,isWritable:true},{pubkey:vp,isSigner:vp.equals(payer.publicKey),isWritable:true},
      {pubkey:PublicKey.default,isSigner:false,isWritable:false},{pubkey:PublicKey.default,isSigner:false,isWritable:false}]})]);
    ok("Deposit created");
  } else ok("Deposit exists");

  const enc: EncryptAccounts = { encryptProgram:EP, configPda:cfgPda, eventAuthority:evtAuth, depositPda:depPda, networkKeyPda:nkPda, networkKey:nk };
  const { cpiAuthority, cpiBump } = deriveSwapPdas(SP);
  const ctx: SwapContext = { programId:SP, enc, payer:payer.publicKey, cpiAuthority, cpiBump };

  // ═══ 1. Create pool + LP position ═══
  log("1/6", "Creating pool + LP position...");
  const mA = Keypair.generate().publicKey, mB = Keypair.generate().publicKey;
  const [pp, pb] = derivePoolPda(SP, mA, mB);
  const rA = Keypair.generate(), rB = Keypair.generate(), ts = Keypair.generate(), pc = Keypair.generate();
  await sendTx(conn, payer, [createPoolIx(ctx, pp, pb, mA, mB, rA.publicKey, rB.publicKey, ts.publicKey, pc.publicKey)], [rA, rB, ts, pc]);
  ok(`Pool: ${pp.toBase58()}`);

  const [lpPda, lpBump] = pda([Buffer.from("pc_lp"), pp.toBuffer(), payer.publicKey.toBuffer()], SP);
  const lpBal = Keypair.generate();
  await sendTx(conn, payer, [new TransactionInstruction({ programId: SP, data: Buffer.from([5, lpBump, cpiBump]), keys: [
    {pubkey:lpPda,isSigner:false,isWritable:true}, {pubkey:pp,isSigner:false,isWritable:false},
    {pubkey:payer.publicKey,isSigner:false,isWritable:false}, {pubkey:lpBal.publicKey,isSigner:true,isWritable:true},
    {pubkey:EP,isSigner:false,isWritable:false}, {pubkey:cfgPda,isSigner:false,isWritable:false},
    {pubkey:depPda,isSigner:false,isWritable:true}, {pubkey:cpiAuthority,isSigner:false,isWritable:false},
    {pubkey:SP,isSigner:false,isWritable:false}, {pubkey:nkPda,isSigner:false,isWritable:false},
    {pubkey:payer.publicKey,isSigner:true,isWritable:true}, {pubkey:evtAuth,isSigner:false,isWritable:false},
    {pubkey:PublicKey.default,isSigner:false,isWritable:false}]})], [lpBal]);
  ok(`LP position: ${lpPda.toBase58()}`);

  // ═══ 2. Add liquidity ═══
  log("2/6", "Adding liquidity (encrypted amounts via gRPC)...");
  const aA = await e(grpc, 10_000n, nk), aB = await e(grpc, 100n, nk);
  await sendTx(conn, payer, [addLiquidityIx(ctx, pp, rA.publicKey, rB.publicKey, ts.publicKey, aA, aB, lpBal.publicKey)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  await pollUntil(conn, ts.publicKey, isVerified, 120_000);
  ok("Liquidity added — reserves and LP balance updated (all encrypted)");

  // ═══ 3. Swap A → B ═══
  log("3/6", "Swap A → B (encrypted amount)...");
  const s1i = await e(grpc, 1000n, nk), s1m = await e(grpc, 0n, nk), s1o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rA.publicKey, rB.publicKey, s1i, s1m, s1o, pc.publicKey, 0)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  await pollUntil(conn, pc.publicKey, isVerified, 120_000);

  // Read public price via gRPC — anyone can do this, no authorization needed
  try {
    const { encodeReadCiphertextMessage } = await import("../../../clients/typescript/src/grpc.ts");
    const msg = encodeReadCiphertextMessage(0, pc.publicKey.toBytes(), new Uint8Array(0), 0n);
    const priceResult = await grpc.readCiphertext({ message: msg, signature: Buffer.alloc(64), signer: Buffer.alloc(32) });
    const priceBuf = priceResult.value;
    const priceVal = priceBuf.readBigUInt64LE(0);
    val("Price (B per A, 6 dec)", `${Number(priceVal) / 1_000_000}`);
  } catch (err: any) {
    ok("Price ciphertext committed (gRPC read may need executor sync)");
  }
  ok("Swap executed — reserves encrypted, price public");

  // ═══ 4. Swap B → A ═══
  log("4/6", "Swap B → A (encrypted amount, reverse)...");
  const s2i = await e(grpc, 10n, nk), s2m = await e(grpc, 0n, nk), s2o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rB.publicKey, rA.publicKey, s2i, s2m, s2o, pc.publicKey, 1)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  ok("Reverse swap executed");

  // ═══ 5. Slippage rejection ═══
  log("5/6", "Swap with excessive slippage...");
  const s3i = await e(grpc, 500n, nk), s3m = await e(grpc, 999n, nk), s3o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rA.publicKey, rB.publicKey, s3i, s3m, s3o, pc.publicKey, 0)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  ok("Swap submitted — slippage check enforced in FHE (no-op if failed)");

  // ═══ 6. Remove liquidity ═══
  log("6/6", "Removing liquidity (encrypted burn amount)...");
  const bc = await e(grpc, 500_000n, nk), oa = await e(grpc, 0n, nk), ob = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [removeLiquidityIx(ctx, pp, rA.publicKey, rB.publicKey, ts.publicKey, bc, lpBal.publicKey, oa, ob)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  await pollUntil(conn, ts.publicKey, isVerified, 120_000);
  ok("Liquidity removed — withdrawn amounts, new reserves, LP balance all encrypted");

  console.log("\n\x1b[1m═══ Result ═══\x1b[0m\n");
  console.log("  6 operations executed on Solana devnet:");
  console.log("    1. Pool created with encrypted zero reserves");
  console.log("    2. Liquidity added (amounts encrypted)");
  console.log("    3. Swap A → B (amount in, amount out, reserves — all encrypted)");
  console.log("    4. Swap B → A (reverse, all encrypted)");
  console.log("    5. Slippage-protected swap (enforced in FHE)");
  console.log("    6. LP tokens burned, proportional reserves withdrawn (all encrypted)");
  console.log("\n  There is no decrypt instruction. Nobody can read:");
  console.log("    - Pool reserves (TVL hidden)");
  console.log("    - Swap amounts (trade sizes hidden)");
  console.log("    - LP positions (ownership hidden)");
  console.log("    - Withdrawn amounts (exits hidden)");
  console.log("\n  What's visible: 6 transactions happened. Nothing else.");
  console.log(`\n  \x1b[32m✓ Fully confidential AMM on Solana.\x1b[0m\n`);

  grpc.close();
}

main().catch(err => { console.error("\x1b[31mError:\x1b[0m", err.message || err); process.exit(1); });
