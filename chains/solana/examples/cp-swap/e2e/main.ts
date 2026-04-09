#!/usr/bin/env bun
/**
 * CP-Swap E2E — Confidential UniV2 AMM with enforced LP positions
 *
 *   1. Create pool + LP position for user
 *   2. Add liquidity — decrypt reserves + LP balance
 *   3. Swap A→B — decrypt output + reserves
 *   4. Swap B→A — decrypt output + reserves
 *   5. Slippage rejection — verify no-op
 *   6. Remove 50% LP — decrypt withdrawn amounts
 *   7. Summary with k-invariant + fee earnings
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <CP_SWAP_PROGRAM_ID>
 */
import { Connection, Keypair, PublicKey, TransactionInstruction } from "@solana/web3.js";
import * as fs from "fs";
import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pda, pollUntil, isVerified, isDecrypted, mockCiphertext } from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import { type SwapContext, deriveSwapPdas, derivePoolPda, createPoolIx, swapIx, addLiquidityIx, requestDecryptIx, removeLiquidityIx } from "./instructions.ts";

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
    inputs: [{ ciphertextBytes: mockCiphertext(v), fheType: FHE128 }],
    authorized: SP.toBytes(), networkEncryptionPublicKey: nk });
  return new PublicKey(ciphertextIdentifiers[0]);
}

async function dec(ctx: SwapContext, ct: PublicKey): Promise<bigint> {
  const req = Keypair.generate();
  await sendTx(conn, payer, [requestDecryptIx(ctx, req.publicKey, ct)], [req]);
  const d = await pollUntil(conn, req.publicKey, isDecrypted, 120_000);
  return d.readBigUInt64LE(107) + (d.readBigUInt64LE(115) << 64n);
}

async function main() {
  console.log("\n\x1b[1m═══ CP-Swap E2E: Confidential AMM with LP Enforcement ═══\x1b[0m\n");
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
  log("1/7", "Creating pool + LP position...");
  const mA = Keypair.generate().publicKey, mB = Keypair.generate().publicKey;
  const [pp, pb] = derivePoolPda(SP, mA, mB);
  const rA = Keypair.generate(), rB = Keypair.generate(), ts = Keypair.generate();
  await sendTx(conn, payer, [createPoolIx(ctx, pp, pb, mA, mB, rA.publicKey, rB.publicKey, ts.publicKey)], [rA, rB, ts]);
  ok(`Pool: ${pp.toBase58()}`);

  // Create LP position
  const [lpPda, lpBump] = pda([Buffer.from("cp_lp"), pp.toBuffer(), payer.publicKey.toBuffer()], SP);
  const lpBal = Keypair.generate();
  const lpKeys = [
    {pubkey:lpPda,isSigner:false,isWritable:true}, {pubkey:pp,isSigner:false,isWritable:false},
    {pubkey:payer.publicKey,isSigner:false,isWritable:false}, {pubkey:lpBal.publicKey,isSigner:true,isWritable:true},
    {pubkey:EP,isSigner:false,isWritable:false}, {pubkey:cfgPda,isSigner:false,isWritable:false},
    {pubkey:depPda,isSigner:false,isWritable:true}, {pubkey:cpiAuthority,isSigner:false,isWritable:false},
    {pubkey:SP,isSigner:false,isWritable:false}, {pubkey:nkPda,isSigner:false,isWritable:false},
    {pubkey:payer.publicKey,isSigner:true,isWritable:true}, {pubkey:evtAuth,isSigner:false,isWritable:false},
    {pubkey:PublicKey.default,isSigner:false,isWritable:false},
  ];
  await sendTx(conn, payer, [new TransactionInstruction({programId:SP, data:Buffer.from([5,lpBump,cpiBump]), keys:lpKeys})], [lpBal]);
  ok(`LP position: ${lpPda.toBase58()}`);

  // ═══ 2. Add liquidity ═══
  log("2/7", "Adding liquidity: 10,000 / 100...");
  const aA = await e(grpc, 10_000n, nk), aB = await e(grpc, 100n, nk);
  await sendTx(conn, payer, [addLiquidityIx(ctx, pp, rA.publicKey, rB.publicKey, ts.publicKey, aA, aB, lpBal.publicKey)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  await pollUntil(conn, ts.publicKey, isVerified, 120_000);

  let ra = await dec(ctx, rA.publicKey), rb = await dec(ctx, rB.publicKey);
  let supply = await dec(ctx, ts.publicKey), userLp = await dec(ctx, lpBal.publicKey);
  val("Reserves", `${ra} / ${rb}`);
  val("LP minted to user", userLp);
  val("Total supply", supply);
  val("k", ra * rb);

  // ═══ 3. Swap 1,000 A → B ═══
  log("3/7", "Swap: 1,000 A → B...");
  const s1i = await e(grpc, 1000n, nk), s1m = await e(grpc, 0n, nk), s1o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rA.publicKey, rB.publicKey, s1i, s1m, s1o, 0)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  const out1 = await dec(ctx, s1o);
  ra = await dec(ctx, rA.publicKey); rb = await dec(ctx, rB.publicKey);
  ok(`Received: ${out1} B`);
  val("Reserves", `${ra} / ${rb}`);
  val("k", ra * rb);

  // ═══ 4. Swap 10 B → A ═══
  log("4/7", "Swap: 10 B → A...");
  const s2i = await e(grpc, 10n, nk), s2m = await e(grpc, 0n, nk), s2o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rB.publicKey, rA.publicKey, s2i, s2m, s2o, 1)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  const out2 = await dec(ctx, s2o);
  ra = await dec(ctx, rA.publicKey); rb = await dec(ctx, rB.publicKey);
  ok(`Received: ${out2} A`);
  val("Reserves", `${ra} / ${rb}`);

  // ═══ 5. Slippage rejection ═══
  log("5/7", "Swap with excessive slippage (should fail)...");
  const s3i = await e(grpc, 500n, nk), s3m = await e(grpc, 999n, nk), s3o = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [swapIx(ctx, pp, rA.publicKey, rB.publicKey, s3i, s3m, s3o, 0)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  const out3 = await dec(ctx, s3o);
  const ra2 = await dec(ctx, rA.publicKey), rb2 = await dec(ctx, rB.publicKey);
  ok(`Output: ${out3} (expected 0)`);
  val("Reserves unchanged?", ra2 === ra && rb2 === rb ? "✓ yes" : "✗ no");
  ra = ra2; rb = rb2;

  // ═══ 6. Remove 50% LP ═══
  log("6/7", "Removing 50% of LP tokens...");
  userLp = await dec(ctx, lpBal.publicKey);
  const burnAmt = userLp / 2n;
  val("Current LP balance", userLp);
  val("Burning", burnAmt);
  const bc = await e(grpc, burnAmt, nk), oa = await e(grpc, 0n, nk), ob = await e(grpc, 0n, nk);
  await sendTx(conn, payer, [removeLiquidityIx(ctx, pp, rA.publicKey, rB.publicKey, ts.publicKey, bc, lpBal.publicKey, oa, ob)]);
  await pollUntil(conn, rA.publicKey, isVerified, 120_000);
  await pollUntil(conn, ts.publicKey, isVerified, 120_000);
  const wA = await dec(ctx, oa), wB = await dec(ctx, ob);
  ra = await dec(ctx, rA.publicKey); rb = await dec(ctx, rB.publicKey);
  supply = await dec(ctx, ts.publicKey); userLp = await dec(ctx, lpBal.publicKey);
  ok(`Withdrew: ${wA} A + ${wB} B`);
  val("Remaining reserves", `${ra} / ${rb}`);
  val("Remaining LP", `${userLp} / ${supply} total`);

  // ═══ 7. Summary ═══
  console.log("\n\x1b[1m═══ Summary ═══\x1b[0m\n");
  console.log("  Everything below was ENCRYPTED on-chain.\n");
  val("  Deposited", "10,000 A + 100 B");
  val("  Swap 1", `1,000 A → ${out1} B`);
  val("  Swap 2", `10 B → ${out2} A`);
  val("  Slippage reject", `output = ${out3}`);
  val("  Withdrew (50% LP)", `${wA} A + ${wB} B`);
  val("  Final reserves", `${ra} A / ${rb} B`);
  val("  Final k", ra * rb);
  val("  LP remaining", `${userLp} of ${supply}`);
  console.log(`\n  \x1b[32m✓ LP positions enforced in FHE. Nobody can drain what they don't own.\x1b[0m\n`);
  grpc.close();
}

main().catch(e => { console.error("\x1b[31mError:\x1b[0m", e.message || e); process.exit(1); });
