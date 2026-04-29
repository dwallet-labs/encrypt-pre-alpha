#!/usr/bin/env bun
/**
 * PC-Swap E2E with VALUE VERIFICATION — comprehensive coverage.
 *
 * Walks every case the protocol must handle correctly and verifies each via
 * SPL conservation (final user SPL + wrap-vault SPL = initial mint, and the
 * user SPL equals the BigInt expectation tracked by the test).
 *
 * Stages
 *   A. AddLiquidity (initial 100+100, lp = receipt_a)
 *   B. Forward swap 1 USDC → DOGE (math)
 *   C. Reverse swap 1 DOGE → USDC (math, opposite direction)
 *   D. Lying user (receipt=0 → no state change)
 *   E. Min_out at exact boundary (slippage holds)
 *   F. Slippage rejection — REFUNDED via vault→user CPI on `refund` slot,
 *      so user balance is unchanged and no donation strands in the vault.
 *   G. AddLiquidity subsequent (proportional LP via min formula)
 *   H. AddLiquidity lying on A side — atomic-deposit gate makes settled=false,
 *      so the truthful B side is refunded and reserves stay flat.
 *   I. RemoveLiquidity insufficient burn (no-op)
 *   J. RemoveLiquidity partial (proportional withdrawal)
 *   K. RemoveLiquidity full (drain remaining LP)
 *   Final: unwrap → SPL conservation (no stranded donations expected)
 *
 * Usage: bun verified.ts <ENCRYPT_PROGRAM_ID> <PC_TOKEN_PROGRAM_ID> <PC_SWAP_PROGRAM_ID>
 */
import { Connection, Keypair, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import * as fs from "fs";
import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { log, ok, sendTx, pda, pollUntil, isVerified, isDecrypted, mockCiphertext } from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import {
  type SwapContext, deriveSwapPdas, derivePoolPda, deriveLpPda,
  createPoolIx, createLpPositionIx, swapIx, addLiquidityIx, removeLiquidityIx,
} from "./instructions.ts";
import {
  type PcTokenContext, derivePcTokenPdas, deriveMintPda, deriveAccountPda, deriveVaultPda, deriveReceiptPda,
  initializeMintIx, initializeAccountIx, initializeVaultIx, wrapIx,
  unwrapBurnIx, unwrapDecryptIx, unwrapCompleteIx,
} from "../../pc-token/e2e/instructions.ts";
import { createSplMint, createSplTokenAccount, splMintToIx, readSplBalance } from "../../pc-token/e2e/spl-helpers.ts";

const RPC = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const FHE64 = 4;
const DECIMALS = 6;
const TOK = (n: number) => BigInt(n) * 1_000_000n;

const [eArg, tArg, sArg] = process.argv.slice(2);
if (!eArg || !tArg || !sArg) {
  console.error("Usage: bun verified.ts <ENCRYPT_ID> <PC_TOKEN_ID> <PC_SWAP_ID>");
  process.exit(1);
}
const EP = new PublicKey(eArg), TP = new PublicKey(tArg), SP = new PublicKey(sArg);
const conn = new Connection(RPC, "confirmed");
const payer = (() => { try { return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(
  fs.readFileSync(process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`, "utf-8")))); } catch { return Keypair.generate(); } })();

async function enc(grpc: any, v: bigint, nk: Buffer, target: PublicKey): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(v, FHE64), fheType: FHE64 }],
    authorized: target.toBytes(),
    networkEncryptionPublicKey: nk,
  });
  return new PublicKey(ciphertextIdentifiers[0]);
}

/** UniV2 constant-product (0.3% fee). Mirrors swap_graph in lib.rs:126. */
const cpOut = (rIn: bigint, rOut: bigint, amtIn: bigint): bigint => {
  const fee = amtIn * 997n;
  return (fee * rOut) / (rIn * 1000n + fee);
};

/** lp_to_mint mirror of add_liquidity_graph. */
const lpToMint = (rA: bigint, rB: bigint, ts: bigint, recA: bigint, recB: bigint): bigint => {
  if (ts === 0n) return recA;
  const lpA = (recA * ts) / (rA + 1n);
  const lpB = (recB * ts) / (rB + 1n);
  return lpA >= lpB ? lpB : lpA;
};

let assertionsPassed = 0, assertionsFailed = 0;
const must = (label: string, actual: bigint, expected: bigint) => {
  if (actual === expected) { assertionsPassed++; ok(`${label}: ${actual} ✓`); }
  else { assertionsFailed++; console.log(`\x1b[31m  ✗\x1b[0m ${label}: got ${actual}, expected ${expected}`); }
};

async function main() {
  console.log("\n\x1b[1m═══ PC-Swap COMPREHENSIVE Value-Verification E2E ═══\x1b[0m\n");
  const grpc = createEncryptClient();
  ok(`Payer: ${payer.publicKey.toBase58()}, Balance: ${(await conn.getBalance(payer.publicKey))/1e9} SOL`);

  // ── Encrypt setup ──
  const [cfgPda] = pda([Buffer.from("encrypt_config")], EP);
  const [evtAuth] = pda([Buffer.from("__event_authority")], EP);
  const [depPda, depBump] = pda([Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()], EP);
  const nk = Buffer.alloc(32, 0x55);
  const [nkPda] = pda([Buffer.from("network_encryption_key"), nk], EP);
  if (!(await conn.getAccountInfo(depPda))) {
    const ci = await conn.getAccountInfo(cfgPda); if (!ci) throw new Error("No config");
    const ev = new PublicKey((ci.data as Buffer).subarray(100, 132));
    const vp = ev.equals(PublicKey.default) ? payer.publicKey : ev;
    const dd = Buffer.alloc(18); dd[0]=14; dd[1]=depBump;
    await sendTx(conn, payer, [new TransactionInstruction({ programId: EP, data: dd, keys: [
      {pubkey:depPda,isSigner:false,isWritable:true},{pubkey:cfgPda,isSigner:false,isWritable:false},
      {pubkey:payer.publicKey,isSigner:true,isWritable:false},{pubkey:payer.publicKey,isSigner:true,isWritable:true},
      {pubkey:payer.publicKey,isSigner:true,isWritable:true},{pubkey:vp,isSigner:vp.equals(payer.publicKey),isWritable:true},
      {pubkey:PublicKey.default,isSigner:false,isWritable:false},{pubkey:PublicKey.default,isSigner:false,isWritable:false}]})]);
  }
  ok("Encrypt ready");

  const encAccts: EncryptAccounts = { encryptProgram:EP, configPda:cfgPda, eventAuthority:evtAuth, depositPda:depPda, networkKeyPda:nkPda, networkKey:nk };
  const tokenPdas = derivePcTokenPdas(TP, payer.publicKey);
  const swapPdas = deriveSwapPdas(SP, TP);
  const tokenCtx: PcTokenContext = { programId:TP, enc:encAccts, payer:payer.publicKey,
    cpiAuthority: tokenPdas.cpiAuthority, cpiBump: tokenPdas.cpiBump };
  const swapCtx: SwapContext = { programId:SP, pcTokenProgramId:TP, enc:encAccts, payer:payer.publicKey,
    cpiAuthority: swapPdas.cpiAuthority, cpiBump: swapPdas.cpiBump,
    pcTokenCpiAuthority: swapPdas.pcTokenCpiAuthority, pcTokenCpiBump: swapPdas.pcTokenCpiBump };

  // ═══ Setup ═══
  log("setup", "Creating mock SPL mints + user accounts...");
  const splUsd = await createSplMint(conn, payer, DECIMALS, payer.publicKey);
  const splDoge = await createSplMint(conn, payer, DECIMALS, payer.publicKey);
  const userUsdAta = await createSplTokenAccount(conn, payer, splUsd.publicKey, payer.publicKey);
  const userDogeAta = await createSplTokenAccount(conn, payer, splDoge.publicKey, payer.publicKey);
  await sendTx(conn, payer, [splMintToIx(splUsd.publicKey, userUsdAta.publicKey, payer.publicKey, TOK(1000))]);
  await sendTx(conn, payer, [splMintToIx(splDoge.publicKey, userDogeAta.publicKey, payer.publicKey, TOK(1000))]);

  const usdAuth = Keypair.generate(), dogeAuth = Keypair.generate();
  const [pcUsdMint, pcUsdMintBump] = deriveMintPda(TP, usdAuth.publicKey);
  const [pcDogeMint, pcDogeMintBump] = deriveMintPda(TP, dogeAuth.publicKey);
  await sendTx(conn, payer, [initializeMintIx(tokenCtx, pcUsdMint, pcUsdMintBump, DECIMALS, usdAuth.publicKey)], [usdAuth]);
  await sendTx(conn, payer, [initializeMintIx(tokenCtx, pcDogeMint, pcDogeMintBump, DECIMALS, dogeAuth.publicKey)], [dogeAuth]);
  const [usdVault, usdVaultBump] = deriveVaultPda(TP, pcUsdMint);
  const [dogeVault, dogeVaultBump] = deriveVaultPda(TP, pcDogeMint);
  await sendTx(conn, payer, [initializeVaultIx(tokenCtx, usdVault, usdVaultBump, pcUsdMint, splUsd.publicKey)]);
  await sendTx(conn, payer, [initializeVaultIx(tokenCtx, dogeVault, dogeVaultBump, pcDogeMint, splDoge.publicKey)]);
  const usdVaultAta = await createSplTokenAccount(conn, payer, splUsd.publicKey, usdVault);
  const dogeVaultAta = await createSplTokenAccount(conn, payer, splDoge.publicKey, dogeVault);
  const [userUsdPc, userUsdPcBump] = deriveAccountPda(TP, pcUsdMint, payer.publicKey);
  const [userDogePc, userDogePcBump] = deriveAccountPda(TP, pcDogeMint, payer.publicKey);
  const userUsdBal = Keypair.generate(), userDogeBal = Keypair.generate();
  await sendTx(conn, payer, [initializeAccountIx(tokenCtx, userUsdPc, userUsdPcBump, pcUsdMint, payer.publicKey, userUsdBal.publicKey)], [userUsdBal]);
  await sendTx(conn, payer, [initializeAccountIx(tokenCtx, userDogePc, userDogePcBump, pcDogeMint, payer.publicKey, userDogeBal.publicKey)], [userDogeBal]);

  await sendTx(conn, payer, [wrapIx(tokenCtx, usdVault, userUsdPc, userUsdAta.publicKey, usdVaultAta.publicKey, userUsdBal.publicKey,
    await enc(grpc, TOK(1000), nk, TP), payer.publicKey, TOK(1000))]);
  await sendTx(conn, payer, [wrapIx(tokenCtx, dogeVault, userDogePc, userDogeAta.publicKey, dogeVaultAta.publicKey, userDogeBal.publicKey,
    await enc(grpc, TOK(1000), nk, TP), payer.publicKey, TOK(1000))]);
  await pollUntil(conn, userUsdBal.publicKey, isVerified);
  await pollUntil(conn, userDogeBal.publicKey, isVerified);
  ok("Setup complete: 1000 pcUSDC + 1000 pcDOGE wrapped, SPL ATAs at 0");

  // ═══ Pool + LP position ═══
  log("pool", "Creating pool + LP position...");
  const [poolPda, poolBump] = derivePoolPda(SP, pcUsdMint, pcDogeMint);
  const [poolVaultUsd, poolVaultUsdBump] = deriveAccountPda(TP, pcUsdMint, poolPda);
  const [poolVaultDoge, poolVaultDogeBump] = deriveAccountPda(TP, pcDogeMint, poolPda);
  const poolVaultUsdBal = Keypair.generate(), poolVaultDogeBal = Keypair.generate();
  const poolReserveUsd = Keypair.generate(), poolReserveDoge = Keypair.generate(), poolTotalSupply = Keypair.generate();
  await sendTx(conn, payer, [createPoolIx(swapCtx, poolPda, poolBump, pcUsdMint, pcDogeMint,
    poolVaultUsd, poolVaultUsdBump, poolVaultDoge, poolVaultDogeBump,
    poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
  )], [poolVaultUsdBal, poolVaultDogeBal, poolReserveUsd, poolReserveDoge, poolTotalSupply]);
  const userLpBal = Keypair.generate();
  await sendTx(conn, payer, [createLpPositionIx(swapCtx, poolPda, payer.publicKey, userLpBal.publicKey)], [userLpBal]);
  ok("Pool ready");

  // ── Tracked expected state ──
  let userUsd = TOK(1000), userDoge = TOK(1000);
  let rUsd = 0n, rDoge = 0n;
  let totalSupply = 0n, userLp = 0n;

  // ═══ A. AddLiquidity initial 100+100 ═══
  log("A", "AddLiquidity initial 100 + 100 (lp = receipt_a)");
  {
    const dep = TOK(100);
    const recA = Keypair.generate(), recB = Keypair.generate();
    await sendTx(conn, payer, [addLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, dep, nk, SP), await enc(grpc, dep, nk, SP), userLpBal.publicKey,
      recA.publicKey, recB.publicKey,
    )], [recA, recB]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    const minted = lpToMint(rUsd, rDoge, totalSupply, dep, dep);
    rUsd += dep; rDoge += dep; totalSupply += minted; userLp += minted;
    userUsd -= dep; userDoge -= dep;
    ok(`pool=(${rUsd},${rDoge}) lp=${userLp}/${totalSupply} user=(${userUsd},${userDoge})`);
  }

  // ═══ B. Forward swap 1 USDC → DOGE ═══
  log("B", "Forward swap: 1 pcUSDC → pcDOGE");
  {
    const amt = TOK(1);
    const out = cpOut(rUsd, rDoge, amt);
    const r = Keypair.generate();
    await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey,
      await enc(grpc, amt, nk, SP), await enc(grpc, 0n, nk, SP), await enc(grpc, 0n, nk, SP), r.publicKey, 0,
    )], [r]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rUsd += amt; rDoge -= out; userUsd -= amt; userDoge += out;
    ok(`out=${out} → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ C. Reverse swap 1 DOGE → USDC ═══
  log("C", "Reverse swap: 1 pcDOGE → pcUSDC");
  {
    const amt = TOK(1);
    const out = cpOut(rDoge, rUsd, amt);
    const r = Keypair.generate();
    await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
      userDogePc, userUsdPc, poolVaultDoge, poolVaultUsd,
      userDogeBal.publicKey, userUsdBal.publicKey, poolVaultDogeBal.publicKey, poolVaultUsdBal.publicKey,
      poolReserveDoge.publicKey, poolReserveUsd.publicKey,
      await enc(grpc, amt, nk, SP), await enc(grpc, 0n, nk, SP), await enc(grpc, 0n, nk, SP), r.publicKey, 1,
    )], [r]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rDoge += amt; rUsd -= out; userDoge -= amt; userUsd += out;
    ok(`out=${out} → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ D. Lying user (claim huge amount) — receipt=0, no state change ═══
  log("D", "Lying user (claim 99,999 USDC, balance is far less) — expect no state change");
  {
    const r = Keypair.generate();
    await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey,
      await enc(grpc, TOK(99_999), nk, SP), await enc(grpc, 0n, nk, SP), await enc(grpc, 0n, nk, SP), r.publicKey, 0,
    )], [r]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    ok(`unchanged → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ E. Min_out at exact boundary — slippage holds ═══
  log("E", "Min_out at exact boundary — slip_ok holds");
  {
    const amt = TOK(1);
    const expected = cpOut(rUsd, rDoge, amt);
    const r = Keypair.generate();
    await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey,
      await enc(grpc, amt, nk, SP), await enc(grpc, expected, nk, SP), await enc(grpc, 0n, nk, SP), r.publicKey, 0,
    )], [r]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rUsd += amt; rDoge -= expected; userUsd -= amt; userDoge += expected;
    ok(`out=${expected} (boundary held) → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ F. Slippage rejection — refunded via vault→user CPI ═══
  // TransferWithReceipt fires before swap_graph; receipt = amt (user is solvent).
  // swap_graph zeros final_in/final_out because amount_out < min_out, but
  // emits refund = receipt (amount), and the dispatch CPIs vault→user for
  // refund. Net effect: user balance and reserves unchanged.
  log("F", "Slippage rejection (1 USDC, min_out=999) — expect refund, no state change");
  {
    const amt = TOK(1);
    const r = Keypair.generate();
    await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey,
      await enc(grpc, amt, nk, SP), await enc(grpc, TOK(999), nk, SP), await enc(grpc, 0n, nk, SP), r.publicKey, 0,
    )], [r]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    // refund returns the deposit; reserves and user balance unchanged.
    ok(`refunded amt=${amt} → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ G. AddLiquidity subsequent 50+50 — proportional LP ═══
  log("G", "AddLiquidity subsequent 50 + 50 — proportional LP via min(lp_a, lp_b)");
  {
    const dep = TOK(50);
    const recA = Keypair.generate(), recB = Keypair.generate();
    const expectedMint = lpToMint(rUsd, rDoge, totalSupply, dep, dep);
    await sendTx(conn, payer, [addLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, dep, nk, SP), await enc(grpc, dep, nk, SP), userLpBal.publicKey,
      recA.publicKey, recB.publicKey,
    )], [recA, recB]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rUsd += dep; rDoge += dep; totalSupply += expectedMint; userLp += expectedMint;
    userUsd -= dep; userDoge -= dep;
    ok(`minted=${expectedMint} → pool=(${rUsd},${rDoge}) lp=${userLp}/${totalSupply} user=(${userUsd},${userDoge})`);
  }

  // ═══ H. AddLiquidity lying on A side — atomic-deposit refunds B ═══
  // Claim 999 USDC (don't have), real 25 DOGE.
  // TransferWithReceipt-A fails → receipt_a=0. TransferWithReceipt-B succeeds → receipt_b=25.
  // graph: settled = both_ok && lp_ok = false → final_a=0, final_b=0,
  // refund_a=0, refund_b=25. Dispatch CPIs vault_b→user for refund_b.
  // Net: reserves and user balances both unchanged.
  log("H", "AddLiquidity lying on A (claim 999 USDC, real 25 DOGE) — expect B refund, no state change");
  {
    const lieA = TOK(999);
    const realB = TOK(25);
    const recA = Keypair.generate(), recB = Keypair.generate();
    await sendTx(conn, payer, [addLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, lieA, nk, SP), await enc(grpc, realB, nk, SP), userLpBal.publicKey,
      recA.publicKey, recB.publicKey,
    )], [recA, recB]);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    // settled=false → no reserve / supply / balance changes.
    ok(`refunded B (${realB}), reserves unchanged → pool=(${rUsd},${rDoge}) user=(${userUsd},${userDoge})`);
  }

  // ═══ I. RemoveLiquidity insufficient (burn=999 huge) — no-op ═══
  log("I", "RemoveLiquidity insufficient (burn=999 LP, user has less) — expect no-op");
  {
    const burn = TOK(999);
    const outA = await enc(grpc, 0n, nk, SP);
    const outB = await enc(grpc, 0n, nk, SP);
    await sendTx(conn, payer, [removeLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, burn, nk, SP), userLpBal.publicKey, outA, outB,
    )]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    ok(`unchanged → pool=(${rUsd},${rDoge}) lp=${userLp}/${totalSupply} user=(${userUsd},${userDoge})`);
  }

  // ═══ J. RemoveLiquidity partial (half of userLp) ═══
  log("J", "RemoveLiquidity partial — burn half of userLp");
  {
    const burn = userLp / 2n;
    const amountA = (rUsd * burn) / (totalSupply + 1n);
    const amountB = (rDoge * burn) / (totalSupply + 1n);
    const outA = await enc(grpc, 0n, nk, SP);
    const outB = await enc(grpc, 0n, nk, SP);
    await sendTx(conn, payer, [removeLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, burn, nk, SP), userLpBal.publicKey, outA, outB,
    )]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rUsd -= amountA; rDoge -= amountB; totalSupply -= burn; userLp -= burn;
    userUsd += amountA; userDoge += amountB;
    ok(`burn=${burn} got=(${amountA},${amountB}) → pool=(${rUsd},${rDoge}) lp=${userLp}/${totalSupply} user=(${userUsd},${userDoge})`);
  }

  // ═══ K. RemoveLiquidity full — drain remaining LP ═══
  log("K", "RemoveLiquidity full — burn remaining userLp");
  {
    const burn = userLp;
    const amountA = (rUsd * burn) / (totalSupply + 1n);
    const amountB = (rDoge * burn) / (totalSupply + 1n);
    const outA = await enc(grpc, 0n, nk, SP);
    const outB = await enc(grpc, 0n, nk, SP);
    await sendTx(conn, payer, [removeLiquidityIx(swapCtx, poolPda,
      userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
      userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
      poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
      await enc(grpc, burn, nk, SP), userLpBal.publicKey, outA, outB,
    )]);
    await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
    await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
    rUsd -= amountA; rDoge -= amountB; totalSupply -= burn; userLp -= burn;
    userUsd += amountA; userDoge += amountB;
    ok(`burn=${burn} got=(${amountA},${amountB}) → pool=(${rUsd},${rDoge}) lp=${userLp}/${totalSupply} user=(${userUsd},${userDoge})`);
  }

  // ═══ Verify by unwrapping remaining pcUSDC + pcDOGE → SPL ═══
  log("verify", `Unwrapping ${userUsd} pcUSDC + ${userDoge} pcDOGE...`);
  await doUnwrap(grpc, tokenCtx, pcUsdMint, usdVault, usdVaultAta.publicKey,
                 userUsdPc, userUsdBal.publicKey, userUsdAta.publicKey, payer, userUsd, nk);
  await doUnwrap(grpc, tokenCtx, pcDogeMint, dogeVault, dogeVaultAta.publicKey,
                 userDogePc, userDogeBal.publicKey, userDogeAta.publicKey, payer, userDoge, nk);

  const finalUsdSpl = await readSplBalance(conn, userUsdAta.publicKey);
  const finalDogeSpl = await readSplBalance(conn, userDogeAta.publicKey);
  const vaultUsdSpl = await readSplBalance(conn, usdVaultAta.publicKey);
  const vaultDogeSpl = await readSplBalance(conn, dogeVaultAta.publicKey);

  console.log("\n\x1b[1m═══ Verification ═══\x1b[0m\n");
  must("user SPL USDC", finalUsdSpl, userUsd);
  must("user SPL DOGE", finalDogeSpl, userDoge);
  must("vault SPL USDC", vaultUsdSpl, TOK(1000) - userUsd);
  must("vault SPL DOGE", vaultDogeSpl, TOK(1000) - userDoge);
  must("conservation USDC", finalUsdSpl + vaultUsdSpl, TOK(1000));
  must("conservation DOGE", finalDogeSpl + vaultDogeSpl, TOK(1000));

  console.log();
  if (assertionsFailed === 0) {
    console.log(`\x1b[32m\x1b[1m✓ All ${assertionsPassed} assertions passed\x1b[0m\n`);
  } else {
    console.log(`\x1b[31m\x1b[1m✗ ${assertionsPassed} passed, ${assertionsFailed} failed\x1b[0m\n`);
    process.exit(1);
  }
  grpc.close();
}

async function doUnwrap(
  grpc: any, ctx: PcTokenContext, pcMint: PublicKey, vault: PublicKey, vaultAta: PublicKey,
  tokenAccount: PublicKey, balanceCt: PublicKey, userAta: PublicKey,
  owner: Keypair, amount: bigint, nk: Buffer,
) {
  if (amount === 0n) return;
  const amountCt = await enc(grpc, amount, nk, TP);
  const burnedCt = await enc(grpc, 0n, nk, TP);
  const [receiptPda, receiptBump] = deriveReceiptPda(TP, burnedCt);

  await sendTx(conn, payer, [unwrapBurnIx(ctx, vault, tokenAccount, receiptPda, receiptBump,
    balanceCt, amountCt, burnedCt, owner.publicKey, amount)], owner === payer ? [] : [owner]);
  await pollUntil(conn, balanceCt, isVerified);
  await pollUntil(conn, burnedCt, isVerified);

  const decReq = Keypair.generate();
  await sendTx(conn, payer, [unwrapDecryptIx(ctx, receiptPda, decReq.publicKey, burnedCt, owner.publicKey)],
    owner === payer ? [decReq] : [owner, decReq]);
  await pollUntil(conn, decReq.publicKey, isDecrypted);

  await sendTx(conn, payer, [unwrapCompleteIx(TP, receiptPda, vault, pcMint,
    decReq.publicKey, vaultAta, userAta, owner.publicKey, payer.publicKey)],
    owner === payer ? [] : [owner]);
}

main().catch(async err => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  if (err.transactionLogs) for (const l of err.transactionLogs) console.error("  ", l);
  if (err.getLogs) try { for (const l of await err.getLogs(conn)) console.error("  ", l); } catch {}
  process.exit(1);
});
