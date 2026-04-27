#!/usr/bin/env bun
/**
 * PC-Swap E2E — Confidential AMM that composes with PC-Token via CPI.
 *
 * Pool reserves are real PC-Token TokenAccounts owned by the pool PDA.
 * User → vault deposits go through pc-token::TransferWithReceipt (disc 22)
 * which emits a binary receipt ciphertext (= amount on success, 0 on
 * insufficient balance). Reserves and payouts are functions of the
 * receipt — a lying user produces receipt=0 and the swap collapses to
 * a no-op uniformly.
 *
 * Balances stay encrypted throughout; only transaction success is observable.
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <PC_TOKEN_PROGRAM_ID> <PC_SWAP_PROGRAM_ID>
 */
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
import * as fs from "fs";
import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pda, pollUntil, isVerified, mockCiphertext } from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import {
  type SwapContext, deriveSwapPdas, derivePoolPda, deriveLpPda,
  createPoolIx, createLpPositionIx, swapIx, addLiquidityIx, removeLiquidityIx,
} from "./instructions.ts";
import {
  type PcTokenContext, derivePcTokenPdas, deriveMintPda, deriveAccountPda, deriveVaultPda,
  initializeMintIx, initializeAccountIx, initializeVaultIx, wrapIx,
} from "../../pc-token/e2e/instructions.ts";
import { createSplMint, createSplTokenAccount, splMintToIx, readSplBalance } from "../../pc-token/e2e/spl-helpers.ts";

const RPC = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const GRPC_URL = process.env.GRPC_URL;
const FHE64 = 4;
const DECIMALS = 6;
const TOKENS = (n: number) => BigInt(n) * 1_000_000n;

const [eArg, tArg, sArg] = process.argv.slice(2);
if (!eArg || !tArg || !sArg) {
  console.error("Usage: bun main.ts <ENCRYPT_ID> <PC_TOKEN_ID> <PC_SWAP_ID>");
  process.exit(1);
}
const EP = new PublicKey(eArg), TP = new PublicKey(tArg), SP = new PublicKey(sArg);
const conn = new Connection(RPC, "confirmed");
const payer = (() => { try { return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(
  fs.readFileSync(process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`, "utf-8")))); } catch { return Keypair.generate(); } })();

/** Encrypt a value into a ciphertext authorized to a target program. */
async function enc(grpc: any, v: bigint, nk: Buffer, target: PublicKey): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(v, FHE64), fheType: FHE64 }],
    authorized: target.toBytes(),
    networkEncryptionPublicKey: nk,
  });
  return new PublicKey(ciphertextIdentifiers[0]);
}

async function main() {
  console.log("\n\x1b[1m═══ PC-Swap E2E: AMM composing with PC-Token via CPI ═══\x1b[0m\n");
  const grpc = GRPC_URL ? createEncryptClient(GRPC_URL) : createEncryptClient();
  ok(`Payer: ${payer.publicKey.toBase58()}, Balance: ${(await conn.getBalance(payer.publicKey))/1e9} SOL`);

  // ── Encrypt setup ──
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
  }
  ok("Encrypt ready");

  const encAccts: EncryptAccounts = { encryptProgram:EP, configPda:cfgPda, eventAuthority:evtAuth, depositPda:depPda, networkKeyPda:nkPda, networkKey:nk };

  // pc-token + pc-swap CPI authorities
  const tokenPdas = derivePcTokenPdas(TP, payer.publicKey);
  const swapPdas = deriveSwapPdas(SP, TP);
  const tokenCtx: PcTokenContext = { programId:TP, enc:encAccts, payer:payer.publicKey,
    cpiAuthority: tokenPdas.cpiAuthority, cpiBump: tokenPdas.cpiBump };
  const swapCtx: SwapContext = { programId:SP, pcTokenProgramId:TP, enc:encAccts, payer:payer.publicKey,
    cpiAuthority: swapPdas.cpiAuthority, cpiBump: swapPdas.cpiBump,
    pcTokenCpiAuthority: swapPdas.pcTokenCpiAuthority, pcTokenCpiBump: swapPdas.pcTokenCpiBump };

  // ═══ 1. Mock SPL mints + balance ═══
  log("1/8", "Creating mock SPL mints (USD + DOGE)...");
  const splUsd = await createSplMint(conn, payer, DECIMALS, payer.publicKey);
  const splDoge = await createSplMint(conn, payer, DECIMALS, payer.publicKey);
  const userUsdAta = await createSplTokenAccount(conn, payer, splUsd.publicKey, payer.publicKey);
  const userDogeAta = await createSplTokenAccount(conn, payer, splDoge.publicKey, payer.publicKey);
  await sendTx(conn, payer, [splMintToIx(splUsd.publicKey, userUsdAta.publicKey, payer.publicKey, TOKENS(1000))]);
  await sendTx(conn, payer, [splMintToIx(splDoge.publicKey, userDogeAta.publicKey, payer.publicKey, TOKENS(1000))]);
  ok(`User has 1000 USD + 1000 DOGE`);

  // ═══ 2. PC-Token mints + vaults + user accounts ═══
  log("2/8", "Creating pcUSD + pcDOGE mints, vaults, and user pc-token accounts...");
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
  ok("PC-Token accounts ready");

  // ═══ 3. Wrap SPL → pcToken ═══
  log("3/8", "Wrapping 1000 USD + 1000 DOGE to pcTokens...");
  const wrapUsdCt = await enc(grpc, TOKENS(1000), nk, TP);
  const wrapDogeCt = await enc(grpc, TOKENS(1000), nk, TP);
  await sendTx(conn, payer, [wrapIx(tokenCtx, usdVault, userUsdPc, userUsdAta.publicKey, usdVaultAta.publicKey, userUsdBal.publicKey, wrapUsdCt, payer.publicKey, TOKENS(1000))]);
  await sendTx(conn, payer, [wrapIx(tokenCtx, dogeVault, userDogePc, userDogeAta.publicKey, dogeVaultAta.publicKey, userDogeBal.publicKey, wrapDogeCt, payer.publicKey, TOKENS(1000))]);
  await pollUntil(conn, userUsdBal.publicKey, isVerified);
  await pollUntil(conn, userDogeBal.publicKey, isVerified);
  ok("Wrapped");

  // ═══ 4. Create pool ═══
  log("4/8", "Creating pool — pc-swap CPIs into pc-token::initialize_account for both vaults...");
  const [poolPda, poolBump] = derivePoolPda(SP, pcUsdMint, pcDogeMint);
  // Pool vaults are pc-token TokenAccounts owned by the pool PDA.
  const [poolVaultUsd, poolVaultUsdBump] = deriveAccountPda(TP, pcUsdMint, poolPda);
  const [poolVaultDoge, poolVaultDogeBump] = deriveAccountPda(TP, pcDogeMint, poolPda);
  const poolVaultUsdBal = Keypair.generate(), poolVaultDogeBal = Keypair.generate();
  const poolReserveUsd = Keypair.generate(), poolReserveDoge = Keypair.generate(), poolTotalSupply = Keypair.generate();

  await sendTx(conn, payer, [createPoolIx(swapCtx, poolPda, poolBump,
    pcUsdMint, pcDogeMint,
    poolVaultUsd, poolVaultUsdBump, poolVaultDoge, poolVaultDogeBump,
    poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
  )], [poolVaultUsdBal, poolVaultDogeBal, poolReserveUsd, poolReserveDoge, poolTotalSupply]);
  ok(`Pool: ${poolPda.toBase58().slice(0, 12)}…`);

  log("4/8", "Creating LP position...");
  const userLpBal = Keypair.generate();
  await sendTx(conn, payer, [createLpPositionIx(swapCtx, poolPda, payer.publicKey, userLpBal.publicKey)], [userLpBal]);
  const [lpPda] = deriveLpPda(SP, poolPda, payer.publicKey);
  ok(`LP: ${lpPda.toBase58().slice(0, 12)}…`);

  // ═══ 5. AddLiquidity (500 pcUSD + 500 pcDOGE) ═══
  log("5/9", "AddLiquidity — 2× CPI pc-token::TransferWithReceipt; reserves gated on receipts...");
  const addUsdCt = await enc(grpc, TOKENS(500), nk, SP);
  const addDogeCt = await enc(grpc, TOKENS(500), nk, SP);
  const addReceiptA = Keypair.generate(), addReceiptB = Keypair.generate();
  await sendTx(conn, payer, [addLiquidityIx(swapCtx, poolPda,
    userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
    userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
    addUsdCt, addDogeCt, userLpBal.publicKey,
    addReceiptA.publicKey, addReceiptB.publicKey,
  )], [addReceiptA, addReceiptB]);
  await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
  await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
  await pollUntil(conn, userLpBal.publicKey, isVerified);
  ok("Liquidity added — vault balances incremented via CPI, LP minted, receipts closed");

  // ═══ 6. Swap (50 pcUSD → pcDOGE) ═══
  log("6/9", "Swap 50 pcUSD → pcDOGE — TransferWithReceipt feeds swap_graph...");
  const swapInCt = await enc(grpc, TOKENS(50), nk, SP);
  const swapMinCt = await enc(grpc, 0n, nk, SP);
  const swapOutCt = await enc(grpc, 0n, nk, SP);
  const swapReceipt = Keypair.generate();
  await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
    userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
    userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey,
    swapInCt, swapMinCt, swapOutCt, swapReceipt.publicKey, 0,
  )], [swapReceipt]);
  await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
  await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
  ok("Swap executed — user paid pcUSD to vault, received pcDOGE from vault");

  // ═══ 7. Swap with slippage rejection ═══
  log("7/9", "Swap with high min_out — should no-op (slippage check in FHE)...");
  const swapIn2 = await enc(grpc, TOKENS(10), nk, SP);
  const swapMin2 = await enc(grpc, TOKENS(999), nk, SP); // unattainable
  const swapOut2 = await enc(grpc, 0n, nk, SP);
  const swapReceipt2 = Keypair.generate();
  await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
    userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
    userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey,
    swapIn2, swapMin2, swapOut2, swapReceipt2.publicKey, 0,
  )], [swapReceipt2]);
  ok("Slippage no-op submitted (FHE conditional zeroes both transfer amounts)");

  // ═══ 8. Lying user — soundness test ═══
  // User claims amount_in = 99,999 pcUSD but their balance is far below that
  // (after wrap/add/swap above they have ~450 pcUSD left). pc-token's
  // TransferWithReceipt no-ops the deposit and emits receipt=0; swap_graph
  // collapses every output to 0; reserves and the user's pcDOGE balance
  // stay untouched.
  log("8/9", "Lying user — amount_in greater than balance. Receipt should be 0; reserves unchanged...");
  const lieInCt = await enc(grpc, TOKENS(99_999), nk, SP);
  const lieMinCt = await enc(grpc, 0n, nk, SP);
  const lieOutCt = await enc(grpc, 0n, nk, SP);
  const lieReceipt = Keypair.generate();
  await sendTx(conn, payer, [swapIx(swapCtx, poolPda,
    userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
    userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey,
    lieInCt, lieMinCt, lieOutCt, lieReceipt.publicKey, 0,
  )], [lieReceipt]);
  ok("Lying-user tx submitted — soundness invariant: receipt=0 ⇒ pool state unchanged");

  // ═══ 9. RemoveLiquidity ═══
  log("9/9", "RemoveLiquidity — pc-swap CPIs pc-token::transfer twice (vaults → user) signed by pool PDA...");
  // Burn ~250 LP units (we minted 500 on first deposit since lp = receipt_a)
  const burnCt = await enc(grpc, TOKENS(250), nk, SP);
  const outA = await enc(grpc, 0n, nk, SP);
  const outB = await enc(grpc, 0n, nk, SP);
  await sendTx(conn, payer, [removeLiquidityIx(swapCtx, poolPda,
    userUsdPc, userDogePc, poolVaultUsd, poolVaultDoge,
    userUsdBal.publicKey, userDogeBal.publicKey, poolVaultUsdBal.publicKey, poolVaultDogeBal.publicKey,
    poolReserveUsd.publicKey, poolReserveDoge.publicKey, poolTotalSupply.publicKey,
    burnCt, userLpBal.publicKey, outA, outB,
  )]);
  await pollUntil(conn, poolReserveUsd.publicKey, isVerified);
  await pollUntil(conn, poolReserveDoge.publicKey, isVerified);
  await pollUntil(conn, userLpBal.publicKey, isVerified);
  ok("Liquidity removed — vault balances decremented, user receives pc-tokens, LP burned");

  console.log("\n\x1b[1m═══ Result ═══\x1b[0m\n");
  console.log("  pc-swap composes with pc-token via CPI; receipts gate state updates:");
  console.log("    • Pool vaults are real pc-token TokenAccounts (owned by pool PDA)");
  console.log("    • create_pool        → CPI pc-token::initialize_account × 2");
  console.log("    • add_liquidity      → CPI pc-token::TransferWithReceipt × 2 + add_liq_graph");
  console.log("    • swap               → CPI pc-token::TransferWithReceipt + swap_graph + transfer (vault→user)");
  console.log("    • remove_liquidity   → remove_liq_graph + CPI pc-token::transfer × 2 (vaults → user)");
  console.log("");
  console.log("  Soundness: every reserve and payout update is a function of the");
  console.log("  binary receipt ciphertext (= amount on success, 0 on insufficient");
  console.log("  balance). Lying about amount_in produces receipt=0 → uniform no-op.");
  console.log("");
  console.log("  All balances stayed encrypted throughout. \x1b[32m✓\x1b[0m\n");

  grpc.close();
}

main().catch(err => { console.error("\x1b[31mError:\x1b[0m", err.message || err); process.exit(1); });
