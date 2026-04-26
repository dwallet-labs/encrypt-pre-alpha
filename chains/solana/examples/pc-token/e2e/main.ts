#!/usr/bin/env bun
/**
 * PC-Token E2E — USDC → pcUSDC → USDC (fully confidential)
 *
 * Balances are NEVER revealed on-chain. The only plaintext that appears
 * is the withdrawal amount on a temporary receipt (closed immediately).
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <PC_TOKEN_PROGRAM_ID>
 */
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
import * as fs from "fs";
import { type EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pda, pollUntil, isVerified, isDecrypted, mockCiphertext } from "../../_shared/helpers.ts";
import { createEncryptClient, Chain } from "../../../clients/typescript/src/grpc.ts";
import { type PcTokenContext, derivePcTokenPdas, deriveMintPda, deriveAccountPda, deriveVaultPda, deriveReceiptPda, initializeMintIx, initializeAccountIx, initializeVaultIx, transferIx, wrapIx, unwrapBurnIx, unwrapDecryptIx, unwrapCompleteIx } from "./instructions.ts";
import { TOKEN_PROGRAM_ID, createSplMint, createSplTokenAccount, splMintToIx, readSplBalance } from "./spl-helpers.ts";

const RPC = "https://api.devnet.solana.com";
const FHE64 = 4; const DECIMALS = 6;
const USDC = (n: number) => BigInt(n) * 1_000_000n;

const [eArg, tArg] = process.argv.slice(2);
if (!eArg || !tArg) { console.error("Usage: bun main.ts <ENCRYPT_ID> <PC_TOKEN_ID>"); process.exit(1); }
const EP = new PublicKey(eArg), TP = new PublicKey(tArg);
const conn = new Connection(RPC, "confirmed");
const payer = (() => { try { return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(
  fs.readFileSync(process.env.KEYPAIR_PATH ?? `${process.env.HOME}/.config/solana/devnet-admin.json`, "utf-8")))); } catch { return Keypair.generate(); } })();

async function enc(grpc: any, v: bigint, nk: Buffer): Promise<PublicKey> {
  const { ciphertextIdentifiers } = await grpc.createInput({ chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(v, FHE64), fheType: FHE64 }],
    authorized: TP.toBytes(), networkEncryptionPublicKey: nk });
  return new PublicKey(ciphertextIdentifiers[0]);
}

async function doUnwrap(
  grpc: any, ctx: PcTokenContext, pcMint: PublicKey, vault: PublicKey,
  vaultAta: PublicKey, tokenAccount: PublicKey, balanceCt: PublicKey,
  userAta: PublicKey, owner: Keypair, amount: bigint, nk: Buffer, label: string
) {
  log(label, `Unwrap burn ${Number(amount)/1e6} pcUSDC...`);
  const amountCt = await enc(grpc, amount, nk);
  const burnedCt = await enc(grpc, 0n, nk);
  const [receiptPda, receiptBump] = deriveReceiptPda(TP, burnedCt);

  await sendTx(conn, payer, [
    unwrapBurnIx(ctx, vault, tokenAccount, receiptPda, receiptBump,
      balanceCt, amountCt, burnedCt, owner.publicKey, amount),
  ], [owner]);
  await pollUntil(conn, balanceCt, isVerified, 120_000);
  await pollUntil(conn, burnedCt, isVerified, 120_000);
  ok("Burn committed");

  log(label, "Decrypting burned amount...");
  const decReq = Keypair.generate();
  await sendTx(conn, payer, [
    unwrapDecryptIx(ctx, receiptPda, decReq.publicKey, burnedCt, owner.publicKey),
  ], [owner, decReq]);
  await pollUntil(conn, decReq.publicKey, isDecrypted, 120_000);
  ok("Decrypted");

  log(label, "Releasing USDC...");
  await sendTx(conn, payer, [
    unwrapCompleteIx(TP, receiptPda, vault, pcMint,
      decReq.publicKey, vaultAta, userAta, owner.publicKey, payer.publicKey),
  ], [owner]);
  ok("USDC released, receipt closed");
}

async function main() {
  console.log("\n\x1b[1m═══ PC-Token E2E: USDC → pcUSDC → USDC ═══\x1b[0m\n");
  console.log("  Balances are NEVER revealed on-chain.\n");

  const grpc = createEncryptClient();
  ok(`Payer: ${payer.publicKey.toBase58()}, Balance: ${(await conn.getBalance(payer.publicKey))/1e9} SOL`);

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

  const encA: EncryptAccounts = { encryptProgram:EP, configPda:cfgPda, eventAuthority:evtAuth, depositPda:depPda, networkKeyPda:nkPda, networkKey:nk };
  const { cpiAuthority, cpiBump } = derivePcTokenPdas(TP, payer.publicKey);
  const ctx: PcTokenContext = { programId:TP, enc:encA, payer:payer.publicKey, cpiAuthority, cpiBump };

  const alice = Keypair.generate(), bob = Keypair.generate(), mark = Keypair.generate();
  await sendAndConfirmTransaction(conn, new Transaction().add(
    SystemProgram.transfer({fromPubkey:payer.publicKey,toPubkey:alice.publicKey,lamports:0.1e9}),
    SystemProgram.transfer({fromPubkey:payer.publicKey,toPubkey:bob.publicKey,lamports:0.1e9}),
    SystemProgram.transfer({fromPubkey:payer.publicKey,toPubkey:mark.publicKey,lamports:0.1e9})), [payer]);

  log("1/9", "Creating mock USDC...");
  const usdcMint = await createSplMint(conn, payer, DECIMALS, payer.publicKey);
  const aliceAta = await createSplTokenAccount(conn, payer, usdcMint.publicKey, alice.publicKey);
  const bobAta = await createSplTokenAccount(conn, payer, usdcMint.publicKey, bob.publicKey);
  const markAta = await createSplTokenAccount(conn, payer, usdcMint.publicKey, mark.publicKey);
  await sendTx(conn, payer, [splMintToIx(usdcMint.publicKey, aliceAta.publicKey, payer.publicKey, USDC(10))]);
  val("Alice USDC", "10");

  log("2/9", "Creating pcUSDC...");
  const mintAuth = Keypair.generate();
  const [pcMint, pcMintBump] = deriveMintPda(TP, mintAuth.publicKey);
  await sendTx(conn, payer, [initializeMintIx(ctx, pcMint, pcMintBump, DECIMALS, mintAuth.publicKey)], [mintAuth]);
  const [vaultPda, vaultBump] = deriveVaultPda(TP, pcMint);
  await sendTx(conn, payer, [initializeVaultIx(ctx, vaultPda, vaultBump, pcMint, usdcMint.publicKey)]);
  const vaultAta = await createSplTokenAccount(conn, payer, usdcMint.publicKey, vaultPda);
  const [aliceCp, aliceBump] = deriveAccountPda(TP, pcMint, alice.publicKey);
  const aliceBal = Keypair.generate();
  await sendTx(conn, payer, [initializeAccountIx(ctx, aliceCp, aliceBump, pcMint, alice.publicKey, aliceBal.publicKey)], [aliceBal]);
  const [bobCp, bobBump] = deriveAccountPda(TP, pcMint, bob.publicKey);
  const bobBal = Keypair.generate();
  await sendTx(conn, payer, [initializeAccountIx(ctx, bobCp, bobBump, pcMint, bob.publicKey, bobBal.publicKey)], [bobBal]);
  const [markCp, markBump] = deriveAccountPda(TP, pcMint, mark.publicKey);
  const markBal = Keypair.generate();
  await sendTx(conn, payer, [initializeAccountIx(ctx, markCp, markBump, pcMint, mark.publicKey, markBal.publicKey)], [markBal]);
  ok("Setup complete");

  log("3/9", "Alice wraps 10 USDC → 10 pcUSDC...");
  const wrapCt = await enc(grpc, USDC(10), nk);
  await sendTx(conn, payer, [wrapIx(ctx, vaultPda, aliceCp, aliceAta.publicKey, vaultAta.publicKey, aliceBal.publicKey, wrapCt, alice.publicKey, USDC(10))], [alice]);
  await pollUntil(conn, aliceBal.publicKey, isVerified, 120_000);
  ok("Wrapped"); val("Vault", `${Number(await readSplBalance(conn, vaultAta.publicKey))/1e6} USDC`);

  log("4/9", "Alice → Bob: 5 pcUSDC...");
  const x1 = await enc(grpc, USDC(5), nk);
  await sendTx(conn, payer, [transferIx(ctx, aliceCp, bobCp, aliceBal.publicKey, bobBal.publicKey, x1, alice.publicKey)], [alice]);
  await pollUntil(conn, aliceBal.publicKey, isVerified, 120_000);
  await pollUntil(conn, bobBal.publicKey, isVerified, 120_000);
  ok("Done");

  await doUnwrap(grpc, ctx, pcMint, vaultPda, vaultAta.publicKey, bobCp, bobBal.publicKey, bobAta.publicKey, bob, USDC(5), nk, "5/9");
  val("Bob USDC", `${Number(await readSplBalance(conn, bobAta.publicKey))/1e6}`);

  log("6/9", "Alice → Mark: 3 pcUSDC...");
  const x2 = await enc(grpc, USDC(3), nk);
  await sendTx(conn, payer, [transferIx(ctx, aliceCp, markCp, aliceBal.publicKey, markBal.publicKey, x2, alice.publicKey)], [alice]);
  await pollUntil(conn, aliceBal.publicKey, isVerified, 120_000);
  await pollUntil(conn, markBal.publicKey, isVerified, 120_000);
  ok("Done");

  await doUnwrap(grpc, ctx, pcMint, vaultPda, vaultAta.publicKey, markCp, markBal.publicKey, markAta.publicKey, mark, USDC(2), nk, "7/9");
  val("Mark USDC", `${Number(await readSplBalance(conn, markAta.publicKey))/1e6}`);

  await doUnwrap(grpc, ctx, pcMint, vaultPda, vaultAta.publicKey, aliceCp, aliceBal.publicKey, aliceAta.publicKey, alice, USDC(1), nk, "8/9");
  val("Alice USDC", `${Number(await readSplBalance(conn, aliceAta.publicKey))/1e6}`);

  const aU = await readSplBalance(conn, aliceAta.publicKey);
  const bU = await readSplBalance(conn, bobAta.publicKey);
  const mU = await readSplBalance(conn, markAta.publicKey);
  const vU = await readSplBalance(conn, vaultAta.publicKey);

  console.log("\n\x1b[1m═══ Final State ═══\x1b[0m\n");
  val("  Alice", `${Number(aU)/1e6} USDC + 1 pcUSDC (balance hidden)`);
  val("  Bob  ", `${Number(bU)/1e6} USDC`);
  val("  Mark ", `${Number(mU)/1e6} USDC + 1 pcUSDC (balance hidden)`);
  val("  Vault", `${Number(vU)/1e6} USDC`);
  console.log(aU===USDC(1) && bU===USDC(5) && mU===USDC(2) && vU===USDC(2)
    ? `\n  \x1b[32m✓ All correct! 10 USDC conserved. No balance ever revealed on-chain.\x1b[0m\n`
    : `\n  \x1b[31m✗ Balance mismatch!\x1b[0m\n`);
  grpc.close();
}

main().catch(e => { console.error("\x1b[31mError:\x1b[0m", e.message || e); process.exit(1); });
