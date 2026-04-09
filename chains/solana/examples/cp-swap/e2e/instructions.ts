/**
 * Instruction builders for CP-Swap.
 */
import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import type { EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { encryptCpiAccounts } from "../../_shared/encrypt-setup.ts";
import { pda } from "../../_shared/helpers.ts";

export interface SwapContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function deriveSwapPdas(programId: PublicKey) {
  const [cpiAuthority, cpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], programId);
  return { cpiAuthority, cpiBump };
}

export function derivePoolPda(programId: PublicKey, mintA: PublicKey, mintB: PublicKey): [PublicKey, number] {
  return pda([Buffer.from("cp_pool"), mintA.toBuffer(), mintB.toBuffer()], programId);
}

function encAccts(ctx: SwapContext) {
  return encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer);
}

export function createPoolIx(
  ctx: SwapContext, poolPda: PublicKey, poolBump: number,
  mintA: PublicKey, mintB: PublicKey,
  raCtx: PublicKey, rbCt: PublicKey, tsCt: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([0, poolBump, ctx.cpiBump]),
    keys: [
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: mintA, isSigner: false, isWritable: false },
      { pubkey: mintB, isSigner: false, isWritable: false },
      { pubkey: raCtx, isSigner: true, isWritable: true },
      { pubkey: rbCt, isSigner: true, isWritable: true },
      { pubkey: tsCt, isSigner: true, isWritable: true },
      ...encAccts(ctx),
    ],
  });
}

export function swapIx(
  ctx: SwapContext, pool: PublicKey,
  rIn: PublicKey, rOut: PublicKey,
  amtIn: PublicKey, minOut: PublicKey, amtOut: PublicKey, dir: number,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([1, ctx.cpiBump, dir]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: rIn, isSigner: false, isWritable: true },
      { pubkey: rOut, isSigner: false, isWritable: true },
      { pubkey: amtIn, isSigner: false, isWritable: true },
      { pubkey: minOut, isSigner: false, isWritable: true },
      { pubkey: amtOut, isSigner: false, isWritable: true },
      ...encAccts(ctx),
    ],
  });
}

export function addLiquidityIx(
  ctx: SwapContext, pool: PublicKey,
  rA: PublicKey, rB: PublicKey, ts: PublicKey,
  amtA: PublicKey, amtB: PublicKey, lpOut: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([2, ctx.cpiBump]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: rA, isSigner: false, isWritable: true },
      { pubkey: rB, isSigner: false, isWritable: true },
      { pubkey: ts, isSigner: false, isWritable: true },
      { pubkey: amtA, isSigner: false, isWritable: true },
      { pubkey: amtB, isSigner: false, isWritable: true },
      { pubkey: lpOut, isSigner: false, isWritable: true },
      ...encAccts(ctx),
    ],
  });
}

export function requestDecryptIx(ctx: SwapContext, req: PublicKey, ct: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([3, ctx.cpiBump]),
    keys: [
      { pubkey: req, isSigner: true, isWritable: true },
      { pubkey: ct, isSigner: false, isWritable: false },
      ...encAccts(ctx).map(a => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a),
    ],
  });
}

export function removeLiquidityIx(
  ctx: SwapContext, pool: PublicKey,
  rA: PublicKey, rB: PublicKey, ts: PublicKey,
  burnCt: PublicKey, outA: PublicKey, outB: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([4, ctx.cpiBump]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: rA, isSigner: false, isWritable: true },
      { pubkey: rB, isSigner: false, isWritable: true },
      { pubkey: ts, isSigner: false, isWritable: true },
      { pubkey: burnCt, isSigner: false, isWritable: true },
      { pubkey: outA, isSigner: false, isWritable: true },
      { pubkey: outB, isSigner: false, isWritable: true },
      ...encAccts(ctx),
    ],
  });
}
