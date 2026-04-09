/**
 * Instruction builders for CP-Swap.
 */

import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";

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
  const [cpiAuthority, cpiBump] = pda(
    [Buffer.from("__encrypt_cpi_authority")],
    programId
  );
  return { cpiAuthority, cpiBump };
}

export function derivePoolPda(
  programId: PublicKey,
  mintA: PublicKey,
  mintB: PublicKey
): [PublicKey, number] {
  return pda(
    [Buffer.from("cp_pool"), mintA.toBuffer(), mintB.toBuffer()],
    programId
  );
}

/** Instruction 0: CreatePool */
export function createPoolIx(
  ctx: SwapContext,
  poolPda: PublicKey,
  poolBump: number,
  mintA: PublicKey,
  mintB: PublicKey,
  reserveACt: PublicKey,
  reserveBCt: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([0, poolBump, ctx.cpiBump]),
    keys: [
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: mintA, isSigner: false, isWritable: false },
      { pubkey: mintB, isSigner: false, isWritable: false },
      { pubkey: reserveACt, isSigner: true, isWritable: true },
      { pubkey: reserveBCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 1: Swap */
export function swapIx(
  ctx: SwapContext,
  pool: PublicKey,
  reserveInCt: PublicKey,
  reserveOutCt: PublicKey,
  amountInCt: PublicKey,
  minAmountOutCt: PublicKey,
  amountOutCt: PublicKey,
  direction: number,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([1, ctx.cpiBump, direction]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: reserveInCt, isSigner: false, isWritable: true },
      { pubkey: reserveOutCt, isSigner: false, isWritable: true },
      { pubkey: amountInCt, isSigner: false, isWritable: true },
      { pubkey: minAmountOutCt, isSigner: false, isWritable: true },
      { pubkey: amountOutCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 2: AddLiquidity */
export function addLiquidityIx(
  ctx: SwapContext,
  pool: PublicKey,
  reserveACt: PublicKey,
  reserveBCt: PublicKey,
  amountACt: PublicKey,
  amountBCt: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([2, ctx.cpiBump]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: reserveACt, isSigner: false, isWritable: true },
      { pubkey: reserveBCt, isSigner: false, isWritable: true },
      { pubkey: amountACt, isSigner: false, isWritable: true },
      { pubkey: amountBCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}
