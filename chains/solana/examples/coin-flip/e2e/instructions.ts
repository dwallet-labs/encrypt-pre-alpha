/**
 * Instruction builders for the encrypted coin flip program.
 */

import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";

import type { EncryptAccounts } from "../../../_shared/encrypt-setup.ts";
import { encryptCpiAccounts } from "../../../_shared/encrypt-setup.ts";
import { pda } from "../../../_shared/helpers.ts";

export interface CoinFlipContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  gamePda: PublicKey;
  gameBump: number;
  gameId: Buffer;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function deriveCoinFlipPdas(programId: PublicKey) {
  const { Keypair } = require("@solana/web3.js");
  const gameId = Buffer.from(Keypair.generate().publicKey.toBytes());
  const [gamePda, gameBump] = pda([Buffer.from("game"), gameId], programId);
  const [cpiAuthority, cpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], programId);
  return { gameId, gamePda, gameBump, cpiAuthority, cpiBump };
}

/** Instruction 0: create_game */
export function createGameIx(
  ctx: CoinFlipContext,
  commitACt: PublicKey,
  resultCt: PublicKey,
  betLamports: bigint = 0n
): TransactionInstruction {
  const betBuf = Buffer.alloc(8);
  betBuf.writeBigUInt64LE(betLamports);

  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.concat([
      Buffer.from([0, ctx.gameBump, ctx.cpiBump]),
      ctx.gameId,
      betBuf,
    ]),
    keys: [
      { pubkey: ctx.gamePda, isSigner: false, isWritable: true },
      { pubkey: ctx.payer, isSigner: true, isWritable: false },
      { pubkey: commitACt, isSigner: false, isWritable: false },
      { pubkey: resultCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}

/** Instruction 1: play */
export function playIx(
  ctx: CoinFlipContext,
  sideB: PublicKey,
  commitACt: PublicKey,
  commitBCt: PublicKey,
  resultCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([1, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.gamePda, isSigner: false, isWritable: true },
      { pubkey: sideB, isSigner: true, isWritable: true },
      { pubkey: commitACt, isSigner: false, isWritable: true },
      { pubkey: commitBCt, isSigner: false, isWritable: true },
      { pubkey: resultCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 2: request_result_decryption */
export function requestResultDecryptionIx(
  ctx: CoinFlipContext,
  requestAcct: PublicKey,
  resultCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([2, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.gamePda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: resultCt, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}

/** Instruction 3: reveal_result */
export function revealResultIx(
  programId: PublicKey,
  gamePda: PublicKey,
  requestAcct: PublicKey,
  caller: PublicKey,
  winner: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    data: Buffer.from([3]),
    keys: [
      { pubkey: gamePda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: false, isWritable: false },
      { pubkey: caller, isSigner: true, isWritable: false },
      { pubkey: winner, isSigner: false, isWritable: true },
    ],
  });
}

/** Instruction 4: cancel_game */
export function cancelGameIx(
  programId: PublicKey,
  gamePda: PublicKey,
  sideA: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    data: Buffer.from([4]),
    keys: [
      { pubkey: gamePda, isSigner: false, isWritable: true },
      { pubkey: sideA, isSigner: true, isWritable: true },
    ],
  });
}
