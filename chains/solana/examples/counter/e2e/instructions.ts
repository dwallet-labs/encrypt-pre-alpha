/**
 * Instruction builders for the confidential counter program.
 */

import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";

import type { EncryptAccounts } from "../../../_shared/encrypt-setup.ts";
import { encryptCpiAccounts } from "../../../_shared/encrypt-setup.ts";
import { pda } from "../../../_shared/helpers.ts";

export interface CounterContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  counterPda: PublicKey;
  counterBump: number;
  counterId: Buffer;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function deriveCounterPdas(programId: PublicKey) {
  const counterId = Buffer.from(Keypair.generate().publicKey.toBytes());
  const [counterPda, counterBump] = pda([Buffer.from("counter"), counterId], programId);
  const [cpiAuthority, cpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], programId);
  return { counterId, counterPda, counterBump, cpiAuthority, cpiBump };
}

/** Instruction 0: create_counter */
export function createCounterIx(
  ctx: CounterContext,
  valueCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.concat([
      Buffer.from([0, ctx.counterBump, ctx.cpiBump]),
      ctx.counterId,
    ]),
    keys: [
      { pubkey: ctx.counterPda, isSigner: false, isWritable: true },
      { pubkey: ctx.payer, isSigner: true, isWritable: false },
      { pubkey: valueCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a, i) => (i === 0 ? { ...a, isWritable: false } : a) // encrypt_program readonly for create
      ),
    ],
  });
}

/** Instruction 1 (increment) or 2 (decrement) */
export function counterOpIx(
  ctx: CounterContext,
  valueCt: PublicKey,
  opcode: 1 | 2
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([opcode, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.counterPda, isSigner: false, isWritable: true },
      { pubkey: valueCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 3: request_value_decryption */
export function requestDecryptionIx(
  ctx: CounterContext,
  valueCt: PublicKey,
  requestAcct: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([3, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.counterPda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: valueCt, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}

/** Instruction 4: reveal_value */
export function revealValueIx(
  programId: PublicKey,
  counterPda: PublicKey,
  requestAcct: PublicKey,
  authority: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    data: Buffer.from([4]),
    keys: [
      { pubkey: counterPda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
  });
}
