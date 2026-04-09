/**
 * Instruction builders for the CP-Token program.
 */

import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";

import type { EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { encryptCpiAccounts } from "../../_shared/encrypt-setup.ts";
import { pda } from "../../_shared/helpers.ts";

export interface CpTokenContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function deriveCpTokenPdas(programId: PublicKey, authority: PublicKey) {
  const [cpiAuthority, cpiBump] = pda(
    [Buffer.from("__encrypt_cpi_authority")],
    programId
  );
  return { cpiAuthority, cpiBump };
}

export function deriveMintPda(
  programId: PublicKey,
  authority: PublicKey
): [PublicKey, number] {
  return pda([Buffer.from("cp_mint"), authority.toBuffer()], programId);
}

export function deriveAccountPda(
  programId: PublicKey,
  mint: PublicKey,
  owner: PublicKey
): [PublicKey, number] {
  return pda(
    [Buffer.from("cp_account"), mint.toBuffer(), owner.toBuffer()],
    programId
  );
}

/** Instruction 0: InitializeMint */
export function initializeMintIx(
  ctx: CpTokenContext,
  mintPda: PublicKey,
  mintBump: number,
  decimals: number,
  mintAuthority: PublicKey,
  freezeAuthority?: PublicKey
): TransactionInstruction {
  const data = Buffer.alloc(freezeAuthority ? 67 : 35);
  data[0] = 0; // disc
  data[1] = mintBump;
  data[2] = decimals;
  mintAuthority.toBuffer().copy(data, 3);
  data[35] = freezeAuthority ? 1 : 0;
  if (freezeAuthority) {
    freezeAuthority.toBuffer().copy(data, 36);
  }

  return new TransactionInstruction({
    programId: ctx.programId,
    data,
    keys: [
      { pubkey: mintPda, isSigner: false, isWritable: true },
      { pubkey: mintAuthority, isSigner: true, isWritable: false },
      { pubkey: ctx.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
}

/** Instruction 1: InitializeAccount */
export function initializeAccountIx(
  ctx: CpTokenContext,
  accountPda: PublicKey,
  accountBump: number,
  mint: PublicKey,
  owner: PublicKey,
  balanceCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([1, accountBump, ctx.cpiBump]),
    keys: [
      { pubkey: accountPda, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: balanceCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(
        ctx.enc,
        ctx.programId,
        ctx.cpiAuthority,
        ctx.payer
      ),
    ],
  });
}

/** Instruction 7: MintTo (amount_ct is client-encrypted via gRPC) */
export function mintToIx(
  ctx: CpTokenContext,
  mint: PublicKey,
  tokenAccount: PublicKey,
  balanceCt: PublicKey,
  amountCt: PublicKey,
  authority: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([7, ctx.cpiBump]),
    keys: [
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: balanceCt, isSigner: false, isWritable: true },
      { pubkey: amountCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(
        ctx.enc,
        ctx.programId,
        ctx.cpiAuthority,
        authority
      ),
    ],
  });
}

/** Instruction 3: Transfer (amount_ct is client-encrypted via gRPC) */
export function transferIx(
  ctx: CpTokenContext,
  fromAccount: PublicKey,
  toAccount: PublicKey,
  fromBalanceCt: PublicKey,
  toBalanceCt: PublicKey,
  amountCt: PublicKey,
  owner: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([3, ctx.cpiBump]),
    keys: [
      { pubkey: fromAccount, isSigner: false, isWritable: false },
      { pubkey: toAccount, isSigner: false, isWritable: false },
      { pubkey: fromBalanceCt, isSigner: false, isWritable: true },
      { pubkey: toBalanceCt, isSigner: false, isWritable: true },
      { pubkey: amountCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(
        ctx.enc,
        ctx.programId,
        ctx.cpiAuthority,
        owner
      ),
    ],
  });
}

/** Instruction 21: RequestDecrypt */
export function requestDecryptIx(
  ctx: CpTokenContext,
  tokenAccount: PublicKey,
  requestAcct: PublicKey,
  ciphertext: PublicKey,
  owner: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([21, ctx.cpiBump]),
    keys: [
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: ciphertext, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(
        ctx.enc,
        ctx.programId,
        ctx.cpiAuthority,
        owner
      ).map((a) =>
        a.pubkey.equals(ctx.enc.configPda)
          ? { ...a, isWritable: false }
          : a
      ),
    ],
  });
}

/** Instruction 22: RevealBalance */
export function revealBalanceIx(
  programId: PublicKey,
  tokenAccount: PublicKey,
  requestAcct: PublicKey,
  owner: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    data: Buffer.from([22]),
    keys: [
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
  });
}
