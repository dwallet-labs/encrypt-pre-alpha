/**
 * Instruction builders for the PC-Token program.
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
import { TOKEN_PROGRAM_ID } from "./spl-helpers.ts";

export interface PcTokenContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function derivePcTokenPdas(programId: PublicKey, authority: PublicKey) {
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
  return pda([Buffer.from("pc_mint"), authority.toBuffer()], programId);
}

export function deriveAccountPda(
  programId: PublicKey,
  mint: PublicKey,
  owner: PublicKey
): [PublicKey, number] {
  return pda(
    [Buffer.from("pc_account"), mint.toBuffer(), owner.toBuffer()],
    programId
  );
}

/** Instruction 0: InitializeMint */
export function initializeMintIx(
  ctx: PcTokenContext,
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
  ctx: PcTokenContext,
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
  ctx: PcTokenContext,
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
  ctx: PcTokenContext,
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

// ── Vault / Wrap / Unwrap ──

export function deriveVaultPda(
  programId: PublicKey,
  pcMint: PublicKey
): [PublicKey, number] {
  return pda([Buffer.from("pc_vault"), pcMint.toBuffer()], programId);
}


/** Instruction 23: InitializeVault */
export function initializeVaultIx(
  ctx: PcTokenContext,
  vaultPda: PublicKey,
  vaultBump: number,
  pcMint: PublicKey,
  splMint: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([23, vaultBump]),
    keys: [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: pcMint, isSigner: false, isWritable: false },
      { pubkey: splMint, isSigner: false, isWritable: false },
      { pubkey: ctx.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
}

/** Instruction 30: Wrap (deposit SPL → mint pcToken) */
export function wrapIx(
  ctx: PcTokenContext,
  vault: PublicKey,
  tokenAccount: PublicKey,
  userAta: PublicKey,
  vaultAta: PublicKey,
  balanceCt: PublicKey,
  amountCt: PublicKey,
  owner: PublicKey,
  amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(10);
  data[0] = 30; // disc
  data[1] = ctx.cpiBump;
  data.writeBigUInt64LE(amount, 2);

  return new TransactionInstruction({
    programId: ctx.programId,
    data,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: userAta, isSigner: false, isWritable: true },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: balanceCt, isSigner: false, isWritable: true },
      { pubkey: amountCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, owner),
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
  });
}

export function deriveReceiptPda(
  programId: PublicKey, burnedCt: PublicKey
): [PublicKey, number] {
  return pda([Buffer.from("pc_receipt"), burnedCt.toBuffer()], programId);
}

/** Instruction 31: UnwrapBurn */
export function unwrapBurnIx(
  ctx: PcTokenContext, vault: PublicKey, tokenAccount: PublicKey,
  receiptPda: PublicKey, receiptBump: number,
  balanceCt: PublicKey, amountCt: PublicKey, burnedCt: PublicKey,
  owner: PublicKey, amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(11);
  data[0] = 31; data[1] = receiptBump; data[2] = ctx.cpiBump;
  data.writeBigUInt64LE(amount, 3);
  return new TransactionInstruction({
    programId: ctx.programId, data,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: receiptPda, isSigner: false, isWritable: true },
      { pubkey: balanceCt, isSigner: false, isWritable: true },
      { pubkey: amountCt, isSigner: false, isWritable: true },
      { pubkey: burnedCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, owner),
    ],
  });
}

/** Instruction 32: UnwrapDecrypt */
export function unwrapDecryptIx(
  ctx: PcTokenContext, receipt: PublicKey,
  requestAcct: PublicKey, burnedCt: PublicKey, owner: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId, data: Buffer.from([32, ctx.cpiBump]),
    keys: [
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: burnedCt, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, owner)
        .map(a => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a),
    ],
  });
}

/** Instruction 33: UnwrapComplete */
export function unwrapCompleteIx(
  programId: PublicKey, receipt: PublicKey, vault: PublicKey,
  pcMint: PublicKey, requestAcct: PublicKey,
  vaultAta: PublicKey, userAta: PublicKey,
  owner: PublicKey, destination: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId, data: Buffer.from([33]),
    keys: [
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: pcMint, isSigner: false, isWritable: false },
      { pubkey: requestAcct, isSigner: false, isWritable: false },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: userAta, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
  });
}
