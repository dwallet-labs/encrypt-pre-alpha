/**
 * Instruction builders for the encrypted ACL program.
 */

import {
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";

import type { EncryptAccounts } from "../../../_shared/encrypt-setup.ts";
import { encryptCpiAccounts } from "../../../_shared/encrypt-setup.ts";
import { pda } from "../../../_shared/helpers.ts";

export interface AclContext {
  programId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  resourcePda: PublicKey;
  resourceBump: number;
  resourceId: Buffer;
  cpiAuthority: PublicKey;
  cpiBump: number;
}

export function deriveAclPdas(programId: PublicKey) {
  const { Keypair } = require("@solana/web3.js");
  const resourceId = Buffer.from(Keypair.generate().publicKey.toBytes());
  const [resourcePda, resourceBump] = pda([Buffer.from("resource"), resourceId], programId);
  const [cpiAuthority, cpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], programId);
  return { resourceId, resourcePda, resourceBump, cpiAuthority, cpiBump };
}

/** Instruction 0: create_resource */
export function createResourceIx(
  ctx: AclContext,
  permsCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.concat([
      Buffer.from([0, ctx.resourceBump, ctx.cpiBump]),
      ctx.resourceId,
    ]),
    keys: [
      { pubkey: ctx.resourcePda, isSigner: false, isWritable: true },
      { pubkey: ctx.payer, isSigner: true, isWritable: false },
      { pubkey: permsCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}

/** Instruction 1 (grant) or 2 (revoke): admin modifies permissions */
export function modifyPermissionIx(
  ctx: AclContext,
  admin: PublicKey,
  permsCt: PublicKey,
  inputCt: PublicKey,
  opcode: 1 | 2
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([opcode, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.resourcePda, isSigner: false, isWritable: true },
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: permsCt, isSigner: false, isWritable: true },
      { pubkey: inputCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 3: check_permission */
export function checkPermissionIx(
  ctx: AclContext,
  checkPda: PublicKey,
  checkBump: number,
  checker: PublicKey,
  permsCt: PublicKey,
  bitCt: PublicKey,
  resultCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([3, checkBump, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.resourcePda, isSigner: false, isWritable: false },
      { pubkey: checkPda, isSigner: false, isWritable: true },
      { pubkey: checker, isSigner: true, isWritable: false },
      { pubkey: permsCt, isSigner: false, isWritable: true },
      { pubkey: bitCt, isSigner: false, isWritable: true },
      { pubkey: resultCt, isSigner: true, isWritable: true },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer),
    ],
  });
}

/** Instruction 4: request_check_decryption */
export function requestCheckDecryptionIx(
  ctx: AclContext,
  checkPda: PublicKey,
  requestAcct: PublicKey,
  resultCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([4, ctx.cpiBump]),
    keys: [
      { pubkey: checkPda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: resultCt, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}

/** Instruction 5: reveal_check */
export function revealCheckIx(
  programId: PublicKey,
  checkPda: PublicKey,
  requestAcct: PublicKey,
  checker: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    data: Buffer.from([5]),
    keys: [
      { pubkey: checkPda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: false, isWritable: false },
      { pubkey: checker, isSigner: true, isWritable: false },
    ],
  });
}

/** Instruction 6: request_permissions_decryption */
export function requestPermissionsDecryptionIx(
  ctx: AclContext,
  requestAcct: PublicKey,
  permsCt: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([6, ctx.cpiBump]),
    keys: [
      { pubkey: ctx.resourcePda, isSigner: false, isWritable: true },
      { pubkey: requestAcct, isSigner: true, isWritable: true },
      { pubkey: permsCt, isSigner: false, isWritable: false },
      ...encryptCpiAccounts(ctx.enc, ctx.programId, ctx.cpiAuthority, ctx.payer).map(
        (a) => a.pubkey.equals(ctx.enc.configPda) ? { ...a, isWritable: false } : a
      ),
    ],
  });
}
