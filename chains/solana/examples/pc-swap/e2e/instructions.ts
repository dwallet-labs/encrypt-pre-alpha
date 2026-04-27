/**
 * Instruction builders for PC-Swap (composes with PC-Token via CPI).
 */
import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import type { EncryptAccounts } from "../../_shared/encrypt-setup.ts";
import { pda } from "../../_shared/helpers.ts";

export interface SwapContext {
  programId: PublicKey;
  pcTokenProgramId: PublicKey;
  enc: EncryptAccounts;
  payer: PublicKey;
  cpiAuthority: PublicKey;        // pc-swap CPI authority
  cpiBump: number;                // pc-swap CPI bump
  pcTokenCpiAuthority: PublicKey; // pc-token CPI authority (passed-through)
  pcTokenCpiBump: number;
}

export function deriveSwapPdas(programId: PublicKey, pcTokenProgramId: PublicKey) {
  const [cpiAuthority, cpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], programId);
  const [pcTokenCpiAuthority, pcTokenCpiBump] = pda([Buffer.from("__encrypt_cpi_authority")], pcTokenProgramId);
  return { cpiAuthority, cpiBump, pcTokenCpiAuthority, pcTokenCpiBump };
}

export function derivePoolPda(programId: PublicKey, mintA: PublicKey, mintB: PublicKey): [PublicKey, number] {
  return pda([Buffer.from("pc_pool"), mintA.toBuffer(), mintB.toBuffer()], programId);
}

export function deriveLpPda(programId: PublicKey, pool: PublicKey, owner: PublicKey): [PublicKey, number] {
  return pda([Buffer.from("pc_lp"), pool.toBuffer(), owner.toBuffer()], programId);
}

/** Account layout shared by every pc-swap instruction that CPIs into encrypt + pc-token. */
function swapEncryptAndTokenAccounts(ctx: SwapContext) {
  return [
    { pubkey: ctx.enc.encryptProgram, isSigner: false, isWritable: false },
    { pubkey: ctx.enc.configPda, isSigner: false, isWritable: true },
    { pubkey: ctx.enc.depositPda, isSigner: false, isWritable: true },
    { pubkey: ctx.cpiAuthority, isSigner: false, isWritable: false },     // pc-swap CPI auth
    { pubkey: ctx.programId, isSigner: false, isWritable: false },        // caller = pc-swap
    { pubkey: ctx.pcTokenCpiAuthority, isSigner: false, isWritable: false }, // pc-token CPI auth
    { pubkey: ctx.pcTokenProgramId, isSigner: false, isWritable: false }, // pc-token program (also caller for pc-token's encrypt CPI)
    { pubkey: ctx.enc.networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: ctx.payer, isSigner: true, isWritable: true },
    { pubkey: ctx.enc.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}

/** 0: CreatePool — creates pool PDA and CPIs pc-token::initialize_account for both vaults. */
export function createPoolIx(
  ctx: SwapContext,
  poolPda: PublicKey, poolBump: number,
  mintA: PublicKey, mintB: PublicKey,
  vaultA: PublicKey, vaultABump: number,
  vaultB: PublicKey, vaultBBump: number,
  vaultABalCt: PublicKey, vaultBBalCt: PublicKey,
  reserveACt: PublicKey, reserveBCt: PublicKey, totalSupplyCt: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([0, poolBump, vaultABump, vaultBBump, ctx.cpiBump, ctx.pcTokenCpiBump, 0]),
    keys: [
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: mintA, isSigner: false, isWritable: false },
      { pubkey: mintB, isSigner: false, isWritable: false },
      { pubkey: vaultA, isSigner: false, isWritable: true },
      { pubkey: vaultB, isSigner: false, isWritable: true },
      { pubkey: vaultABalCt, isSigner: true, isWritable: true },
      { pubkey: vaultBBalCt, isSigner: true, isWritable: true },
      { pubkey: reserveACt, isSigner: true, isWritable: true },
      { pubkey: reserveBCt, isSigner: true, isWritable: true },
      { pubkey: totalSupplyCt, isSigner: true, isWritable: true },
      ...swapEncryptAndTokenAccounts(ctx),
    ],
  });
}

/** 5: CreateLpPosition */
export function createLpPositionIx(
  ctx: SwapContext, pool: PublicKey, owner: PublicKey, balanceCt: PublicKey,
): TransactionInstruction {
  const [lpPda, lpBump] = deriveLpPda(ctx.programId, pool, owner);
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([5, lpBump, ctx.cpiBump]),
    keys: [
      { pubkey: lpPda, isSigner: false, isWritable: true },
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: balanceCt, isSigner: true, isWritable: true },
      { pubkey: ctx.enc.encryptProgram, isSigner: false, isWritable: false },
      { pubkey: ctx.enc.configPda, isSigner: false, isWritable: true },
      { pubkey: ctx.enc.depositPda, isSigner: false, isWritable: true },
      { pubkey: ctx.cpiAuthority, isSigner: false, isWritable: false },
      { pubkey: ctx.programId, isSigner: false, isWritable: false },
      { pubkey: ctx.enc.networkKeyPda, isSigner: false, isWritable: false },
      { pubkey: ctx.payer, isSigner: true, isWritable: true },
      { pubkey: ctx.enc.eventAuthority, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
}

/** 1: Swap. direction=0 → A→B, direction=1 → B→A.
 *  receiptCt: fresh keypair, signs the tx — pc-swap CPIs into
 *  pc-token::TransferWithReceipt(disc 22) which creates this account. */
export function swapIx(
  ctx: SwapContext, pool: PublicKey,
  userInAcct: PublicKey, userOutAcct: PublicKey,
  vaultInAcct: PublicKey, vaultOutAcct: PublicKey,
  userInBalCt: PublicKey, userOutBalCt: PublicKey,
  vaultInBalCt: PublicKey, vaultOutBalCt: PublicKey,
  reserveInCt: PublicKey, reserveOutCt: PublicKey,
  amtInCt: PublicKey, minOutCt: PublicKey, amtOutCt: PublicKey,
  receiptCt: PublicKey,
  direction: number,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([1, ctx.cpiBump, ctx.pcTokenCpiBump, direction]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userInAcct, isSigner: false, isWritable: true },
      { pubkey: userOutAcct, isSigner: false, isWritable: true },
      { pubkey: vaultInAcct, isSigner: false, isWritable: true },
      { pubkey: vaultOutAcct, isSigner: false, isWritable: true },
      { pubkey: userInBalCt, isSigner: false, isWritable: true },
      { pubkey: userOutBalCt, isSigner: false, isWritable: true },
      { pubkey: vaultInBalCt, isSigner: false, isWritable: true },
      { pubkey: vaultOutBalCt, isSigner: false, isWritable: true },
      { pubkey: reserveInCt, isSigner: false, isWritable: true },
      { pubkey: reserveOutCt, isSigner: false, isWritable: true },
      { pubkey: amtInCt, isSigner: false, isWritable: true },
      { pubkey: minOutCt, isSigner: false, isWritable: true },
      { pubkey: amtOutCt, isSigner: false, isWritable: true },
      { pubkey: receiptCt, isSigner: true, isWritable: true },
      ...swapEncryptAndTokenAccounts(ctx),
    ],
  });
}

/** 2: AddLiquidity — two TransferWithReceipt CPIs (one per side); the
 *  graph reads both receipts as the trusted deposit amounts.
 *  receiptACt / receiptBCt: fresh keypairs, sign the tx. */
export function addLiquidityIx(
  ctx: SwapContext, pool: PublicKey,
  userAAcct: PublicKey, userBAcct: PublicKey,
  vaultAAcct: PublicKey, vaultBAcct: PublicKey,
  userABalCt: PublicKey, userBBalCt: PublicKey,
  vaultABalCt: PublicKey, vaultBBalCt: PublicKey,
  reserveACt: PublicKey, reserveBCt: PublicKey, totalSupplyCt: PublicKey,
  amtACt: PublicKey, amtBCt: PublicKey, userLpCt: PublicKey,
  receiptACt: PublicKey, receiptBCt: PublicKey,
): TransactionInstruction {
  const [lpPda] = deriveLpPda(ctx.programId, pool, ctx.payer);
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([2, ctx.cpiBump, ctx.pcTokenCpiBump]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: lpPda, isSigner: false, isWritable: false },
      { pubkey: userAAcct, isSigner: false, isWritable: true },
      { pubkey: userBAcct, isSigner: false, isWritable: true },
      { pubkey: vaultAAcct, isSigner: false, isWritable: true },
      { pubkey: vaultBAcct, isSigner: false, isWritable: true },
      { pubkey: userABalCt, isSigner: false, isWritable: true },
      { pubkey: userBBalCt, isSigner: false, isWritable: true },
      { pubkey: vaultABalCt, isSigner: false, isWritable: true },
      { pubkey: vaultBBalCt, isSigner: false, isWritable: true },
      { pubkey: reserveACt, isSigner: false, isWritable: true },
      { pubkey: reserveBCt, isSigner: false, isWritable: true },
      { pubkey: totalSupplyCt, isSigner: false, isWritable: true },
      { pubkey: amtACt, isSigner: false, isWritable: true },
      { pubkey: amtBCt, isSigner: false, isWritable: true },
      { pubkey: userLpCt, isSigner: false, isWritable: true },
      { pubkey: receiptACt, isSigner: true, isWritable: true },
      { pubkey: receiptBCt, isSigner: true, isWritable: true },
      ...swapEncryptAndTokenAccounts(ctx),
    ],
  });
}

/** 4: RemoveLiquidity — burn LP, withdraw proportional reserves via CPI from vaults. */
export function removeLiquidityIx(
  ctx: SwapContext, pool: PublicKey,
  userAAcct: PublicKey, userBAcct: PublicKey,
  vaultAAcct: PublicKey, vaultBAcct: PublicKey,
  userABalCt: PublicKey, userBBalCt: PublicKey,
  vaultABalCt: PublicKey, vaultBBalCt: PublicKey,
  reserveACt: PublicKey, reserveBCt: PublicKey, totalSupplyCt: PublicKey,
  burnCt: PublicKey, userLpCt: PublicKey, outACt: PublicKey, outBCt: PublicKey,
): TransactionInstruction {
  const [lpPda] = deriveLpPda(ctx.programId, pool, ctx.payer);
  return new TransactionInstruction({
    programId: ctx.programId,
    data: Buffer.from([4, ctx.cpiBump, ctx.pcTokenCpiBump]),
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: lpPda, isSigner: false, isWritable: false },
      { pubkey: userAAcct, isSigner: false, isWritable: true },
      { pubkey: userBAcct, isSigner: false, isWritable: true },
      { pubkey: vaultAAcct, isSigner: false, isWritable: true },
      { pubkey: vaultBAcct, isSigner: false, isWritable: true },
      { pubkey: userABalCt, isSigner: false, isWritable: true },
      { pubkey: userBBalCt, isSigner: false, isWritable: true },
      { pubkey: vaultABalCt, isSigner: false, isWritable: true },
      { pubkey: vaultBBalCt, isSigner: false, isWritable: true },
      { pubkey: reserveACt, isSigner: false, isWritable: true },
      { pubkey: reserveBCt, isSigner: false, isWritable: true },
      { pubkey: totalSupplyCt, isSigner: false, isWritable: true },
      { pubkey: burnCt, isSigner: false, isWritable: true },
      { pubkey: userLpCt, isSigner: false, isWritable: true },
      { pubkey: outACt, isSigner: false, isWritable: true },
      { pubkey: outBCt, isSigner: false, isWritable: true },
      ...swapEncryptAndTokenAccounts(ctx),
    ],
  });
}
