/**
 * Minimal SPL Token helpers — no @solana/spl-token dependency.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { sendTx } from "../../_shared/helpers.ts";

export const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
);
const RENT_SYSVAR = new PublicKey(
  "SysvarRent111111111111111111111111111111111"
);

const SPL_ACCOUNT_SIZE = 165;

/** Create an SPL mint + initialize it. Returns mint keypair. */
export async function createSplMint(
  connection: Connection,
  payer: Keypair,
  decimals: number,
  mintAuthority: PublicKey
): Promise<Keypair> {
  const mint = Keypair.generate();
  const rent = await connection.getMinimumBalanceForRentExemption(82);

  const data = Buffer.alloc(67);
  data[0] = 0; // InitializeMint
  data[1] = decimals;
  mintAuthority.toBuffer().copy(data, 2);
  data[34] = 0; // no freeze authority

  await sendTx(
    connection,
    payer,
    [
      SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: mint.publicKey,
        lamports: rent,
        space: 82,
        programId: TOKEN_PROGRAM_ID,
      }),
      new TransactionInstruction({
        programId: TOKEN_PROGRAM_ID,
        data,
        keys: [
          { pubkey: mint.publicKey, isSigner: false, isWritable: true },
          { pubkey: RENT_SYSVAR, isSigner: false, isWritable: false },
        ],
      }),
    ],
    [mint]
  );
  return mint;
}

/** Create an SPL token account for a given mint + owner. Returns account keypair. */
export async function createSplTokenAccount(
  connection: Connection,
  payer: Keypair,
  mint: PublicKey,
  owner: PublicKey
): Promise<Keypair> {
  const account = Keypair.generate();
  const rent = await connection.getMinimumBalanceForRentExemption(SPL_ACCOUNT_SIZE);

  await sendTx(
    connection,
    payer,
    [
      SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: account.publicKey,
        lamports: rent,
        space: SPL_ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      new TransactionInstruction({
        programId: TOKEN_PROGRAM_ID,
        data: Buffer.from([1]), // InitializeAccount
        keys: [
          { pubkey: account.publicKey, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: owner, isSigner: false, isWritable: false },
          { pubkey: RENT_SYSVAR, isSigner: false, isWritable: false },
        ],
      }),
    ],
    [account]
  );
  return account;
}

/** SPL Token MintTo instruction. */
export function splMintToIx(
  mint: PublicKey,
  destination: PublicKey,
  authority: PublicKey,
  amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(9);
  data[0] = 7; // MintTo
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    data,
    keys: [
      { pubkey: mint, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
  });
}

/** Read SPL token account balance. */
export async function readSplBalance(
  connection: Connection,
  account: PublicKey
): Promise<bigint> {
  const info = await connection.getAccountInfo(account);
  if (!info || info.data.length < 72) return 0n;
  return (info.data as Buffer).readBigUInt64LE(64);
}
