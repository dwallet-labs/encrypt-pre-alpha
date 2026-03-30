/**
 * Shared helpers for Encrypt e2e demos.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

// ── Logging ──

export const log = (step: string, msg: string) =>
  console.log(`\x1b[36m[${step}]\x1b[0m ${msg}`);

export const ok = (msg: string) =>
  console.log(`\x1b[32m  ✓\x1b[0m ${msg}`);

export const val = (label: string, v: string | number | bigint) =>
  console.log(`\x1b[33m  →\x1b[0m ${label}: ${v}`);

// ── Transaction helpers ──

export async function sendTx(
  connection: Connection,
  payer: Keypair,
  ixs: TransactionInstruction[],
  signers: Keypair[] = []
) {
  const tx = new Transaction().add(...ixs);
  await sendAndConfirmTransaction(connection, tx, [payer, ...signers]);
}

// ── PDA ──

export function pda(
  seeds: (Buffer | Uint8Array)[],
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, programId);
}

// ── Polling ──

export async function pollUntil(
  connection: Connection,
  account: PublicKey,
  check: (data: Buffer) => boolean,
  timeoutMs = 120_000,
  intervalMs = 1_000
): Promise<Buffer> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const info = await connection.getAccountInfo(account);
      if (info && check(info.data as Buffer)) {
        return info.data as Buffer;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`timeout waiting for ${account.toBase58()}`);
}

/** Check if a ciphertext account has status = VERIFIED (byte 99 == 1). */
export const isVerified = (d: Buffer) => d.length >= 100 && d[99] === 1;

/** Check if a decryption request is complete (total == written > 0). */
export const isDecrypted = (d: Buffer) => {
  if (d.length < 107) return false;
  const total = d.readUInt32LE(99);
  const written = d.readUInt32LE(103);
  return written === total && total > 0;
};

// ── Mock ciphertext ──

/** Encode a mock plaintext value as little-endian u128 bytes for dev mode. */
export function mockCiphertext(value: bigint): Uint8Array {
  const buf = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}
