#!/usr/bin/env bun
/**
 * Coin Flip House Backend
 *
 * Player creates game via React frontend. This backend:
 *   1. Proxies gRPC createInput for encrypted commits
 *   2. Watches for player-created games
 *   3. Matches bet + commits house value (play instruction)
 *   4. Requests decryption + reveals result (winner gets 2x from escrow)
 *
 * Usage: bun server/house.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";

// @ts-ignore
import { createEncryptClient, DEVNET_PRE_ALPHA_GRPC_URL, Chain } from "../../../../clients/typescript/src/grpc";

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const GRPC_URL = process.env.GRPC_URL || DEVNET_PRE_ALPHA_GRPC_URL;
const PORT = Number(process.env.PORT) || 3001;
const FHE_UINT64 = 4;

const ENCRYPT_PROGRAM = new PublicKey(process.env.ENCRYPT_PROGRAM!);
const COINFLIP_PROGRAM = new PublicKey(process.env.COINFLIP_PROGRAM!);

const connection = new Connection(RPC_URL, "confirmed");

if (!process.env.HOUSE_SECRET_KEY) {
  throw new Error("HOUSE_SECRET_KEY not set in .env — base58 or JSON array of the house keypair secret key");
}

let house: Keypair;
try {
  const raw = process.env.HOUSE_SECRET_KEY.trim();
  if (raw.startsWith("[")) {
    house = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(raw)));
  } else {
    // base58-encoded secret key
    const { default: bs58 } = await import("bs58");
    house = Keypair.fromSecretKey(bs58.decode(raw));
  }
} catch (e: any) {
  throw new Error(`Failed to parse HOUSE_SECRET_KEY: ${e.message}`);
}

function findPda(seeds: (Buffer | Uint8Array)[], pid: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, pid);
}

function mockCiphertext(value: bigint): Uint8Array {
  const buf = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

async function sendTx(ixs: TransactionInstruction[], signers: Keypair[] = []) {
  const tx = new Transaction().add(...ixs);
  await sendAndConfirmTransaction(connection, tx, [house, ...signers]);
}

async function pollUntil(account: PublicKey, check: (d: Buffer) => boolean, ms = 120_000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try {
      const info = await connection.getAccountInfo(account);
      if (info && check(info.data as Buffer)) return info.data as Buffer;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("Timeout");
}

const isVerified = (d: Buffer) => d.length >= 100 && d[99] === 1;
const isDecrypted = (d: Buffer) => {
  if (d.length < 107) return false;
  const total = d.readUInt32LE(99);
  const written = d.readUInt32LE(103);
  return written === total && total > 0;
};

// ── Encrypt state ──

let encryptClient: ReturnType<typeof createEncryptClient>;
let configPda: PublicKey;
let eventAuthority: PublicKey;
let depositPda: PublicKey;
let networkKeyPda: PublicKey;
let networkKey: Buffer;
let cpiAuthority: PublicKey;
let cpiBump: number;

function encCpi() {
  return [
    { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: configPda, isSigner: false, isWritable: true },
    { pubkey: depositPda, isSigner: false, isWritable: true },
    { pubkey: cpiAuthority, isSigner: false, isWritable: false },
    { pubkey: COINFLIP_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: house.publicKey, isSigner: true, isWritable: true },
    { pubkey: eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}

// ── Game tracking ──

interface GameState {
  gamePda: string;
  status: "pending" | "house_playing" | "computing" | "decrypting" | "resolved";
  result: number | null; // 1=side_a wins, 2=side_b wins
}

const games = new Map<string, GameState>();

// ── Init ──

async function init() {
  console.log("\x1b[1m=== Coin Flip House Backend ===\x1b[0m\n");

  encryptClient = createEncryptClient(GRPC_URL);

  const bal = await connection.getBalance(house.publicKey);
  console.log(`House: ${house.publicKey.toBase58()} (${bal / LAMPORTS_PER_SOL} SOL)`);
  if (bal < LAMPORTS_PER_SOL) {
    console.warn("WARNING: House balance is low — fund this wallet on devnet");
  }

  [configPda] = findPda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  [eventAuthority] = findPda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [dp, db] = findPda([Buffer.from("encrypt_deposit"), house.publicKey.toBuffer()], ENCRYPT_PROGRAM);
  depositPda = dp;
  networkKey = Buffer.alloc(32, 0x55);
  [networkKeyPda] = findPda([Buffer.from("network_encryption_key"), networkKey], ENCRYPT_PROGRAM);
  [cpiAuthority, cpiBump] = findPda([Buffer.from("__encrypt_cpi_authority")], COINFLIP_PROGRAM);

  const configInfo = await connection.getAccountInfo(configPda);
  if (!configInfo) throw new Error("Executor not running");

  const encVault = new PublicKey((configInfo.data as Buffer).subarray(100, 132));
  const vaultPk = encVault.equals(SystemProgram.programId) ? house.publicKey : encVault;

  if (!(await connection.getAccountInfo(depositPda))) {
    const data = Buffer.alloc(18); data[0] = 14; data[1] = db;
    await sendTx([new TransactionInstruction({
      programId: ENCRYPT_PROGRAM, data,
      keys: [
        { pubkey: depositPda, isSigner: false, isWritable: true },
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: house.publicKey, isSigner: true, isWritable: false },
        { pubkey: house.publicKey, isSigner: true, isWritable: true },
        { pubkey: house.publicKey, isSigner: true, isWritable: true },
        { pubkey: vaultPk, isSigner: vaultPk.equals(house.publicKey), isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
    })]);
    console.log("Deposit created");
  }

  console.log(`\nhttp://localhost:${PORT}\n`);
}

// ── House joins and resolves a game ──

async function houseJoinAndResolve(gamePdaStr: string) {
  const gamePda = new PublicKey(gamePdaStr);
  const gs = games.get(gamePdaStr)!;

  try {
    gs.status = "house_playing";
    const d = (await connection.getAccountInfo(gamePda))!.data as Buffer;
    const commitA = new PublicKey(d.subarray(65, 97));
    const resultCt = new PublicKey(d.subarray(97, 129));
    const sideA = new PublicKey(d.subarray(1, 33));
    const bet = d.readBigUInt64LE(196);
    console.log(`  bet=${Number(bet) / LAMPORTS_PER_SOL} SOL, side_a=${sideA.toBase58().slice(0, 8)}...`);

    // House encrypted commit
    const houseVal = Math.random() < 0.5 ? 0 : 1;
    const { ciphertextIdentifiers } = await encryptClient.createInput({
      chain: Chain.Solana,
      inputs: [{ ciphertextBytes: mockCiphertext(BigInt(houseVal)), fheType: FHE_UINT64 }],
      authorized: COINFLIP_PROGRAM.toBytes(),
      networkEncryptionPublicKey: networkKey,
    });
    const commitB = new PublicKey(ciphertextIdentifiers[0]);

    // Play (house = side_b)
    await sendTx([new TransactionInstruction({
      programId: COINFLIP_PROGRAM,
      data: Buffer.from([1, cpiBump]),
      keys: [
        { pubkey: gamePda, isSigner: false, isWritable: true },
        { pubkey: house.publicKey, isSigner: true, isWritable: true },
        { pubkey: commitA, isSigner: false, isWritable: true },
        { pubkey: commitB, isSigner: false, isWritable: true },
        { pubkey: resultCt, isSigner: false, isWritable: true },
        ...encCpi(),
      ],
    })]);
    console.log("  House played");

    // Wait for XOR
    gs.status = "computing";
    await pollUntil(resultCt, isVerified, 60_000);
    console.log("  XOR committed");

    // Request decryption (disc 2)
    gs.status = "decrypting";
    const decReq = Keypair.generate();
    await sendTx(
      [new TransactionInstruction({
        programId: COINFLIP_PROGRAM,
        data: Buffer.from([2, cpiBump]),
        keys: [
          { pubkey: gamePda, isSigner: false, isWritable: true },
          { pubkey: decReq.publicKey, isSigner: true, isWritable: true },
          { pubkey: resultCt, isSigner: false, isWritable: false },
          ...encCpi().map((a) => a.pubkey.equals(configPda) ? { ...a, isWritable: false } : a),
        ],
      })],
      [decReq]
    );

    await pollUntil(decReq.publicKey, isDecrypted);
    console.log("  Decrypted");

    // Read XOR result
    const reqData = (await connection.getAccountInfo(decReq.publicKey))!.data as Buffer;
    const xor = reqData.readBigUInt64LE(107);
    const sideAWins = xor === 1n;
    const winner = sideAWins ? sideA : house.publicKey;

    // Reveal (disc 3) — pays winner from escrow
    await sendTx([new TransactionInstruction({
      programId: COINFLIP_PROGRAM,
      data: Buffer.from([3]),
      keys: [
        { pubkey: gamePda, isSigner: false, isWritable: true },
        { pubkey: decReq.publicKey, isSigner: false, isWritable: false },
        { pubkey: house.publicKey, isSigner: true, isWritable: false },
        { pubkey: winner, isSigner: false, isWritable: true },
      ],
    })]);

    gs.result = sideAWins ? 1 : 2;
    gs.status = "resolved";
    const label = sideAWins ? "PLAYER WINS" : "HOUSE WINS";
    console.log(`  ${label} — ${Number(bet) * 2 / LAMPORTS_PER_SOL} SOL to ${winner.toBase58().slice(0, 8)}...\n`);

  } catch (err: any) {
    console.error(`  Error: ${err.message}`);
    gs.status = "resolved";
    gs.result = 0;
  }
}

// ── Server ──

await init();

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" },
      });
    }
    const h = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

    // POST /api/join — house joins a player-created game
    if (url.pathname === "/api/join" && req.method === "POST") {
      try {
        const { gamePda } = await req.json() as { gamePda: string };
        const gs: GameState = { gamePda, status: "pending", result: null };
        games.set(gamePda, gs);
        console.log(`[Game] ${gamePda.slice(0, 12)}... — house joining`);
        houseJoinAndResolve(gamePda); // background
        return new Response(JSON.stringify({ ok: true }), { headers: h });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: h });
      }
    }

    // GET /api/game/:pda
    if (url.pathname.startsWith("/api/game/") && req.method === "GET") {
      const pda = url.pathname.split("/").pop()!;
      const gs = games.get(pda);
      if (!gs) return new Response(JSON.stringify({ status: "unknown" }), { headers: h });
      return new Response(JSON.stringify({ status: gs.status, result: gs.result }), { headers: h });
    }

    // GET /api/info
    if (url.pathname === "/api/info") {
      const bal = await connection.getBalance(house.publicKey);
      return new Response(JSON.stringify({
        house: house.publicKey.toBase58(), balanceSol: bal / LAMPORTS_PER_SOL, cpiBump,
      }), { headers: h });
    }

    return new Response("Not found", { status: 404 });
  },
});
