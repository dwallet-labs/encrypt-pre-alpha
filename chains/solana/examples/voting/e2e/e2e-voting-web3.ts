#!/usr/bin/env bun
/**
 * Confidential Voting E2E Demo — @solana/web3.js
 *
 * Sends transactions as a user would. The `encrypt solana dev` executor
 * running in the background handles graph evaluation, decryption, and
 * input ciphertext creation (via gRPC).
 *
 * Flow:
 *   1. Create proposal with encrypted zero tallies
 *   2. Cast 5 votes (3 yes, 2 no) — each vote's encrypted input is
 *      submitted to the executor via gRPC, then used in execute_graph
 *   3. Close proposal
 *   4. Request decryption of tallies
 *   5. Poll until executor responds
 *   6. Reveal and verify results
 *
 * Prerequisites:
 *   just demo-web3 <ENCRYPT_ID> <VOTING_ID>
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import { createEncryptClient, DEVNET_PRE_ALPHA_GRPC_URL, Chain } from "../../../clients/typescript/src/grpc";

// ── Config ──

const RPC_URL = "https://api.devnet.solana.com";
const GRPC_URL = DEVNET_PRE_ALPHA_GRPC_URL;

const [encryptArg, votingArg] = process.argv.slice(2);
if (!encryptArg || !votingArg) {
  console.error(
    "Usage: bun e2e-voting-web3.ts <ENCRYPT_PROGRAM_ID> <VOTING_PROGRAM_ID>"
  );
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const VOTING_PROGRAM = new PublicKey(votingArg);
const connection = new Connection(RPC_URL, "confirmed");
const payer = Keypair.generate();

// ── Helpers ──

const log = (step: string, msg: string) =>
  console.log(`\x1b[36m[${step}]\x1b[0m ${msg}`);
const ok = (msg: string) => console.log(`\x1b[32m  ✓\x1b[0m ${msg}`);
const val = (label: string, v: string | number | bigint) =>
  console.log(`\x1b[33m  →\x1b[0m ${label}: ${v}`);

async function send(ixs: TransactionInstruction[], signers: Keypair[] = []) {
  const tx = new Transaction().add(...ixs);
  await sendAndConfirmTransaction(connection, tx, [payer, ...signers]);
}

function pda(
  seeds: (Buffer | Uint8Array)[],
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, programId);
}

async function pollUntil(
  account: PublicKey,
  check: (data: Buffer) => boolean,
  timeoutMs = 120000,
  intervalMs = 1000
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

/** Encode a mock plaintext value as the "encrypted ciphertext" for dev mode. */
function mockCiphertext(value: bigint): Uint8Array {
  const buf = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

const FHE_BOOL = 0;

// ── Main ──

async function main() {
  console.log("\n\x1b[1m═══ Confidential Voting E2E Demo ═══\x1b[0m\n");

  // Connect to executor gRPC
  const encrypt = createEncryptClient(GRPC_URL);
  log("Setup", `Connected to executor gRPC at ${GRPC_URL}`);

  // Fund payer
  log("Setup", "Funding payer...");
  const sig = await connection.requestAirdrop(payer.publicKey, 100e9);
  await connection.confirmTransaction(sig);
  ok(`Payer: ${payer.publicKey.toBase58()}`);

  // Derive encrypt PDAs
  const [configPda] = pda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = pda(
    [Buffer.from("__event_authority")],
    ENCRYPT_PROGRAM
  );
  const [depositPda, depositBump] = pda(
    [Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()],
    ENCRYPT_PROGRAM
  );
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = pda(
    [Buffer.from("network_encryption_key"), networkKey],
    ENCRYPT_PROGRAM
  );

  // Read enc_vault from config
  const configInfo = await connection.getAccountInfo(configPda);
  if (!configInfo) {
    throw new Error("Config not initialized. Is the executor running?");
  }
  const encVault = new PublicKey(
    (configInfo.data as Buffer).subarray(100, 132)
  );
  const vaultPk = encVault.equals(SystemProgram.programId)
    ? payer.publicKey
    : encVault;

  // Create deposit
  log("Setup", "Creating deposit...");
  const depositData = Buffer.alloc(18);
  depositData[0] = 14; // IX_CREATE_DEPOSIT
  depositData[1] = depositBump;

  await send([
    new TransactionInstruction({
      programId: ENCRYPT_PROGRAM,
      data: depositData,
      keys: [
        { pubkey: depositPda, isSigner: false, isWritable: true },
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        {
          pubkey: vaultPk,
          isSigner: vaultPk.equals(payer.publicKey),
          isWritable: true,
        },
        {
          pubkey: SystemProgram.programId,
          isSigner: false,
          isWritable: false,
        },
        {
          pubkey: SystemProgram.programId,
          isSigner: false,
          isWritable: false,
        },
      ],
    }),
  ]);
  ok("Deposit created");

  // Derive voting PDAs
  const proposalId = Buffer.from(Keypair.generate().publicKey.toBytes());
  const [proposalPda, proposalBump] = pda(
    [Buffer.from("proposal"), proposalId],
    VOTING_PROGRAM
  );
  const [cpiAuthority, cpiBump] = pda(
    [Buffer.from("__encrypt_cpi_authority")],
    VOTING_PROGRAM
  );

  // ── 1. Create Proposal ──
  log("1/6", "Creating proposal...");

  const yesCt = Keypair.generate();
  const noCt = Keypair.generate();

  await send(
    [
      new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.concat([
          Buffer.from([0, proposalBump, cpiBump]),
          proposalId,
        ]),
        keys: [
          { pubkey: proposalPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: yesCt.publicKey, isSigner: true, isWritable: true },
          { pubkey: noCt.publicKey, isSigner: true, isWritable: true },
          { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: configPda, isSigner: false, isWritable: false },
          { pubkey: depositPda, isSigner: false, isWritable: true },
          { pubkey: cpiAuthority, isSigner: false, isWritable: false },
          { pubkey: VOTING_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: networkKeyPda, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: eventAuthority, isSigner: false, isWritable: false },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ],
      }),
    ],
    [yesCt, noCt]
  );
  ok(`Proposal: ${proposalPda.toBase58()}`);
  ok(`Yes CT:   ${yesCt.publicKey.toBase58()}`);
  ok(`No CT:    ${noCt.publicKey.toBase58()}`);

  // ── 2. Cast Votes ──
  const votes: { name: string; vote: number }[] = [
    { name: "Alice", vote: 1 },
    { name: "Bob", vote: 1 },
    { name: "Charlie", vote: 1 },
    { name: "Dave", vote: 0 },
    { name: "Eve", vote: 0 },
  ];

  for (const { name, vote } of votes) {
    log("2/6", `${name} votes ${vote === 1 ? "YES ✋" : "NO  ✋"}...`);

    const voter = Keypair.generate();
    const airdropSig = await connection.requestAirdrop(voter.publicKey, 1e9);
    await connection.confirmTransaction(airdropSig);

    // Submit encrypted vote via gRPC → executor creates the ciphertext on-chain
    const { ciphertextIdentifiers } = await encrypt.createInput({
      chain: Chain.Solana,
      inputs: [{ ciphertextBytes: mockCiphertext(BigInt(vote)), fheType: FHE_BOOL }],
      authorized: VOTING_PROGRAM.toBytes(),
      networkEncryptionPublicKey: networkKey,
    });
    const voteCt = new PublicKey(ciphertextIdentifiers[0]);
    ok(`Vote CT: ${voteCt.toBase58()} (via gRPC)`);

    // Cast vote on voting program (CPI to execute_graph)
    const [voteRecord, vrBump] = pda(
      [Buffer.from("vote"), proposalId, voter.publicKey.toBuffer()],
      VOTING_PROGRAM
    );

    await send(
      [
        new TransactionInstruction({
          programId: VOTING_PROGRAM,
          data: Buffer.from([1, vrBump, cpiBump]),
          keys: [
            { pubkey: proposalPda, isSigner: false, isWritable: true },
            { pubkey: voteRecord, isSigner: false, isWritable: true },
            { pubkey: voter.publicKey, isSigner: true, isWritable: false },
            { pubkey: voteCt, isSigner: false, isWritable: true },
            { pubkey: yesCt.publicKey, isSigner: false, isWritable: true },
            { pubkey: noCt.publicKey, isSigner: false, isWritable: true },
            { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
            { pubkey: configPda, isSigner: false, isWritable: true },
            { pubkey: depositPda, isSigner: false, isWritable: true },
            { pubkey: cpiAuthority, isSigner: false, isWritable: false },
            { pubkey: VOTING_PROGRAM, isSigner: false, isWritable: false },
            { pubkey: networkKeyPda, isSigner: false, isWritable: false },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: eventAuthority, isSigner: false, isWritable: false },
            {
              pubkey: SystemProgram.programId,
              isSigner: false,
              isWritable: false,
            },
          ],
        }),
      ],
      [voter]
    );

    ok(`${name} voted ${vote === 1 ? "YES" : "NO"}`);

    // Wait for executor to commit graph outputs
    log("2/6", "  Waiting for executor to commit results...");
    await pollUntil(
      yesCt.publicKey,
      (d) => d.length >= 100 && d[99] === 1, // status = VERIFIED
      60000
    );
    ok("Graph outputs committed by executor");
  }

  // ── 3. Close Proposal ──
  log("3/6", "Closing proposal...");
  await send([
    new TransactionInstruction({
      programId: VOTING_PROGRAM,
      data: Buffer.from([2]),
      keys: [
        { pubkey: proposalPda, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
      ],
    }),
  ]);
  ok("Proposal closed — no more votes accepted");

  // ── 4. Request Decryption ──
  log("4/6", "Requesting decryption of tallies...");

  const yesReq = Keypair.generate();
  await send(
    [
      new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([3, cpiBump, 1]),
        keys: [
          { pubkey: proposalPda, isSigner: false, isWritable: true },
          { pubkey: yesReq.publicKey, isSigner: true, isWritable: true },
          { pubkey: yesCt.publicKey, isSigner: false, isWritable: false },
          { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: configPda, isSigner: false, isWritable: false },
          { pubkey: depositPda, isSigner: false, isWritable: true },
          { pubkey: cpiAuthority, isSigner: false, isWritable: false },
          { pubkey: VOTING_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: networkKeyPda, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: eventAuthority, isSigner: false, isWritable: false },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ],
      }),
    ],
    [yesReq]
  );
  ok(`Yes decryption requested: ${yesReq.publicKey.toBase58()}`);

  const noReq = Keypair.generate();
  await send(
    [
      new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([3, cpiBump, 0]),
        keys: [
          { pubkey: proposalPda, isSigner: false, isWritable: true },
          { pubkey: noReq.publicKey, isSigner: true, isWritable: true },
          { pubkey: noCt.publicKey, isSigner: false, isWritable: false },
          { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: configPda, isSigner: false, isWritable: false },
          { pubkey: depositPda, isSigner: false, isWritable: true },
          { pubkey: cpiAuthority, isSigner: false, isWritable: false },
          { pubkey: VOTING_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: networkKeyPda, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: eventAuthority, isSigner: false, isWritable: false },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ],
      }),
    ],
    [noReq]
  );
  ok(`No decryption requested: ${noReq.publicKey.toBase58()}`);

  // ── 5. Wait for Executor ──
  log("5/6", "Waiting for executor to decrypt...");

  await pollUntil(yesReq.publicKey, (d) => {
    if (d.length < 107) return false;
    const total = d.readUInt32LE(99);
    const written = d.readUInt32LE(103);
    return written === total && total > 0;
  });
  ok("Yes tally decrypted");

  await pollUntil(noReq.publicKey, (d) => {
    if (d.length < 107) return false;
    const total = d.readUInt32LE(99);
    const written = d.readUInt32LE(103);
    return written === total && total > 0;
  });
  ok("No tally decrypted");

  // ── 6. Reveal Results ──
  log("6/6", "Revealing tallies on-chain...");

  await send([
    new TransactionInstruction({
      programId: VOTING_PROGRAM,
      data: Buffer.from([4, 1]),
      keys: [
        { pubkey: proposalPda, isSigner: false, isWritable: true },
        { pubkey: yesReq.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
      ],
    }),
  ]);
  await send([
    new TransactionInstruction({
      programId: VOTING_PROGRAM,
      data: Buffer.from([4, 0]),
      keys: [
        { pubkey: proposalPda, isSigner: false, isWritable: true },
        { pubkey: noReq.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
      ],
    }),
  ]);

  // Read final state
  const propData = (await connection.getAccountInfo(proposalPda))!.data;
  const totalVotes = (propData as Buffer).readBigUInt64LE(130);
  const revealedYes = (propData as Buffer).readBigUInt64LE(138);
  const revealedNo = (propData as Buffer).readBigUInt64LE(146);

  console.log("\n\x1b[1m═══ Results ═══\x1b[0m\n");
  val("Total votes", totalVotes);
  val("Yes votes", revealedYes);
  val("No votes", revealedNo);

  const passed = revealedYes > revealedNo;
  console.log(
    `\n  ${passed ? "\x1b[32mProposal PASSED\x1b[0m" : "\x1b[31mProposal REJECTED\x1b[0m"} (${revealedYes} yes / ${revealedNo} no)\n`
  );

  encrypt.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
