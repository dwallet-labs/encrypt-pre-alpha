#!/usr/bin/env bun
/**
 * Confidential Voting E2E Demo — @solana/kit (web3.js v2)
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
 *   Terminal 1: solana-test-validator --reset
 *   Terminal 2: encrypt solana dev --program-id <ENCRYPT_PROGRAM_ID>
 *   Terminal 3: just demo-kit <ENCRYPT_ID> <VOTING_ID>
 */

import {
  address,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  generateKeyPairSigner,
  createTransactionMessage,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  appendTransactionMessageInstruction,
  appendTransactionMessageInstructions,
  signTransactionMessageWithSigners,
  sendAndConfirmTransactionFactory,
  pipe,
  getAddressEncoder,
  getAddressDecoder,
  getProgramDerivedAddress,
  getUtf8Encoder,
  type Address,
  type IInstruction,
  type IAccountMeta,
  type TransactionSigner,
  AccountRole,
} from "@solana/kit";

import { createEncryptClient, DEVNET_PRE_ALPHA_GRPC_URL, Chain } from "../../../clients/typescript/src/grpc";

// ── Config ──

const RPC_URL = "https://api.devnet.solana.com";
const WS_URL = "wss://api.devnet.solana.com";
const GRPC_URL = DEVNET_PRE_ALPHA_GRPC_URL;

const SYSTEM_PROGRAM = address("11111111111111111111111111111111");

const [encryptArg, votingArg] = process.argv.slice(2);
if (!encryptArg || !votingArg) {
  console.error(
    "Usage: bun e2e-voting-kit.ts <ENCRYPT_PROGRAM_ID> <VOTING_PROGRAM_ID>"
  );
  process.exit(1);
}

const ENCRYPT_PROGRAM = address(encryptArg);
const VOTING_PROGRAM = address(votingArg);

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);
const sendAndConfirm = sendAndConfirmTransactionFactory({
  rpc,
  rpcSubscriptions,
});

// ── Helpers ──

const log = (step: string, msg: string) =>
  console.log(`\x1b[36m[${step}]\x1b[0m ${msg}`);
const ok = (msg: string) => console.log(`\x1b[32m  \u2713\x1b[0m ${msg}`);
const val = (label: string, v: string | number | bigint) =>
  console.log(`\x1b[33m  \u2192\x1b[0m ${label}: ${v}`);

const utf8 = getUtf8Encoder();
const addressEncoder = getAddressEncoder();
const addressDecoder = getAddressDecoder();

async function findPda(
  seeds: Uint8Array[],
  programId: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    seeds,
    programAddress: programId,
  });
  return [result[0], result[1]];
}

/**
 * Build and send a transaction using the @solana/kit pipe pattern.
 */
async function sendTx(
  payer: TransactionSigner,
  instructions: IInstruction[],
  _extraSigners: TransactionSigner[] = []
) {
  const { value: blockhash } = await rpc.getLatestBlockhash().send();

  let msg = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(payer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m)
  );

  for (const ix of instructions) {
    msg = appendTransactionMessageInstruction(ix, msg);
  }

  const signed = await signTransactionMessageWithSigners(msg);
  await sendAndConfirm(signed, { commitment: "confirmed" });
}

function acct(
  addr: Address,
  role: AccountRole,
  signer?: TransactionSigner
): IAccountMeta | (IAccountMeta & { signer: TransactionSigner }) {
  if (signer) {
    return { address: addr, role, signer } as any;
  }
  return { address: addr, role };
}

async function pollUntil(
  addr: Address,
  check: (data: Uint8Array) => boolean,
  timeoutMs = 120000,
  intervalMs = 1000
): Promise<Uint8Array> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const resp = await rpc
        .getAccountInfo(addr, { encoding: "base64" })
        .send();
      if (resp.value) {
        const raw =
          typeof resp.value.data === "string"
            ? Uint8Array.from(atob(resp.value.data), (c) => c.charCodeAt(0))
            : typeof resp.value.data === "object" && Array.isArray(resp.value.data)
              ? Uint8Array.from(atob(resp.value.data[0] as string), (c) => c.charCodeAt(0))
              : resp.value.data as Uint8Array;
        if (check(raw)) return raw;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`timeout waiting for ${addr}`);
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

function readU32LE(data: Uint8Array, offset: number): number {
  return (
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24)
  ) >>> 0;
}

function readU64LE(data: Uint8Array, offset: number): bigint {
  const lo = BigInt(readU32LE(data, offset));
  const hi = BigInt(readU32LE(data, offset + 4));
  return (hi << 32n) | lo;
}

const FHE_BOOL = 0;

// ── Main ──

async function main() {
  console.log("\n\x1b[1m\u2550\u2550\u2550 Confidential Voting E2E \u2014 @solana/kit \u2550\u2550\u2550\x1b[0m\n");

  // Connect to executor gRPC
  const encrypt = createEncryptClient(GRPC_URL);
  log("Setup", `Connected to executor gRPC at ${GRPC_URL}`);

  // Generate payer and airdrop
  const payer = await generateKeyPairSigner();
  log("Setup", "Funding payer...");
  const airdropSig = await rpc.requestAirdrop(payer.address, 100_000_000_000n).send();
  // Poll until airdrop is confirmed
  for (let i = 0; i < 30; i++) {
    const status = await rpc.getSignatureStatuses([airdropSig]).send();
    if (status.value[0]?.confirmationStatus === "confirmed" || status.value[0]?.confirmationStatus === "finalized") break;
    await new Promise((r) => setTimeout(r, 500));
  }
  ok(`Payer: ${payer.address}`);

  // Derive encrypt PDAs
  const [configPda] = await findPda(
    [utf8.encode("encrypt_config")],
    ENCRYPT_PROGRAM
  );
  const [eventAuthority] = await findPda(
    [utf8.encode("__event_authority")],
    ENCRYPT_PROGRAM
  );
  const [depositPda, depositBump] = await findPda(
    [utf8.encode("encrypt_deposit"), addressEncoder.encode(payer.address)],
    ENCRYPT_PROGRAM
  );
  const networkKey = new Uint8Array(32).fill(0x55);
  const [networkKeyPda] = await findPda(
    [utf8.encode("network_encryption_key"), networkKey],
    ENCRYPT_PROGRAM
  );

  // Read enc_vault from config account (offset 100..132)
  const configResp = await rpc
    .getAccountInfo(configPda, { encoding: "base64" })
    .send();
  if (!configResp.value) {
    throw new Error("Config not initialized. Is the executor running?");
  }
  const configRaw =
    typeof configResp.value.data === "object" && Array.isArray(configResp.value.data)
      ? Uint8Array.from(atob(configResp.value.data[0] as string), (c) => c.charCodeAt(0))
      : Uint8Array.from(atob(configResp.value.data as string), (c) => c.charCodeAt(0));
  const encVaultBytes = configRaw.slice(100, 132);
  const encVault = addressDecoder.decode(encVaultBytes);
  const vaultIsPayer = encVault === SYSTEM_PROGRAM;
  const vaultAddr = vaultIsPayer ? payer.address : encVault;

  // ── Create Deposit ──
  log("Setup", "Creating deposit...");
  const depositData = new Uint8Array(18);
  depositData[0] = 14; // IX_CREATE_DEPOSIT
  depositData[1] = depositBump;
  // initial_enc=0 (8 bytes) + initial_gas=0 (8 bytes) already zeroed

  await sendTx(payer, [
    {
      programAddress: ENCRYPT_PROGRAM,
      data: depositData,
      accounts: [
        acct(depositPda, AccountRole.WRITABLE),
        acct(configPda, AccountRole.READONLY),
        acct(payer.address, AccountRole.READONLY_SIGNER, payer),
        acct(payer.address, AccountRole.WRITABLE_SIGNER, payer),
        acct(payer.address, AccountRole.WRITABLE_SIGNER, payer), // user_ata (dummy)
        vaultIsPayer
          ? acct(payer.address, AccountRole.WRITABLE_SIGNER, payer)
          : acct(vaultAddr, AccountRole.WRITABLE),
        acct(SYSTEM_PROGRAM, AccountRole.READONLY), // token_program
        acct(SYSTEM_PROGRAM, AccountRole.READONLY),
      ],
    },
  ]);
  ok("Deposit created");

  // Derive voting PDAs
  const proposalIdSigner = await generateKeyPairSigner();
  const proposalId = addressEncoder.encode(proposalIdSigner.address);
  const [proposalPda, proposalBump] = await findPda(
    [utf8.encode("proposal"), proposalId],
    VOTING_PROGRAM
  );
  const [cpiAuthority, cpiBump] = await findPda(
    [utf8.encode("__encrypt_cpi_authority")],
    VOTING_PROGRAM
  );

  // ── 1. Create Proposal ──
  log("1/6", "Creating proposal...");

  const yesCt = await generateKeyPairSigner();
  const noCt = await generateKeyPairSigner();

  const createProposalData = new Uint8Array(3 + 32);
  createProposalData[0] = 0; // create_proposal
  createProposalData[1] = proposalBump;
  createProposalData[2] = cpiBump;
  createProposalData.set(proposalId, 3);

  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: createProposalData,
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(payer.address, AccountRole.READONLY_SIGNER, payer),
        acct(yesCt.address, AccountRole.WRITABLE_SIGNER, yesCt),
        acct(noCt.address, AccountRole.WRITABLE_SIGNER, noCt),
        acct(ENCRYPT_PROGRAM, AccountRole.READONLY),
        acct(configPda, AccountRole.READONLY),
        acct(depositPda, AccountRole.WRITABLE),
        acct(cpiAuthority, AccountRole.READONLY),
        acct(VOTING_PROGRAM, AccountRole.READONLY),
        acct(networkKeyPda, AccountRole.READONLY),
        acct(payer.address, AccountRole.WRITABLE_SIGNER, payer),
        acct(eventAuthority, AccountRole.READONLY),
        acct(SYSTEM_PROGRAM, AccountRole.READONLY),
      ],
    },
  ]);
  ok(`Proposal: ${proposalPda}`);
  ok(`Yes CT:   ${yesCt.address}`);
  ok(`No CT:    ${noCt.address}`);

  // ── 2. Cast Votes ──
  const votes: { name: string; vote: number }[] = [
    { name: "Alice", vote: 1 },
    { name: "Bob", vote: 1 },
    { name: "Charlie", vote: 1 },
    { name: "Dave", vote: 0 },
    { name: "Eve", vote: 0 },
  ];

  for (const { name, vote } of votes) {
    log("2/6", `${name} votes ${vote === 1 ? "YES \u270b" : "NO  \u270b"}...`);

    const voter = await generateKeyPairSigner();
    const voterAirdropSig = await rpc.requestAirdrop(voter.address, 1_000_000_000n).send();
    for (let i = 0; i < 30; i++) {
      const status = await rpc.getSignatureStatuses([voterAirdropSig]).send();
      if (status.value[0]?.confirmationStatus === "confirmed" || status.value[0]?.confirmationStatus === "finalized") break;
      await new Promise((r) => setTimeout(r, 500));
    }

    // Submit encrypted vote via gRPC → executor creates the ciphertext on-chain
    const { ciphertextIdentifiers } = await encrypt.createInput({
      chain: Chain.Solana,
      inputs: [{ ciphertextBytes: mockCiphertext(BigInt(vote)), fheType: FHE_BOOL }],
      authorized: addressEncoder.encode(VOTING_PROGRAM),
      networkEncryptionPublicKey: networkKey,
    });
    const voteCt = address(addressDecoder.decode(ciphertextIdentifiers[0]));
    ok(`Vote CT: ${voteCt} (via gRPC)`);

    // Cast vote on voting program (CPI to execute_graph)
    const [voteRecord, vrBump] = await findPda(
      [
        utf8.encode("vote"),
        proposalId,
        addressEncoder.encode(voter.address),
      ],
      VOTING_PROGRAM
    );

    await sendTx(payer, [
      {
        programAddress: VOTING_PROGRAM,
        data: Uint8Array.from([1, vrBump, cpiBump]),
        accounts: [
          acct(proposalPda, AccountRole.WRITABLE),
          acct(voteRecord, AccountRole.WRITABLE),
          acct(voter.address, AccountRole.READONLY_SIGNER, voter),
          acct(voteCt, AccountRole.WRITABLE),
          acct(yesCt.address, AccountRole.WRITABLE),
          acct(noCt.address, AccountRole.WRITABLE),
          acct(ENCRYPT_PROGRAM, AccountRole.READONLY),
          acct(configPda, AccountRole.WRITABLE),
          acct(depositPda, AccountRole.WRITABLE),
          acct(cpiAuthority, AccountRole.READONLY),
          acct(VOTING_PROGRAM, AccountRole.READONLY),
          acct(networkKeyPda, AccountRole.READONLY),
          acct(payer.address, AccountRole.WRITABLE_SIGNER, payer),
          acct(eventAuthority, AccountRole.READONLY),
          acct(SYSTEM_PROGRAM, AccountRole.READONLY),
        ],
      },
    ]);

    ok(`${name} voted ${vote === 1 ? "YES" : "NO"}`);

    // Wait for executor to commit graph outputs
    log("2/6", "  Waiting for executor to commit results...");
    await pollUntil(
      yesCt.address,
      (d) => d.length >= 100 && d[99] === 1, // status = VERIFIED
      60000
    );
    ok("Graph outputs committed by executor");
  }

  // ── 3. Close Proposal ──
  log("3/6", "Closing proposal...");
  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: Uint8Array.from([2]),
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(payer.address, AccountRole.READONLY_SIGNER, payer),
      ],
    },
  ]);
  ok("Proposal closed \u2014 no more votes accepted");

  // ── 4. Request Decryption ──
  log("4/6", "Requesting decryption of tallies...");

  const yesReq = await generateKeyPairSigner();
  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: Uint8Array.from([3, cpiBump, 1]), // request_tally_decryption, is_yes=true
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(yesReq.address, AccountRole.WRITABLE_SIGNER, yesReq),
        acct(yesCt.address, AccountRole.READONLY),
        acct(ENCRYPT_PROGRAM, AccountRole.READONLY),
        acct(configPda, AccountRole.READONLY),
        acct(depositPda, AccountRole.WRITABLE),
        acct(cpiAuthority, AccountRole.READONLY),
        acct(VOTING_PROGRAM, AccountRole.READONLY),
        acct(networkKeyPda, AccountRole.READONLY),
        acct(payer.address, AccountRole.WRITABLE_SIGNER, payer),
        acct(eventAuthority, AccountRole.READONLY),
        acct(SYSTEM_PROGRAM, AccountRole.READONLY),
      ],
    },
  ]);
  ok(`Yes decryption requested: ${yesReq.address}`);

  const noReq = await generateKeyPairSigner();
  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: Uint8Array.from([3, cpiBump, 0]), // is_yes=false
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(noReq.address, AccountRole.WRITABLE_SIGNER, noReq),
        acct(noCt.address, AccountRole.READONLY),
        acct(ENCRYPT_PROGRAM, AccountRole.READONLY),
        acct(configPda, AccountRole.READONLY),
        acct(depositPda, AccountRole.WRITABLE),
        acct(cpiAuthority, AccountRole.READONLY),
        acct(VOTING_PROGRAM, AccountRole.READONLY),
        acct(networkKeyPda, AccountRole.READONLY),
        acct(payer.address, AccountRole.WRITABLE_SIGNER, payer),
        acct(eventAuthority, AccountRole.READONLY),
        acct(SYSTEM_PROGRAM, AccountRole.READONLY),
      ],
    },
  ]);
  ok(`No decryption requested: ${noReq.address}`);

  // ── 5. Wait for Executor ──
  log("5/6", "Waiting for executor to decrypt...");

  const yesData = await pollUntil(yesReq.address, (d) => {
    if (d.length < 107) return false;
    const total = readU32LE(d, 99);
    const written = readU32LE(d, 103);
    return written === total && total > 0;
  });
  ok("Yes tally decrypted");

  const noData = await pollUntil(noReq.address, (d) => {
    if (d.length < 107) return false;
    const total = readU32LE(d, 99);
    const written = readU32LE(d, 103);
    return written === total && total > 0;
  });
  ok("No tally decrypted");

  // ── 6. Reveal Results ──
  log("6/6", "Revealing tallies on-chain...");

  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: Uint8Array.from([4, 1]), // reveal_tally, is_yes=true
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(yesReq.address, AccountRole.READONLY),
        acct(payer.address, AccountRole.READONLY_SIGNER, payer),
      ],
    },
  ]);
  await sendTx(payer, [
    {
      programAddress: VOTING_PROGRAM,
      data: Uint8Array.from([4, 0]), // reveal_tally, is_yes=false
      accounts: [
        acct(proposalPda, AccountRole.WRITABLE),
        acct(noReq.address, AccountRole.READONLY),
        acct(payer.address, AccountRole.READONLY_SIGNER, payer),
      ],
    },
  ]);

  // Read final state
  const propResp = await rpc
    .getAccountInfo(proposalPda, { encoding: "base64" })
    .send();
  const propData =
    typeof propResp.value!.data === "object" && Array.isArray(propResp.value!.data)
      ? Uint8Array.from(atob(propResp.value!.data[0] as string), (c) => c.charCodeAt(0))
      : Uint8Array.from(atob(propResp.value!.data as string), (c) => c.charCodeAt(0));

  const totalVotes = readU64LE(propData, 130);
  const revealedYes = readU64LE(propData, 138);
  const revealedNo = readU64LE(propData, 146);

  console.log("\n\x1b[1m\u2550\u2550\u2550 Results \u2550\u2550\u2550\x1b[0m\n");
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
  if (err.cause) console.error("Cause:", err.cause);
  if (err.logs) console.error("Logs:", err.logs);
  process.exit(1);
});
