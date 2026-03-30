/**
 * Shared Encrypt program setup for e2e demos.
 *
 * Derives PDAs, reads config, creates deposit — identical across all examples.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";

import { createEncryptClient } from "../../clients/typescript/src/grpc.ts";
import { log, ok, pda, sendTx } from "./helpers.ts";

export { Chain } from "../../clients/typescript/src/grpc.ts";

/** All the Encrypt program accounts needed for CPI. */
export interface EncryptAccounts {
  encryptProgram: PublicKey;
  configPda: PublicKey;
  eventAuthority: PublicKey;
  depositPda: PublicKey;
  networkKeyPda: PublicKey;
  networkKey: Buffer;
}

/** Return value from `setupEncrypt`. */
export interface EncryptSetup {
  accounts: EncryptAccounts;
  encrypt: ReturnType<typeof createEncryptClient>;
}

/**
 * Connect to the executor gRPC, derive Encrypt PDAs, read config,
 * and create the fee deposit. Returns everything needed for CPI.
 */
export async function setupEncrypt(
  connection: Connection,
  payer: Keypair,
  encryptProgram: PublicKey,
  grpcUrl = "pre-alpha-dev-1.encrypt.ika-network.net:443"
): Promise<EncryptSetup> {
  const encrypt = createEncryptClient(grpcUrl);
  log("Setup", `Connected to executor gRPC at ${grpcUrl}`);

  // Fund payer
  log("Setup", "Funding payer...");
  const sig = await connection.requestAirdrop(payer.publicKey, 100e9);
  await connection.confirmTransaction(sig);
  ok(`Payer: ${payer.publicKey.toBase58()}`);

  // Derive Encrypt PDAs
  const [configPda] = pda([Buffer.from("encrypt_config")], encryptProgram);
  const [eventAuthority] = pda([Buffer.from("__event_authority")], encryptProgram);
  const [depositPda, depositBump] = pda(
    [Buffer.from("encrypt_deposit"), payer.publicKey.toBuffer()],
    encryptProgram
  );
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = pda(
    [Buffer.from("network_encryption_key"), networkKey],
    encryptProgram
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

  await sendTx(connection, payer, [
    new TransactionInstruction({
      programId: encryptProgram,
      data: depositData,
      keys: [
        { pubkey: depositPda, isSigner: false, isWritable: true },
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: vaultPk, isSigner: vaultPk.equals(payer.publicKey), isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
    }),
  ]);
  ok("Deposit created");

  return {
    accounts: { encryptProgram, configPda, eventAuthority, depositPda, networkKeyPda, networkKey },
    encrypt,
  };
}

/**
 * Build the encrypt CPI account metas that every instruction needs.
 * Pass the example program as `callerProgram`.
 */
export function encryptCpiAccounts(
  enc: EncryptAccounts,
  callerProgram: PublicKey,
  cpiAuthority: PublicKey,
  payer: PublicKey
) {
  return [
    { pubkey: enc.encryptProgram, isSigner: false, isWritable: false },
    { pubkey: enc.configPda, isSigner: false, isWritable: true },
    { pubkey: enc.depositPda, isSigner: false, isWritable: true },
    { pubkey: cpiAuthority, isSigner: false, isWritable: false },
    { pubkey: callerProgram, isSigner: false, isWritable: false },
    { pubkey: enc.networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: enc.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}
