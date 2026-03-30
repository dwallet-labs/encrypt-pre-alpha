#!/usr/bin/env bun
/**
 * Confidential Counter E2E Demo
 *
 * Flow: create counter → increment 5x → decrement 2x → decrypt → reveal = 3
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <COUNTER_PROGRAM_ID>
 */

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { setupEncrypt } from "../../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pollUntil, isVerified, isDecrypted } from "../../../_shared/helpers.ts";
import {
  deriveCounterPdas,
  createCounterIx,
  counterOpIx,
  requestDecryptionIx,
  revealValueIx,
} from "./instructions.ts";

const RPC_URL = "https://api.devnet.solana.com";

const [encryptArg, counterArg] = process.argv.slice(2);
if (!encryptArg || !counterArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <COUNTER_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const COUNTER_PROGRAM = new PublicKey(counterArg);
const connection = new Connection(RPC_URL, "confirmed");
const payer = Keypair.generate();

async function main() {
  console.log("\n\x1b[1m═══ Confidential Counter E2E Demo ═══\x1b[0m\n");

  const { accounts: enc, encrypt } = await setupEncrypt(
    connection, payer, ENCRYPT_PROGRAM
  );

  const { counterId, counterPda, counterBump, cpiAuthority, cpiBump } =
    deriveCounterPdas(COUNTER_PROGRAM);

  const ctx = {
    programId: COUNTER_PROGRAM, enc, payer: payer.publicKey,
    counterPda, counterBump, counterId, cpiAuthority, cpiBump,
  };

  // 1. Create counter
  log("1/6", "Creating counter...");
  const valueCt = Keypair.generate();
  await sendTx(connection, payer, [createCounterIx(ctx, valueCt.publicKey)], [valueCt]);
  ok(`Counter: ${counterPda.toBase58()}`);
  ok(`Value CT: ${valueCt.publicKey.toBase58()}`);

  // 2. Increment 5 times
  for (let i = 1; i <= 5; i++) {
    log("2/6", `Incrementing (${i}/5)...`);
    await sendTx(connection, payer, [counterOpIx(ctx, valueCt.publicKey, 1)]);
    await pollUntil(connection, valueCt.publicKey, isVerified, 60_000);
    ok(`Increment ${i} committed`);
  }

  // 3. Decrement 2 times
  for (let i = 1; i <= 2; i++) {
    log("3/6", `Decrementing (${i}/2)...`);
    await sendTx(connection, payer, [counterOpIx(ctx, valueCt.publicKey, 2)]);
    await pollUntil(connection, valueCt.publicKey, isVerified, 60_000);
    ok(`Decrement ${i} committed`);
  }

  // 4. Request decryption
  log("4/6", "Requesting decryption...");
  const decReq = Keypair.generate();
  await sendTx(connection, payer,
    [requestDecryptionIx(ctx, valueCt.publicKey, decReq.publicKey)], [decReq]
  );
  ok(`Decryption requested: ${decReq.publicKey.toBase58()}`);

  // 5. Wait for executor
  log("5/6", "Waiting for executor to decrypt...");
  await pollUntil(connection, decReq.publicKey, isDecrypted);
  ok("Value decrypted");

  // 6. Reveal value
  log("6/6", "Revealing value on-chain...");
  await sendTx(connection, payer, [
    revealValueIx(COUNTER_PROGRAM, counterPda, decReq.publicKey, payer.publicKey),
  ]);

  const ctrData = (await connection.getAccountInfo(counterPda))!.data as Buffer;
  const revealedValue = ctrData.readBigUInt64LE(129);

  console.log("\n\x1b[1m═══ Result ═══\x1b[0m\n");
  val("Revealed value", revealedValue);

  const expected = 3n;
  if (revealedValue === expected) {
    console.log(`\n  \x1b[32m✓ Counter value is ${revealedValue} (5 inc - 2 dec = 3)\x1b[0m\n`);
  } else {
    console.log(`\n  \x1b[31m✗ Expected ${expected}, got ${revealedValue}\x1b[0m\n`);
  }

  encrypt.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
