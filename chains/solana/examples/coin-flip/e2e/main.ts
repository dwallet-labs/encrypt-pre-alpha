#!/usr/bin/env bun
/**
 * Encrypted Coin Flip E2E Demo
 *
 * Provably fair with on-chain escrow: result = commit_a XOR commit_b.
 * XOR=1 -> side_a wins, XOR=0 -> side_b wins.
 * Both sides deposit equal bets. Winner gets 2x from escrow.
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <COINFLIP_PROGRAM_ID>
 */

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { setupEncrypt, Chain } from "../../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pollUntil, mockCiphertext, isVerified, isDecrypted } from "../../../_shared/helpers.ts";
import {
  deriveCoinFlipPdas,
  createGameIx,
  playIx,
  requestResultDecryptionIx,
  revealResultIx,
} from "./instructions.ts";

const RPC_URL = "https://api.devnet.solana.com";
const FHE_UINT64 = 4;

const [encryptArg, coinflipArg] = process.argv.slice(2);
if (!encryptArg || !coinflipArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <COINFLIP_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const COINFLIP_PROGRAM = new PublicKey(coinflipArg);
const connection = new Connection(RPC_URL, "confirmed");
const payer = Keypair.generate();

async function main() {
  console.log("\n\x1b[1m=== Encrypted Coin Flip E2E Demo ===\x1b[0m\n");

  const { accounts: enc, encrypt } = await setupEncrypt(
    connection, payer, ENCRYPT_PROGRAM
  );

  const { gameId, gamePda, gameBump, cpiAuthority, cpiBump } =
    deriveCoinFlipPdas(COINFLIP_PROGRAM);

  const ctx = {
    programId: COINFLIP_PROGRAM, enc, payer: payer.publicKey,
    gamePda, gameBump, gameId, cpiAuthority, cpiBump,
  };

  // 1. Side A creates game
  const sideAValue = 1n;
  log("1/5", `Side A creating game (commit=${sideAValue})...`);

  const { ciphertextIdentifiers: sideAIds } = await encrypt.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(sideAValue), fheType: FHE_UINT64 }],
    authorized: COINFLIP_PROGRAM.toBytes(),
    networkEncryptionPublicKey: enc.networkKey,
  });
  const commitACt = new PublicKey(sideAIds[0]);
  ok(`Side A commit CT: ${commitACt.toBase58()}`);

  const resultCt = Keypair.generate();
  await sendTx(connection, payer, [createGameIx(ctx, commitACt, resultCt.publicKey)], [resultCt]);
  ok(`Game: ${gamePda.toBase58()}`);
  ok(`Result CT: ${resultCt.publicKey.toBase58()}`);

  // 2. Side B joins
  const sideBValue = 0n;
  log("2/5", `Side B joining (commit=${sideBValue})...`);

  const sideB = Keypair.generate();
  const airdropSig = await connection.requestAirdrop(sideB.publicKey, 1e9);
  await connection.confirmTransaction(airdropSig);

  const { ciphertextIdentifiers: sideBIds } = await encrypt.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(sideBValue), fheType: FHE_UINT64 }],
    authorized: COINFLIP_PROGRAM.toBytes(),
    networkEncryptionPublicKey: enc.networkKey,
  });
  const commitBCt = new PublicKey(sideBIds[0]);
  ok(`Side B commit CT: ${commitBCt.toBase58()}`);

  await sendTx(connection, payer,
    [playIx(ctx, sideB.publicKey, commitACt, commitBCt, resultCt.publicKey)],
    [sideB]
  );
  ok("Side B played!");

  log("2/5", "Waiting for executor to compute XOR...");
  await pollUntil(connection, resultCt.publicKey, isVerified, 60_000);
  ok("XOR result committed");

  // 3. Request decryption
  log("3/5", "Requesting decryption...");
  const decReq = Keypair.generate();
  await sendTx(connection, payer,
    [requestResultDecryptionIx(ctx, decReq.publicKey, resultCt.publicKey)], [decReq]
  );

  log("3/5", "Waiting for executor to decrypt...");
  await pollUntil(connection, decReq.publicKey, isDecrypted);
  ok("Result decrypted");

  // 4. Read decrypted value to determine winner
  const gameData = (await connection.getAccountInfo(gamePda))!.data as Buffer;
  const sideAKey = new PublicKey(gameData.subarray(1, 33));
  const sideBKey = new PublicKey(gameData.subarray(129, 161));

  // We need to figure out the winner from the decrypted value
  // For the demo, we try side_a first; if XOR=1 -> side_a wins, XOR=0 -> side_b wins
  // Read pending_digest to determine result direction
  log("4/5", "Revealing result on-chain...");
  // Try with side_a as winner first (XOR=1 case)
  try {
    await sendTx(connection, payer, [
      revealResultIx(COINFLIP_PROGRAM, gamePda, decReq.publicKey, payer.publicKey, sideAKey),
    ]);
  } catch {
    // XOR=0 case: side_b wins
    await sendTx(connection, payer, [
      revealResultIx(COINFLIP_PROGRAM, gamePda, decReq.publicKey, payer.publicKey, sideBKey),
    ]);
  }

  const finalGameData = (await connection.getAccountInfo(gamePda))!.data as Buffer;
  const revealedResult = finalGameData[195]; // 1=side_a wins, 2=side_b wins

  console.log("\n\x1b[1m=== Result ===\x1b[0m\n");
  val("Side A commit", sideAValue);
  val("Side B commit", sideBValue);
  val("XOR result", `${sideAValue} ^ ${sideBValue} = ${sideAValue ^ sideBValue}`);

  if (revealedResult === 1) {
    console.log(`\n  \x1b[32mSIDE A WINS!\x1b[0m\n`);
  } else {
    console.log(`\n  \x1b[31mSIDE B WINS!\x1b[0m\n`);
  }

  encrypt.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
