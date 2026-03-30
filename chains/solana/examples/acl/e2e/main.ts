#!/usr/bin/env bun
/**
 * Encrypted ACL E2E Demo
 *
 * Flow: create resource → grant READ+WRITE → check READ (pass) →
 *       revoke READ → check READ (fail) → decrypt perms = 2 (WRITE only)
 *
 * Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <ACL_PROGRAM_ID>
 */

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { setupEncrypt, Chain } from "../../../_shared/encrypt-setup.ts";
import { log, ok, val, sendTx, pollUntil, pda, mockCiphertext, isVerified, isDecrypted } from "../../../_shared/helpers.ts";
import {
  deriveAclPdas,
  createResourceIx,
  modifyPermissionIx,
  checkPermissionIx,
  requestCheckDecryptionIx,
  requestPermissionsDecryptionIx,
  type AclContext,
} from "./instructions.ts";

const RPC_URL = "https://api.devnet.solana.com";
const FHE_UINT64 = 4;

const [encryptArg, aclArg] = process.argv.slice(2);
if (!encryptArg || !aclArg) {
  console.error("Usage: bun main.ts <ENCRYPT_PROGRAM_ID> <ACL_PROGRAM_ID>");
  process.exit(1);
}

const ENCRYPT_PROGRAM = new PublicKey(encryptArg);
const ACL_PROGRAM = new PublicKey(aclArg);
const connection = new Connection(RPC_URL, "confirmed");
const payer = Keypair.generate();

/** Grant or revoke a permission and wait for executor to commit. */
async function grantOrRevoke(
  ctx: AclContext,
  encrypt: ReturnType<typeof import("../../../_shared/encrypt-setup.ts").setupEncrypt> extends Promise<infer T> ? T["encrypt"] : never,
  permsCt: PublicKey,
  opcode: 1 | 2,
  value: bigint,
  label: string
) {
  log("2/6", `${label}...`);
  const { ciphertextIdentifiers } = await encrypt.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(value), fheType: FHE_UINT64 }],
    authorized: ACL_PROGRAM.toBytes(),
    networkEncryptionPublicKey: ctx.enc.networkKey,
  });
  const inputCt = new PublicKey(ciphertextIdentifiers[0]);
  ok(`Input CT: ${inputCt.toBase58()}`);

  await sendTx(connection, payer, [
    modifyPermissionIx(ctx, payer.publicKey, permsCt, inputCt, opcode),
  ]);
  await pollUntil(connection, permsCt, isVerified, 60_000);
  ok(`${label} committed`);
}

/** Check a permission, decrypt, and return the result. */
async function checkPermission(
  ctx: AclContext,
  encrypt: ReturnType<typeof import("../../../_shared/encrypt-setup.ts").setupEncrypt> extends Promise<infer T> ? T["encrypt"] : never,
  permsCt: PublicKey,
  checkerName: string,
  permValue: bigint
): Promise<bigint> {
  log("3/6", `${checkerName} checking permission (bit=${permValue})...`);

  const checker = Keypair.generate();
  const airdropSig = await connection.requestAirdrop(checker.publicKey, 1e9);
  await connection.confirmTransaction(airdropSig);

  const { ciphertextIdentifiers } = await encrypt.createInput({
    chain: Chain.Solana,
    inputs: [{ ciphertextBytes: mockCiphertext(permValue), fheType: FHE_UINT64 }],
    authorized: ACL_PROGRAM.toBytes(),
    networkEncryptionPublicKey: ctx.enc.networkKey,
  });
  const bitCt = new PublicKey(ciphertextIdentifiers[0]);

  const [checkPda, checkBump] = pda(
    [Buffer.from("check"), ctx.resourceId, checker.publicKey.toBuffer()],
    ctx.programId
  );
  const resultCt = Keypair.generate();

  await sendTx(connection, payer,
    [checkPermissionIx(ctx, checkPda, checkBump, checker.publicKey, permsCt, bitCt, resultCt.publicKey)],
    [checker, resultCt]
  );
  await pollUntil(connection, resultCt.publicKey, isVerified, 60_000);
  ok("Check result committed");

  // Request + wait for decryption
  const decReq = Keypair.generate();
  await sendTx(connection, payer,
    [requestCheckDecryptionIx(ctx, checkPda, decReq.publicKey, resultCt.publicKey)],
    [decReq]
  );
  await pollUntil(connection, decReq.publicKey, isDecrypted);

  const reqData = (await connection.getAccountInfo(decReq.publicKey))!.data as Buffer;
  return reqData.readBigUInt64LE(107);
}

async function main() {
  console.log("\n\x1b[1m═══ Encrypted ACL E2E Demo ═══\x1b[0m\n");

  const { accounts: enc, encrypt } = await setupEncrypt(
    connection, payer, ENCRYPT_PROGRAM
  );

  const { resourceId, resourcePda, resourceBump, cpiAuthority, cpiBump } =
    deriveAclPdas(ACL_PROGRAM);

  const ctx: AclContext = {
    programId: ACL_PROGRAM, enc, payer: payer.publicKey,
    resourcePda, resourceBump, resourceId, cpiAuthority, cpiBump,
  };

  // 1. Create resource
  log("1/6", "Creating resource with encrypted zero permissions...");
  const permsCt = Keypair.generate();
  await sendTx(connection, payer, [createResourceIx(ctx, permsCt.publicKey)], [permsCt]);
  ok(`Resource: ${resourcePda.toBase58()}`);
  ok(`Permissions CT: ${permsCt.publicKey.toBase58()}`);

  // 2. Grant READ (bit 0 = 1) and WRITE (bit 1 = 2)
  await grantOrRevoke(ctx, encrypt, permsCt.publicKey, 1, 1n, "Granting READ (bit 0)");
  await grantOrRevoke(ctx, encrypt, permsCt.publicKey, 1, 2n, "Granting WRITE (bit 1)");

  // 3. Check READ -- should have it
  const check1 = await checkPermission(ctx, encrypt, permsCt.publicKey, "Alice", 1n);
  val("Check READ result", check1);
  console.log(
    check1 > 0n
      ? "  \x1b[32m  HAS READ permission\x1b[0m"
      : "  \x1b[31m  NO READ permission\x1b[0m"
  );

  // 4. Revoke READ (mask = all bits except bit 0)
  await grantOrRevoke(ctx, encrypt, permsCt.publicKey, 2, BigInt("0xFFFFFFFFFFFFFFFE"), "Revoking READ");

  // 5. Check READ -- should NOT have it
  const check2 = await checkPermission(ctx, encrypt, permsCt.publicKey, "Bob", 1n);
  val("Check READ result (after revoke)", check2);
  console.log(
    check2 > 0n
      ? "  \x1b[32m  HAS READ permission\x1b[0m"
      : "  \x1b[31m  NO READ permission\x1b[0m"
  );

  // 6. Decrypt full permissions
  log("6/6", "Decrypting full permissions bitmask...");
  const permReq = Keypair.generate();
  await sendTx(connection, payer,
    [requestPermissionsDecryptionIx(ctx, permReq.publicKey, permsCt.publicKey)],
    [permReq]
  );
  await pollUntil(connection, permReq.publicKey, isDecrypted);

  const permReqData = (await connection.getAccountInfo(permReq.publicKey))!.data as Buffer;
  const fullPerms = permReqData.readBigUInt64LE(107);

  console.log("\n\x1b[1m═══ Results ═══\x1b[0m\n");
  val("Permissions bitmask", `0b${fullPerms.toString(2).padStart(8, "0")} (${fullPerms})`);
  val("READ (bit 0)", (fullPerms & 1n) ? "YES" : "NO");
  val("WRITE (bit 1)", (fullPerms & 2n) ? "YES" : "NO");

  const expected = 2n;
  if (fullPerms === expected) {
    console.log(`\n  \x1b[32m✓ Permissions = ${fullPerms} (WRITE only, as expected)\x1b[0m\n`);
  } else {
    console.log(`\n  \x1b[31m✗ Expected ${expected}, got ${fullPerms}\x1b[0m\n`);
  }

  encrypt.close();
}

main().catch((err) => {
  console.error("\x1b[31mError:\x1b[0m", err.message || err);
  process.exit(1);
});
