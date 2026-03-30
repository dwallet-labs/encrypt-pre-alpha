/**
 * Encrypt gRPC client — static typed wrapper.
 *
 * Uses statically generated types from the proto (no runtime proto loading).
 * Re-exports types for convenience.
 */

import * as grpc from "@grpc/grpc-js";

// Re-export generated types
export {
  type EncryptedInput,
  type CreateInputRequest,
  type CreateInputResponse,
  type ReadCiphertextRequest,
  type ReadCiphertextResponse,
} from "./generated/grpc/encrypt_service";

import {
  Chain as ProtoChain,
  EncryptServiceClient as GrpcClient,
  type CreateInputResponse,
  type ReadCiphertextResponse,
  type EncryptedInput,
} from "./generated/grpc/encrypt_service";

/** Chain identifier (matches proto enum, camelCase for ergonomics). */
export const Chain = {
  Solana: ProtoChain.SOLANA,
} as const;
export type Chain = ProtoChain;

// ── CreateInput ──

export interface CreateInputParams {
  chain: Chain;
  inputs: EncryptedInput[];
  proof?: Buffer;
  authorized: Buffer;
  networkEncryptionPublicKey: Buffer;
}

export interface CreateInputResult {
  ciphertextIdentifiers: Buffer[];
}

// ── ReadCiphertext ──

export interface ReadCiphertextParams {
  /** BCS-serialized ReadCiphertextMessage. */
  message: Buffer;
  /** Ed25519 signature over `message`. Not required for public ciphertexts. */
  signature: Buffer;
  /** Public key of the signer (32 bytes). */
  signer: Buffer;
}

export interface ReadCiphertextResult {
  /** Production: re-encrypted ciphertext. Mock: plaintext bytes. */
  value: Buffer;
  /** FHE type discriminator. */
  fheType: number;
  /** On-chain digest. */
  digest: Buffer;
}

/**
 * BCS-encode a ReadCiphertextMessage.
 *
 * BCS format: chain(u8) + ciphertext_identifier(vec) + reencryption_key(vec) + epoch(u64)
 * where vec = ULEB128 length prefix + bytes.
 */
export function encodeReadCiphertextMessage(
  chain: number,
  ciphertextIdentifier: Uint8Array,
  reencryptionKey: Uint8Array,
  epoch: bigint
): Buffer {
  // BCS ULEB128: for lengths <= 127, it's just 1 byte
  const ctIdLen = ciphertextIdentifier.length;
  const rekeyLen = reencryptionKey.length;
  const totalLen = 1 + 1 + ctIdLen + 1 + rekeyLen + 8;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf[offset++] = chain;
  buf[offset++] = ctIdLen; // ULEB128 (works for len < 128)
  Buffer.from(ciphertextIdentifier).copy(buf, offset);
  offset += ctIdLen;
  buf[offset++] = rekeyLen;
  Buffer.from(reencryptionKey).copy(buf, offset);
  offset += rekeyLen;
  buf.writeBigUInt64LE(epoch, offset);

  return buf;
}

/** gRPC endpoint for the Encrypt pre-alpha on Solana devnet. */
export const DEVNET_PRE_ALPHA_GRPC_URL =
  "pre-alpha-dev-1.encrypt.ika-network.net:443";

/**
 * Create a gRPC client connected to the Encrypt executor.
 *
 * Defaults to the pre-alpha devnet endpoint (TLS).
 * Pass `"localhost:50051"` for local dev.
 */
export function createEncryptClient(
  grpcUrl: string = DEVNET_PRE_ALPHA_GRPC_URL
) {
  const isLocal =
    grpcUrl.startsWith("localhost") || grpcUrl.startsWith("127.0.0.1");
  const creds = isLocal
    ? grpc.credentials.createInsecure()
    : grpc.credentials.createSsl();
  const client = new GrpcClient(grpcUrl, creds);

  return {
    /**
     * Submit encrypted inputs and get back their on-chain identifiers.
     */
    createInput(params: CreateInputParams): Promise<CreateInputResult> {
      return new Promise((resolve, reject) => {
        client.createInput(
          {
            chain: params.chain,
            inputs: params.inputs.map((inp) => ({
              ciphertextBytes: Buffer.from(inp.ciphertextBytes),
              fheType: inp.fheType,
            })),
            proof: params.proof ?? Buffer.alloc(0),
            authorized: Buffer.from(params.authorized),
            networkEncryptionPublicKey: Buffer.from(
              params.networkEncryptionPublicKey
            ),
          },
          (
            err: grpc.ServiceError | null,
            response?: CreateInputResponse
          ) => {
            if (err) reject(err);
            else
              resolve({
                ciphertextIdentifiers: response!.ciphertextIdentifiers,
              });
          }
        );
      });
    },

    /**
     * Read a ciphertext off-chain.
     *
     * For public ciphertexts: signature/signer can be zero-filled.
     * For private ciphertexts: signature must be valid ed25519 over `message`.
     *
     * Use `encodeReadCiphertextMessage()` to build the BCS message.
     */
    readCiphertext(
      params: ReadCiphertextParams
    ): Promise<ReadCiphertextResult> {
      return new Promise((resolve, reject) => {
        client.readCiphertext(
          {
            message: params.message,
            signature: params.signature,
            signer: params.signer,
          },
          (
            err: grpc.ServiceError | null,
            response?: ReadCiphertextResponse
          ) => {
            if (err) reject(err);
            else
              resolve({
                value: response!.value as Buffer,
                fheType: response!.fheType,
                digest: response!.digest as Buffer,
              });
          }
        );
      });
    },

    close() {
      client.close();
    },
  };
}
