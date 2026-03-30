/**
 * Encrypt gRPC-Web client — browser-compatible.
 *
 * Uses @protobuf-ts/grpcweb-transport which works via fetch() in any browser.
 * Server must have tonic-web layer enabled (already configured in the executor).
 *
 * Usage:
 *   import { createEncryptWebClient, encryptValue, Chain } from "@encrypt.xyz/pre-alpha-solana-client/grpc-web";
 *
 *   const client = createEncryptWebClient("https://pre-alpha-dev-1.encrypt.ika-network.net:443");
 *   const ct = encryptValue(42);
 *   const ids = await client.createInput({
 *     chain: Chain.SOLANA,
 *     inputs: [{ ciphertextBytes: ct, fheType: 4 }],
 *     authorized: programId.toBytes(),
 *     networkEncryptionPublicKey: networkKey,
 *   });
 */

import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport";
import { EncryptServiceClient } from "./generated/grpc-web/encrypt_service.client";
import { Chain, type CreateInputRequest } from "./generated/grpc-web/encrypt_service";

export { Chain } from "./generated/grpc-web/encrypt_service";

export interface EncryptInput {
  ciphertextBytes: Uint8Array;
  fheType: number;
}

export interface CreateInputParams {
  chain: Chain;
  inputs: EncryptInput[];
  proof?: Uint8Array;
  authorized: Uint8Array;
  networkEncryptionPublicKey: Uint8Array;
}

/**
 * Create a browser gRPC-Web client for the Encrypt executor.
 *
 * @param baseUrl - Executor gRPC address, e.g. "https://pre-alpha-dev-1.encrypt.ika-network.net:443"
 */
export function createEncryptWebClient(baseUrl: string) {
  const transport = new GrpcWebFetchTransport({ baseUrl });
  const client = new EncryptServiceClient(transport);

  return {
    /**
     * Submit encrypted inputs and get back on-chain ciphertext identifiers.
     * Encryption happens CLIENT-SIDE — only ciphertext bytes cross the wire.
     */
    async createInput(params: CreateInputParams): Promise<Uint8Array[]> {
      const request: CreateInputRequest = {
        chain: params.chain,
        inputs: params.inputs.map((inp) => ({
          ciphertextBytes: inp.ciphertextBytes,
          fheType: inp.fheType,
        })),
        proof: params.proof ?? new Uint8Array(0),
        authorized: params.authorized,
        networkEncryptionPublicKey: params.networkEncryptionPublicKey,
      };

      const { response } = await client.createInput(request);
      return response.ciphertextIdentifiers;
    },
  };
}

/**
 * Client-side mock encryption (dev mode).
 * Encodes a plaintext value as little-endian u128 bytes.
 *
 * In production, this is replaced by a WASM FHE encryptor that produces
 * real ciphertexts + a ZK proof of valid encryption.
 */
export function encryptValue(value: number | bigint): Uint8Array {
  const buf = new Uint8Array(16);
  let v = BigInt(value);
  for (let i = 0; i < 16; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}
