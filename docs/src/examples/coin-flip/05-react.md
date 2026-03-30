# Building the Full-Stack Coin Flip App

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

React frontend + Bun house backend.

## What you'll learn

- The player-vs-house architecture
- How the browser encrypts locally and sends ciphertext via gRPC-Web
- How the house backend auto-resolves games
- Frontend flow: bet, flip, poll, result

## Architecture

```
React App (:5173)        House Backend (:3001)       Executor (:50051)
     |                        |                          |
     |-- encryptValue() ----->|                          |
     |-- gRPC-Web createInput =========================>|
     |<- ciphertextId ================================--|
     |                        |                          |
     |-- create_game tx ----->| (on-chain)               |
     |                        |                          |
     |-- POST /api/join ----->|                          |
     |                        |-- gRPC createInput ----->|
     |                        |-- play tx --------------->|
     |                        |-- poll result_ct -------->|
     |                        |-- request_decryption ---->|
     |                        |-- poll decryption ------->|
     |                        |-- reveal_result --------->|
     |                        |                          |
     |-- GET /api/game ------>|                          |
     |<- { status, result } --|                          |
```

The player encrypts locally in the browser and sends ciphertext directly to the executor via gRPC-Web (`fetch()`-based, no special proxy). The house backend runs as an automated counterparty -- it loads a persistent keypair from `HOUSE_SECRET_KEY` in the `.env` file and handles everything after the player creates a game.

## House backend

The backend (`react/server/house.ts`) has two responsibilities:

**1. Join games as side B.**

When the frontend calls `POST /api/join`, the backend:
- Reads the game PDA to get `commit_a`, `result_ct`, and `bet_lamports`
- Creates its own encrypted commit via gRPC
- Sends the `play` instruction (matches bet + triggers XOR graph)

```typescript
// House creates encrypted commit
const houseVal = Math.random() < 0.5 ? 0 : 1;
const { ciphertextIdentifiers } = await encryptClient.createInput({
  chain: Chain.Solana,
  inputs: [{ ciphertextBytes: mockCiphertext(BigInt(houseVal)), fheType: FHE_UINT64 }],
  authorized: COINFLIP_PROGRAM.toBytes(),
  networkEncryptionPublicKey: networkKey,
});
const commitB = new PublicKey(ciphertextIdentifiers[0]);

// Send play instruction
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
```

**2. Resolve the game.**

After play, the backend polls `result_ct` until the executor commits the XOR result (status = VERIFIED). Then it requests decryption, polls until complete, reads the result, and sends `reveal_result` to pay the winner:

```typescript
// Poll for XOR computation
await pollUntil(resultCt, isVerified, 60_000);

// Request decryption
const decReq = Keypair.generate();
await sendTx([new TransactionInstruction({
  programId: COINFLIP_PROGRAM,
  data: Buffer.from([2, cpiBump]),
  keys: [
    { pubkey: gamePda, isSigner: false, isWritable: true },
    { pubkey: decReq.publicKey, isSigner: true, isWritable: true },
    { pubkey: resultCt, isSigner: false, isWritable: false },
    ...encCpi(),
  ],
})], [decReq]);

// Poll for decryption
await pollUntil(decReq.publicKey, isDecrypted);

// Read result and reveal
const reqData = (await connection.getAccountInfo(decReq.publicKey))!.data as Buffer;
const xor = reqData.readBigUInt64LE(107);
const sideAWins = xor === 1n;
const winner = sideAWins ? sideA : house.publicKey;

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
```

## React frontend

The frontend (`react/src/App.tsx`) handles wallet connection, bet input, and game lifecycle.

**Player flow:**

1. Connect wallet (Solana wallet adapter)
2. Enter bet amount in SOL
3. Click "Flip"
4. Frontend encrypts commit locally and sends ciphertext to executor via gRPC-Web
5. Frontend sends `create_game` transaction (deposits bet, stores commit)
6. Frontend calls `POST /api/join` to tell house to play
7. Frontend polls `GET /api/game/:pda` for status updates
8. Display result: win (+2x bet) or lose

**Creating the game on-chain:**

The player's commit is encrypted in the browser -- the plaintext never leaves the client. `encryptValue()` is a client-side mock encryption function (production: WASM FHE encryptor). gRPC-Web works via `fetch()` -- no special proxy needed; the executor's `tonic-web` layer handles it.

```typescript
import { createEncryptWebClient, encryptValue, Chain } from "@encrypt.xyz/pre-alpha-solana-client/grpc-web";

const grpcClient = createEncryptWebClient("https://pre-alpha-dev-1.encrypt.ika-network.net:443");

const playerVal = Math.random() < 0.5 ? 0 : 1;
const ids = await grpcClient.createInput({
  chain: Chain.SOLANA,
  inputs: [{ ciphertextBytes: encryptValue(BigInt(playerVal)), fheType: FHE_UINT64 }],
  authorized: COINFLIP_PROGRAM.toBytes(),
  networkEncryptionPublicKey: networkKey,
});
const commitACt = new PublicKey(ids[0]);

const gameId = Buffer.from(Keypair.generate().publicKey.toBytes());
const [gamePda, gameBump] = findPda([Buffer.from("game"), gameId], COINFLIP_PROGRAM);
const resultCt = Keypair.generate();

const createData = Buffer.alloc(43);
createData[0] = 0; // discriminator
createData[1] = gameBump;
createData[2] = enc.cpiBump;
gameId.copy(createData, 3);
createData.writeBigUInt64LE(BigInt(betLamports), 35);

const tx = new Transaction().add(new TransactionInstruction({
  programId: COINFLIP_PROGRAM,
  data: createData,
  keys: [
    { pubkey: gamePda, isSigner: false, isWritable: true },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
    { pubkey: commitACt, isSigner: false, isWritable: false },
    { pubkey: resultCt.publicKey, isSigner: true, isWritable: true },
    { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.configPda, isSigner: false, isWritable: false },
    { pubkey: enc.depositPda, isSigner: false, isWritable: true },
    { pubkey: enc.cpiAuthority, isSigner: false, isWritable: false },
    { pubkey: COINFLIP_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
    { pubkey: enc.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ],
}));
await wallet.sendTransaction(tx, connection, { signers: [resultCt] });
```

**Polling for result:**

```typescript
const start = Date.now();
while (Date.now() - start < 120_000) {
  const r = await fetch(`${HOUSE_API}/api/game/${gamePda.toBase58()}`);
  const state = await r.json();
  if (state.status === "resolved") {
    const won = state.result === 1;
    setResult(won ? "win" : "lose");
    return;
  }
  await new Promise((r) => setTimeout(r, 800));
}
```

## Encrypt deposit

Both the frontend and house backend need an Encrypt deposit account before they can use Encrypt CPIs. The frontend creates one on first use:

```typescript
const ensureDeposit = async () => {
  if (await connection.getAccountInfo(enc.depositPda)) return; // already exists
  const data = Buffer.alloc(18);
  data[0] = 14; // create_deposit discriminator
  data[1] = enc.depositBump;
  const tx = new Transaction().add(new TransactionInstruction({
    programId: ENCRYPT_PROGRAM, data,
    keys: [/* deposit PDA, config, payer, vault, system_program */],
  }));
  await wallet.sendTransaction(tx, connection);
};
```

## Running on Devnet

The app connects to Solana devnet and the pre-alpha executor automatically. No local validator or executor setup is needed.

```bash
# Set the house secret key in the .env (Bun loads from the react/ directory)
# Supports base58 or JSON array format
echo 'HOUSE_SECRET_KEY=[1,2,3,...,64 bytes]' >> chains/solana/examples/coin-flip/react/.env

# Fund the house wallet on devnet
solana airdrop 2 <HOUSE_PUBLIC_KEY> --url devnet

# Terminal 1: Start the house backend
cd chains/solana/examples/coin-flip/react
bun server/house.ts

# Terminal 2: Start the React dev server
cd chains/solana/examples/coin-flip/react
bun run dev
```

Open `http://localhost:5173`, connect a wallet (e.g. Phantom set to devnet), airdrop SOL, and flip.
