# Building the Voting App

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

React frontend — fully client-side, no backend needed.

## What you'll learn

- How encrypted votes are created locally and cast
- How the authority requests decryption and reveals results directly from the browser
- Multi-wallet support via URL sharing

## Architecture

```
React App (:5173)                              Executor (:50051)
     |                                              |
     |-- encryptValue() (local)                     |
     |-- gRPC-Web createInput =====================>|
     |<- ciphertextId ============================--|
     |                                              |
     |-- create_proposal tx (on-chain) ------------>|
     |-- cast_vote tx ----------------------------->|
     |                          Executor computes   |
     |                          conditional add     |
     |                                              |
     |-- close_proposal tx ------------------------>|
     |                                              |
     |-- request_tally_decryption tx x2 ----------->|
     |   (yes + no, authority signs)                |
     |-- poll for decryption results -------------->|
     |                                              |
     |-- reveal_tally tx x2 ----------------------->|
     |   (authority signs)                          |
     |                                              |
     |-- read proposal account for final counts     |
```

Everything happens in the browser. The voter encrypts locally and sends ciphertext to the executor via gRPC-Web. The authority requests decryption and reveals results by signing transactions with their wallet — no backend keypair needed.

## React frontend

The frontend (`react/src/App.tsx`) handles the full proposal lifecycle.

**Creating a proposal:**

The frontend creates the proposal PDA and two ciphertext keypair accounts (yes_count, no_count) initialized to encrypted zero:

```typescript
const proposalId = Buffer.from(Keypair.generate().publicKey.toBytes());
const [pda, bump] = findPda([Buffer.from("proposal"), proposalId], VOTING_PROGRAM);
const yesCt = Keypair.generate();
const noCt = Keypair.generate();

const tx = new Transaction().add(new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: createData,
  keys: [
    { pubkey: pda, isSigner: false, isWritable: true },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
    { pubkey: yesCt.publicKey, isSigner: true, isWritable: true },
    { pubkey: noCt.publicKey, isSigner: true, isWritable: true },
    // ... encrypt program accounts ...
  ],
}));
await wallet.sendTransaction(tx, connection, { signers: [yesCt, noCt] });
```

**Casting a vote:**

1. Encrypt the vote locally via `encryptValue()` and send ciphertext to executor via gRPC-Web
2. If previous votes exist, wait for ciphertext accounts to reach VERIFIED status (the executor must finish the previous graph before a new one can use the same accounts)
3. Send `cast_vote` transaction with the encrypted vote + proposal's yes/no ciphertext accounts

The plaintext never leaves the browser. `encryptValue()` is client-side mock encryption (production: WASM FHE encryptor). gRPC-Web works via `fetch()` -- no special proxy needed; the executor uses `tonic-web`.

```typescript
import { createEncryptWebClient, encryptValue, Chain } from "@encrypt.xyz/pre-alpha-solana-client/grpc-web";

const grpcClient = createEncryptWebClient("https://pre-alpha-dev-1.encrypt.ika-network.net:443");

const voteVal = voteYes ? 1 : 0;
const ids = await grpcClient.createInput({
  chain: Chain.SOLANA,
  inputs: [{ ciphertextBytes: encryptValue(voteVal), fheType: FHE_BOOL }],
  authorized: VOTING_PROGRAM.toBytes(),
  networkEncryptionPublicKey: networkKey,
});
const voteCt = new PublicKey(ids[0]);

// Wait for previous vote's computation to finish
if (proposal.totalVotes > 0) {
  await pollUntil(connection, proposal.yesCt, isVerified, 60_000);
}

const ix = new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: Buffer.from([1, vrBump, cpiBump]),
  keys: [
    { pubkey: proposal.pda, isSigner: false, isWritable: true },
    { pubkey: voteRecord, isSigner: false, isWritable: true },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
    { pubkey: voteCt, isSigner: false, isWritable: true },
    { pubkey: proposal.yesCt, isSigner: false, isWritable: true },
    { pubkey: proposal.noCt, isSigner: false, isWritable: true },
    // ... encrypt program accounts ...
  ],
});
await wallet.sendTransaction(new Transaction().add(ix), connection);
```

**Decrypting and revealing:**

The authority handles decryption entirely from the browser — no backend needed. The wallet signs the decryption request and reveal transactions directly:

```typescript
// 1. Request decryption for yes tally
const yesReq = Keypair.generate();
await sendTx([new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: Buffer.from([3, cpiBump, 1]),  // disc=3, is_yes=1
  keys: [
    { pubkey: proposal.pda, isSigner: false, isWritable: true },
    { pubkey: yesReq.publicKey, isSigner: true, isWritable: true },
    { pubkey: proposal.yesCt, isSigner: false, isWritable: false },
    ...encCpi(),
  ],
})], [yesReq]);

// 2. Request decryption for no tally
const noReq = Keypair.generate();
await sendTx([new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: Buffer.from([3, cpiBump, 0]),  // disc=3, is_yes=0
  keys: [
    { pubkey: proposal.pda, isSigner: false, isWritable: true },
    { pubkey: noReq.publicKey, isSigner: true, isWritable: true },
    { pubkey: proposal.noCt, isSigner: false, isWritable: false },
    ...encCpi(),
  ],
})], [noReq]);

// 3. Poll until both are decrypted
await pollUntil(connection, yesReq.publicKey, isDecrypted);
await pollUntil(connection, noReq.publicKey, isDecrypted);

// 4. Reveal yes (authority signature required)
await sendTx([new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: Buffer.from([4, 1]),  // disc=4, is_yes=1
  keys: [
    { pubkey: proposal.pda, isSigner: false, isWritable: true },
    { pubkey: yesReq.publicKey, isSigner: false, isWritable: false },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
  ],
})]);

// 5. Reveal no
await sendTx([new TransactionInstruction({
  programId: VOTING_PROGRAM,
  data: Buffer.from([4, 0]),  // disc=4, is_yes=0
  keys: [
    { pubkey: proposal.pda, isSigner: false, isWritable: true },
    { pubkey: noReq.publicKey, isSigner: false, isWritable: false },
    { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
  ],
})]);

// 6. Read final results from on-chain proposal account
const propData = (await connection.getAccountInfo(proposal.pda))!.data as Buffer;
const yesCount = Number(propData.readBigUInt64LE(138));
const noCount = Number(propData.readBigUInt64LE(146));
```

## Multi-wallet support via URL sharing

When a proposal is created, the URL is updated with query params:

```typescript
const params = new URLSearchParams({
  proposal: pda.toBase58(),
  yesCt: yesCt.toBase58(),
  noCt: noCt.toBase58(),
});
window.history.replaceState({}, "", `?${params}`);
```

Other voters can open this URL in their browser. On mount, the app reads the URL params and loads the proposal from on-chain state:

```typescript
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const pdaStr = params.get("proposal");
  const yesStr = params.get("yesCt");
  const noStr = params.get("noCt");
  if (pdaStr && yesStr && noStr) {
    const pda = new PublicKey(pdaStr);
    connection.getAccountInfo(pda).then((info) => {
      if (!info) return;
      const d = info.data as Buffer;
      const isOpen = d[129] === 1;
      const totalVotes = Number(d.readBigUInt64LE(130));
      setProposal({ pda, yesCt: new PublicKey(yesStr), noCt: new PublicKey(noStr), isOpen, totalVotes, /* ... */ });
    });
  }
}, [connection]);
```

A "Copy Voting Link" button makes sharing easy.

## Running on Devnet

The app connects to Solana devnet and the pre-alpha executor automatically. No local validator or executor setup is needed.

```bash
cd chains/solana/examples/voting/react
bun run dev
```

Open `http://localhost:5173`, connect a wallet (e.g. Phantom set to devnet), airdrop SOL, create a proposal, share the link with other wallets, vote, close, and decrypt.
