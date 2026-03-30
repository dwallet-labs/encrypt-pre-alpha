# Confidential Counter: React Frontend

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## 1. Project Setup

The frontend uses Vite + React + Solana wallet adapter.

```bash
cd chains/solana/examples/counter/react
bun install
```

Dependencies in `package.json`:

```json
{
  "dependencies": {
    "@solana/wallet-adapter-base": "^0.9.23",
    "@solana/wallet-adapter-react": "^0.15.35",
    "@solana/wallet-adapter-react-ui": "^0.9.35",
    "@solana/wallet-adapter-wallets": "^0.19.32",
    "@solana/web3.js": "^1.95.3",
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  }
}
```

Entry point (`main.tsx`) wraps the app with Solana providers:

```typescript
const RPC_URL = "https://api.devnet.solana.com";

function Root() {
  const wallets = useMemo(() => [], []);
  return (
    <ConnectionProvider endpoint={RPC_URL}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>
          <App />
        </WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}
```

## 2. Program IDs

```typescript
const ENCRYPT_PROGRAM = new PublicKey(
  "Cq37zHSH1zB6xomYK2LjP6uXJvLR3uTehxA5W9wgHGvx"
);
const COUNTER_PROGRAM = new PublicKey(
  "CntR1111111111111111111111111111111111111111"
);
```

Update these to match your deployed program IDs.

## 3. PDA Derivation

All Encrypt infrastructure PDAs derive from known seeds:

```typescript
function deriveEncryptPdas(payer: PublicKey) {
  const [configPda] = findPda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = findPda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = findPda(
    [Buffer.from("encrypt_deposit"), payer.toBuffer()], ENCRYPT_PROGRAM
  );
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = findPda(
    [Buffer.from("network_encryption_key"), networkKey], ENCRYPT_PROGRAM
  );
  const [cpiAuthority, cpiBump] = findPda(
    [Buffer.from("__encrypt_cpi_authority")], COUNTER_PROGRAM
  );
  return { configPda, eventAuthority, depositPda, depositBump, networkKeyPda, cpiAuthority, cpiBump };
}
```

The `cpiAuthority` is derived from the **counter program** (not the Encrypt
program). Each program that CPIs into Encrypt has its own CPI authority PDA.

## 4. Encrypt CPI Account List

Every Encrypt CPI needs these accounts in order:

```typescript
function encryptCpiAccounts(payer: PublicKey, enc: ReturnType<typeof deriveEncryptPdas>) {
  return [
    { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.configPda, isSigner: false, isWritable: true },
    { pubkey: enc.depositPda, isSigner: false, isWritable: true },
    { pubkey: enc.cpiAuthority, isSigner: false, isWritable: false },
    { pubkey: COUNTER_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: enc.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}
```

## 5. Polling Pattern

After a CPI, the executor processes the FHE computation off-chain. The
frontend polls until the ciphertext account is verified:

```typescript
async function pollUntil(
  connection: any, account: PublicKey,
  check: (data: Buffer) => boolean,
  timeoutMs = 120_000, intervalMs = 1_000
): Promise<Buffer> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const info = await connection.getAccountInfo(account);
      if (info && check(info.data as Buffer)) return info.data as Buffer;
    } catch {}
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Timeout waiting for executor");
}

// Ciphertext is verified when status byte (offset 99) == 1
const isVerified = (d: Buffer) => d.length >= 100 && d[99] === 1;

// Decryption is complete when written_bytes == total_bytes and total > 0
const isDecrypted = (d: Buffer) => {
  if (d.length < 107) return false;
  const total = d.readUInt32LE(99);
  const written = d.readUInt32LE(103);
  return written === total && total > 0;
};
```

## 6. Create Counter Flow

```typescript
const handleInitialize = useCallback(async () => {
  await ensureDeposit(); // create deposit account if needed
  const enc = getEnc();
  const id = Buffer.from(Keypair.generate().publicKey.toBytes());
  const [pda, bump] = findPda([Buffer.from("counter"), id], COUNTER_PROGRAM);
  const valueKeypair = Keypair.generate();

  await sendTx(
    [new TransactionInstruction({
      programId: COUNTER_PROGRAM,
      data: Buffer.concat([Buffer.from([0, bump, enc.cpiBump]), id]),
      keys: [
        { pubkey: pda, isSigner: false, isWritable: true },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: valueKeypair.publicKey, isSigner: true, isWritable: true },
        ...encryptCpiAccounts(wallet.publicKey, enc),
      ],
    })],
    [valueKeypair]
  );

  setCounterPda(pda);
  setValueCt(valueKeypair.publicKey);
}, [/* deps */]);
```

The `valueKeypair` is a fresh keypair whose public key becomes the ciphertext
account address. The Encrypt program creates this account during the CPI. The
keypair must sign the transaction.

## 7. Increment / Decrement Flow

```typescript
const handleOp = useCallback(async (opcode: 1 | 2, label: string) => {
  const enc = getEnc();
  await sendTx([new TransactionInstruction({
    programId: COUNTER_PROGRAM,
    data: Buffer.from([opcode, enc.cpiBump]),
    keys: [
      { pubkey: counterPda, isSigner: false, isWritable: true },
      { pubkey: valueCt, isSigner: false, isWritable: true },
      ...encryptCpiAccounts(wallet.publicKey, enc),
    ],
  })]);

  // Wait for executor to process the FHE computation
  await pollUntil(connection, valueCt, isVerified, 60_000);
}, [/* deps */]);
```

After sending the transaction, poll the ciphertext account until `isVerified`
returns true. The executor typically processes within a few seconds on devnet.

## 8. Decrypt + Reveal Flow

Decryption is a two-step process:

```typescript
const handleDecrypt = useCallback(async () => {
  const enc = getEnc();
  const reqKeypair = Keypair.generate();

  // Step 1: Request decryption
  await sendTx(
    [new TransactionInstruction({
      programId: COUNTER_PROGRAM,
      data: Buffer.from([3, enc.cpiBump]),
      keys: [
        { pubkey: counterPda, isSigner: false, isWritable: true },
        { pubkey: reqKeypair.publicKey, isSigner: true, isWritable: true },
        { pubkey: valueCt, isSigner: false, isWritable: false },
        ...encryptCpiAccounts(wallet.publicKey, enc),
      ],
    })],
    [reqKeypair]
  );

  // Step 2: Wait for decryptor
  await pollUntil(connection, reqKeypair.publicKey, isDecrypted);

  // Step 3: Reveal (copy plaintext into counter state)
  await sendTx([new TransactionInstruction({
    programId: COUNTER_PROGRAM,
    data: Buffer.from([4]),
    keys: [
      { pubkey: counterPda, isSigner: false, isWritable: true },
      { pubkey: reqKeypair.publicKey, isSigner: false, isWritable: false },
      { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
    ],
  })]);

  // Read the revealed value from counter PDA
  const data = (await connection.getAccountInfo(counterPda))!.data as Buffer;
  const revealed = data.readBigUInt64LE(129);
  setDisplayValue(revealed.toString());
}, [/* deps */]);
```

The `reqKeypair` is a fresh keypair for the decryption request account. After
the decryptor writes the result, `reveal_value` (opcode 4) copies the verified
plaintext into `counter.revealed_value`.

## 9. Running on Devnet

The app connects to Solana devnet and the pre-alpha executor automatically. No local validator or executor setup is needed.

```bash
cd chains/solana/examples/counter/react
bun install
bun dev
```

Open `http://localhost:5173`, connect a wallet (e.g. Phantom set to devnet),
airdrop SOL, and create a counter.
