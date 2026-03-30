import { useState, useCallback, useRef, useEffect } from 'react';
import { useConnection, useWallet } from '@solana/wallet-adapter-react';
import { WalletMultiButton } from '@solana/wallet-adapter-react-ui';
import {
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  Keypair,
} from '@solana/web3.js';

// ── Program IDs ──

const ENCRYPT_PROGRAM = new PublicKey(import.meta.env.VITE_ENCRYPT_PROGRAM);
const COUNTER_PROGRAM = new PublicKey(import.meta.env.VITE_COUNTER_PROGRAM);

// ── Solana helpers ──

function findPda(seeds: (Buffer | Uint8Array)[], programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, programId);
}

function deriveEncryptPdas(payer: PublicKey) {
  const [configPda] = findPda([Buffer.from('encrypt_config')], ENCRYPT_PROGRAM);
  const [eventAuthority] = findPda([Buffer.from('__event_authority')], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = findPda(
    [Buffer.from('encrypt_deposit'), payer.toBuffer()],
    ENCRYPT_PROGRAM,
  );
  const networkKey = Buffer.alloc(32, 0x55);
  const [networkKeyPda] = findPda(
    [Buffer.from('network_encryption_key'), networkKey],
    ENCRYPT_PROGRAM,
  );
  const [cpiAuthority, cpiBump] = findPda(
    [Buffer.from('__encrypt_cpi_authority')],
    COUNTER_PROGRAM,
  );
  return {
    configPda,
    eventAuthority,
    depositPda,
    depositBump,
    networkKeyPda,
    cpiAuthority,
    cpiBump,
  };
}

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

async function pollUntil(
  connection: any,
  account: PublicKey,
  check: (data: Buffer) => boolean,
  timeoutMs = 120_000,
  intervalMs = 1_000,
): Promise<Buffer> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const info = await connection.getAccountInfo(account);
      if (info && check(info.data as Buffer)) return info.data as Buffer;
    } catch {}
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('Timeout waiting for executor');
}

const isVerified = (d: Buffer) => d.length >= 100 && d[99] === 1;
const isDecrypted = (d: Buffer) => {
  if (d.length < 107) return false;
  const total = d.readUInt32LE(99);
  const written = d.readUInt32LE(103);
  return written === total && total > 0;
};

// ── Fake cipher text for visual effect ──
function randomCipher(): string {
  const chars = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * 16)];
  return s;
}

// ── Counter App ──

function CounterApp() {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [counterPda, setCounterPda] = useState<PublicKey | null>(null);
  const [valueCt, setValueCt] = useState<PublicKey | null>(null);
  const [displayValue, setDisplayValue] = useState<string | null>(null);
  const [cipherDisplay, setCipherDisplay] = useState(randomCipher());
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');
  const [depositCreated, setDepositCreated] = useState(false);

  const encRef = useRef<ReturnType<typeof deriveEncryptPdas> | null>(null);

  // Animate cipher text
  useEffect(() => {
    if (displayValue !== null) return;
    const iv = setInterval(() => setCipherDisplay(randomCipher()), 120);
    return () => clearInterval(iv);
  }, [displayValue]);

  const getEnc = useCallback(() => {
    if (!wallet.publicKey) throw new Error('Wallet not connected');
    if (!encRef.current) encRef.current = deriveEncryptPdas(wallet.publicKey);
    return encRef.current;
  }, [wallet.publicKey]);

  const sendTx = useCallback(
    async (ixs: TransactionInstruction[], signers: Keypair[] = []) => {
      if (!wallet.publicKey || !wallet.sendTransaction) throw new Error('No wallet');
      const tx = new Transaction().add(...ixs);
      const sig = await wallet.sendTransaction(tx, connection, { signers });
      await connection.confirmTransaction(sig, 'confirmed');
      return sig;
    },
    [wallet, connection],
  );

  const ensureDeposit = useCallback(async () => {
    if (depositCreated || !wallet.publicKey) return;
    const enc = getEnc();
    const configInfo = await connection.getAccountInfo(enc.configPda);
    if (!configInfo) throw new Error('Encrypt config not found. Is the executor running?');
    const depositInfo = await connection.getAccountInfo(enc.depositPda);
    if (depositInfo) {
      setDepositCreated(true);
      return;
    }
    const encVault = new PublicKey((configInfo.data as Buffer).subarray(100, 132));
    const vaultPk = encVault.equals(SystemProgram.programId) ? wallet.publicKey : encVault;
    const depositData = Buffer.alloc(18);
    depositData[0] = 14;
    depositData[1] = enc.depositBump;
    await sendTx([
      new TransactionInstruction({
        programId: ENCRYPT_PROGRAM,
        data: depositData,
        keys: [
          { pubkey: enc.depositPda, isSigner: false, isWritable: true },
          { pubkey: enc.configPda, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultPk, isSigner: vaultPk.equals(wallet.publicKey), isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
      }),
    ]);
    setDepositCreated(true);
  }, [wallet.publicKey, connection, sendTx, getEnc, depositCreated]);

  const handleInitialize = useCallback(async () => {
    if (!wallet.publicKey) return;
    setLoading(true);
    setStatus('Setting up deposit...');
    try {
      await ensureDeposit();
      const enc = getEnc();
      const id = Buffer.from(Keypair.generate().publicKey.toBytes());
      const [pda, bump] = findPda([Buffer.from('counter'), id], COUNTER_PROGRAM);
      const valueKeypair = Keypair.generate();
      setStatus('Creating encrypted counter...');
      await sendTx(
        [
          new TransactionInstruction({
            programId: COUNTER_PROGRAM,
            data: Buffer.concat([Buffer.from([0, bump, enc.cpiBump]), id]),
            keys: [
              { pubkey: pda, isSigner: false, isWritable: true },
              { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
              { pubkey: valueKeypair.publicKey, isSigner: true, isWritable: true },
              ...encryptCpiAccounts(wallet.publicKey, enc).map((a, i) =>
                i === 0 ? { ...a, isWritable: false } : a,
              ),
            ],
          }),
        ],
        [valueKeypair],
      );
      setCounterPda(pda);
      setValueCt(valueKeypair.publicKey);
      setDisplayValue(null);
      setStatus('Counter created');
    } catch (err: any) {
      setStatus(`Error: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  }, [wallet.publicKey, sendTx, ensureDeposit, getEnc]);

  const handleOp = useCallback(
    async (opcode: 1 | 2, label: string) => {
      if (!wallet.publicKey || !counterPda || !valueCt) return;
      setLoading(true);
      setStatus(label + '...');
      try {
        const enc = getEnc();
        await sendTx([
          new TransactionInstruction({
            programId: COUNTER_PROGRAM,
            data: Buffer.from([opcode, enc.cpiBump]),
            keys: [
              { pubkey: counterPda, isSigner: false, isWritable: true },
              { pubkey: valueCt, isSigner: false, isWritable: true },
              ...encryptCpiAccounts(wallet.publicKey, enc),
            ],
          }),
        ]);
        setStatus('Waiting for executor...');
        await pollUntil(connection, valueCt, isVerified, 60_000);
        setDisplayValue(null);
        setStatus(label + ' complete');
      } catch (err: any) {
        setStatus(`Error: ${err.message || err}`);
      } finally {
        setLoading(false);
      }
    },
    [wallet.publicKey, counterPda, valueCt, connection, sendTx, getEnc],
  );

  const handleDecrypt = useCallback(async () => {
    if (!wallet.publicKey || !counterPda || !valueCt) return;
    setLoading(true);
    setStatus('Requesting decryption...');
    try {
      const enc = getEnc();
      const reqKeypair = Keypair.generate();
      await sendTx(
        [
          new TransactionInstruction({
            programId: COUNTER_PROGRAM,
            data: Buffer.from([3, enc.cpiBump]),
            keys: [
              { pubkey: counterPda, isSigner: false, isWritable: true },
              { pubkey: reqKeypair.publicKey, isSigner: true, isWritable: true },
              { pubkey: valueCt, isSigner: false, isWritable: false },
              ...encryptCpiAccounts(wallet.publicKey, enc).map((a) =>
                a.pubkey.equals(enc.configPda) ? { ...a, isWritable: false } : a,
              ),
            ],
          }),
        ],
        [reqKeypair],
      );
      setStatus('Decrypting...');
      await pollUntil(connection, reqKeypair.publicKey, isDecrypted);
      setStatus('Revealing...');
      await sendTx([
        new TransactionInstruction({
          programId: COUNTER_PROGRAM,
          data: Buffer.from([4]),
          keys: [
            { pubkey: counterPda, isSigner: false, isWritable: true },
            { pubkey: reqKeypair.publicKey, isSigner: false, isWritable: false },
            { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
          ],
        }),
      ]);
      const data = (await connection.getAccountInfo(counterPda))!.data as Buffer;
      const revealed = data.readBigUInt64LE(129);
      setDisplayValue(revealed.toString());
      setStatus('Decrypted');
    } catch (err: any) {
      setStatus(`Error: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  }, [wallet.publicKey, counterPda, valueCt, connection, sendTx, getEnc]);

  return (
    <div className="app-container">
      <div className="page-title">Encrypt Example</div>
      <h1>Confidential Counter</h1>
      <p className="subtitle">
        An on-chain counter whose value is always encrypted via FHE. Nobody can read it until the
        owner decrypts.
      </p>

      {!counterPda ? (
        <div className="card">
          <p className="info-text">
            Initialize a counter that starts at encrypted zero. The value lives on Solana as an FHE
            ciphertext -- invisible to validators, explorers, and everyone else.
          </p>
          <div className="button-row">
            <button
              className="primary"
              onClick={handleInitialize}
              disabled={!wallet.publicKey || loading}
            >
              {loading ? 'Creating...' : 'Create Counter'}
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="card counter-card">
            <div className="value-container">
              <div className="value-label">Current Value</div>
              {displayValue !== null ? (
                <div className="value-display">{displayValue}</div>
              ) : (
                <div className="value-display encrypted">{cipherDisplay}</div>
              )}
              <div className="value-note">
                {displayValue !== null
                  ? 'Plaintext revealed on-chain'
                  : 'Encrypted -- only ciphertext on-chain'}
              </div>
            </div>
            <div className="button-row">
              <button
                className="op-btn"
                onClick={() => handleOp(2, 'Decrement')}
                disabled={loading}
              >
                - Decrement
              </button>
              <button
                className="op-btn"
                onClick={() => handleOp(1, 'Increment')}
                disabled={loading}
              >
                + Increment
              </button>
            </div>
            <div className="button-row">
              <button className="primary decrypt-btn" onClick={handleDecrypt} disabled={loading}>
                {loading ? status : 'Decrypt Value'}
              </button>
            </div>
          </div>

          <div className="card details">
            <p>
              counter <code>{counterPda.toBase58()}</code>
            </p>
            <p>
              ciphertext <code>{valueCt?.toBase58()}</code>
            </p>
          </div>
        </>
      )}

      {status && !loading && (
        <div className="status-bar">
          <span className="status-text">
            <span className={`status-dot ${loading ? '' : 'idle'}`} />
            {status}
          </span>
        </div>
      )}
    </div>
  );
}

// ── Root App with Header ──

export default function App() {
  const { publicKey } = useWallet();
  const { connection } = useConnection();
  const [bal, setBal] = useState<number | null>(null);
  const [airdropping, setAirdropping] = useState(false);

  useEffect(() => {
    if (publicKey) {
      connection.getBalance(publicKey).then((b) => setBal(b / 1e9));
    }
  }, [publicKey, connection]);

  const doAirdrop = useCallback(async () => {
    if (!publicKey) return;
    setAirdropping(true);
    try {
      const sig = await connection.requestAirdrop(publicKey, 10e9);
      await connection.confirmTransaction(sig, 'confirmed');
      const b = await connection.getBalance(publicKey);
      setBal(b / 1e9);
    } catch {}
    setAirdropping(false);
  }, [publicKey, connection]);

  return (
    <>
      <div className="header">
        <div className="header-brand">
          <img src="/logo.svg" alt="Encrypt" className="brand-logo" />
          <span>Encrypt</span>
        </div>
        <div className="header-right">
          {publicKey && bal !== null && <span className="balance-pill">{bal.toFixed(2)} SOL</span>}
          {publicKey && (
            <button className="airdrop-btn" onClick={doAirdrop} disabled={airdropping}>
              {airdropping ? '...' : 'Airdrop'}
            </button>
          )}
          <WalletMultiButton />
        </div>
      </div>

      {publicKey ? (
        <CounterApp />
      ) : (
        <div className="connect-screen">
          <div className="page-title">Encrypt Example</div>
          <h1>Confidential Counter</h1>
          <p className="subtitle">Connect your wallet to get started.</p>
        </div>
      )}
    </>
  );
}
