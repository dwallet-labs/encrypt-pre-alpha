import { useState, useCallback, useEffect, useRef } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import {
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  Keypair,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";

import { createEncryptWebClient, encryptValue, Chain } from "../../../../clients/typescript/src/grpc-web";

const HOUSE_API = import.meta.env.VITE_HOUSE_API || "http://localhost:3001";
const GRPC_URL = import.meta.env.VITE_GRPC_URL;
const ENCRYPT_PROGRAM = new PublicKey(import.meta.env.VITE_ENCRYPT_PROGRAM);
const COINFLIP_PROGRAM = new PublicKey(import.meta.env.VITE_COINFLIP_PROGRAM);
const NETWORK_KEY = new Uint8Array(32).fill(0x55);

function findPda(seeds: (Buffer | Uint8Array)[], pid: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, pid);
}

type Phase = "idle" | "creating" | "waiting" | "result";

function CoinFlipApp() {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [phase, setPhase] = useState<Phase>("idle");
  const [betSol, setBetSol] = useState("0.1");
  const [result, setResult] = useState<"win" | "lose" | null>(null);
  const [status, setStatus] = useState("");
  const [depositDone, setDepositDone] = useState(false);
  const encRef = useRef<{ configPda: PublicKey; depositPda: PublicKey; depositBump: number;
    eventAuthority: PublicKey; networkKeyPda: PublicKey; cpiAuthority: PublicKey; cpiBump: number } | null>(null);

  const getEnc = useCallback(() => {
    if (!wallet.publicKey) throw new Error("No wallet");
    if (encRef.current) return encRef.current;
    const [configPda] = findPda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
    const [eventAuthority] = findPda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
    const [depositPda, depositBump] = findPda([Buffer.from("encrypt_deposit"), wallet.publicKey.toBuffer()], ENCRYPT_PROGRAM);
    const [networkKeyPda] = findPda([Buffer.from("network_encryption_key"), Buffer.alloc(32, 0x55)], ENCRYPT_PROGRAM);
    const [cpiAuthority, cpiBump] = findPda([Buffer.from("__encrypt_cpi_authority")], COINFLIP_PROGRAM);
    encRef.current = { configPda, depositPda, depositBump, eventAuthority, networkKeyPda, cpiAuthority, cpiBump };
    return encRef.current;
  }, [wallet.publicKey]);

  const ensureDeposit = useCallback(async () => {
    if (depositDone || !wallet.publicKey || !wallet.sendTransaction) return;
    const enc = getEnc();
    if (await connection.getAccountInfo(enc.depositPda)) { setDepositDone(true); return; }
    const configInfo = await connection.getAccountInfo(enc.configPda);
    if (!configInfo) throw new Error("Executor not running");
    const encVault = new PublicKey((configInfo.data as Buffer).subarray(100, 132));
    const vaultPk = encVault.equals(SystemProgram.programId) ? wallet.publicKey : encVault;
    const data = Buffer.alloc(18); data[0] = 14; data[1] = enc.depositBump;
    const tx = new Transaction().add(new TransactionInstruction({
      programId: ENCRYPT_PROGRAM, data,
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
    }));
    const sig = await wallet.sendTransaction(tx, connection);
    await connection.confirmTransaction(sig, "confirmed");
    setDepositDone(true);
  }, [wallet, connection, depositDone, getEnc]);

  const handleFlip = useCallback(async () => {
    if (!wallet.publicKey || !wallet.sendTransaction) return;
    setPhase("creating");
    setResult(null);
    setStatus("Encrypting your commitment...");

    try {
      await ensureDeposit();
      const enc = getEnc();
      const betLamports = Math.floor(parseFloat(betSol) * LAMPORTS_PER_SOL);

      // 1. Encrypt locally + send via gRPC-Web directly to executor (no backend proxy)
      const playerVal = Math.random() < 0.5 ? 0 : 1;
      const grpcClient = createEncryptWebClient(GRPC_URL);
      const ids = await grpcClient.createInput({
        chain: Chain.SOLANA,
        inputs: [{ ciphertextBytes: encryptValue(playerVal), fheType: 4 }],
        authorized: COINFLIP_PROGRAM.toBytes(),
        networkEncryptionPublicKey: NETWORK_KEY,
      });
      const commitACt = new PublicKey(ids[0]);

      setStatus("Creating game + depositing bet...");

      // 2. Create game on-chain (player = side_a)
      const gameId = Buffer.from(Keypair.generate().publicKey.toBytes());
      const [gamePda, gameBump] = findPda([Buffer.from("game"), gameId], COINFLIP_PROGRAM);
      const resultCt = Keypair.generate();

      const createData = Buffer.alloc(43);
      createData[0] = 0; // disc
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

      const sig = await wallet.sendTransaction(tx, connection, { signers: [resultCt] });
      await connection.confirmTransaction(sig, "confirmed");

      setPhase("waiting");
      setStatus("Game created. House is joining...");

      // 3. Tell house backend to join
      const joinResp = await fetch(`${HOUSE_API}/api/join`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ gamePda: gamePda.toBase58() }),
      });
      if (!joinResp.ok) throw new Error("House failed to join");

      setStatus("House committed. Computing encrypted XOR...");

      // 4. Poll for result
      const start = Date.now();
      while (Date.now() - start < 120_000) {
        const r = await fetch(`${HOUSE_API}/api/game/${gamePda.toBase58()}`);
        const state = await r.json();
        if (state.status === "computing") setStatus("Executor computing XOR...");
        if (state.status === "decrypting") setStatus("Decrypting result...");
        if (state.status === "resolved") {
          const won = state.result === 1;
          setResult(won ? "win" : "lose");
          setStatus(won
            ? `You won ${(parseFloat(betSol) * 2).toFixed(2)} SOL!`
            : `House wins. Lost ${betSol} SOL.`);
          setPhase("result");
          return;
        }
        await new Promise((r) => setTimeout(r, 800));
      }
      throw new Error("Timeout");
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
      setPhase("idle");
    }
  }, [wallet, connection, betSol, ensureDeposit, getEnc]);

  return (
    <div className="app-container">
      <div className="page-title">Encrypt Example</div>
      <h1>Coin Flip</h1>
      <p className="subtitle">
        Provably fair -- both sides commit encrypted values, result = XOR.
        Winner takes 2x from escrow.
      </p>

      {phase === "idle" && (
        <div className="card">
          <div className="bet-section">
            <label className="bet-label">Bet Amount</label>
            <div className="bet-input-row">
              <input className="bet-input" type="number" value={betSol}
                onChange={(e) => setBetSol(e.target.value)} min="0.01" step="0.1" />
              <span className="bet-unit">SOL</span>
            </div>
            <div className="payout-row">
              <span>Win payout</span>
              <span className="payout-value">{(parseFloat(betSol || "0") * 2).toFixed(2)} SOL</span>
            </div>
          </div>
          <button className="primary flip-btn" onClick={handleFlip} disabled={!wallet.publicKey}>
            Flip
          </button>
        </div>
      )}

      {phase === "creating" && (
        <div className="card">
          <div className="coin-area"><div className="coin spinning">?</div></div>
          <p className="loading-status">{status}</p>
        </div>
      )}

      {phase === "waiting" && (
        <div className="card">
          <div className="coin-area"><div className="coin spinning">?</div></div>
          <p className="loading-status">{status}</p>
        </div>
      )}

      {phase === "result" && result && (
        <div className="card">
          <div className="coin-area">
            <div className={`coin result-${result}`}>{result === "win" ? "W" : "L"}</div>
          </div>
          <div className={`result-banner ${result}`}>{result === "win" ? "You Win!" : "House Wins"}</div>
          <div className={`result-amount ${result}`}>
            {result === "win" ? `+${(parseFloat(betSol) * 2).toFixed(2)} SOL` : `-${betSol} SOL`}
          </div>
          <button className="primary flip-btn" onClick={() => { setPhase("idle"); setResult(null); setStatus(""); }}>
            Play Again
          </button>
        </div>
      )}

      {status && phase === "idle" && (
        <div className="status-bar"><span className="status-text">{status}</span></div>
      )}
    </div>
  );
}

export default function App() {
  const { publicKey } = useWallet();
  const { connection } = useConnection();
  const [bal, setBal] = useState<number | null>(null);
  const [airdropping, setAirdropping] = useState(false);

  const refreshBalance = useCallback(async () => {
    if (!publicKey) return;
    const b = await connection.getBalance(publicKey);
    setBal(b / LAMPORTS_PER_SOL);
  }, [publicKey, connection]);

  // Refresh on mount + every 3s
  useEffect(() => {
    if (!publicKey) return;
    refreshBalance();
    const iv = setInterval(refreshBalance, 3000);
    return () => clearInterval(iv);
  }, [publicKey, refreshBalance]);

  const doAirdrop = useCallback(async () => {
    if (!publicKey) return;
    setAirdropping(true);
    try {
      const sig = await connection.requestAirdrop(publicKey, 10 * LAMPORTS_PER_SOL);
      await connection.confirmTransaction(sig, "confirmed");
      setBal((await connection.getBalance(publicKey)) / LAMPORTS_PER_SOL);
    } catch {}
    setAirdropping(false);
  }, [publicKey, connection]);

  return (
    <>
      <div className="header">
        <div className="header-brand"><img src="/logo.svg" alt="Encrypt" className="brand-logo" /><span>Encrypt</span></div>
        <div className="header-right">
          {publicKey && bal !== null && <span className="balance-pill">{bal.toFixed(2)} SOL</span>}
          {publicKey && <button className="airdrop-btn" onClick={doAirdrop} disabled={airdropping}>{airdropping ? "..." : "Airdrop"}</button>}
          <WalletMultiButton />
        </div>
      </div>
      {publicKey ? <CoinFlipApp /> : (
        <div className="connect-screen"><div className="page-title">Encrypt Example</div><h1>Coin Flip</h1><p className="subtitle">Connect your wallet to play.</p></div>
      )}
    </>
  );
}
