import { useState, useCallback, useEffect } from "react";
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

const GRPC_URL = import.meta.env.VITE_GRPC_URL;
const ENCRYPT_PROGRAM = new PublicKey(import.meta.env.VITE_ENCRYPT_PROGRAM);
const VOTING_PROGRAM = new PublicKey(import.meta.env.VITE_VOTING_PROGRAM);
const NETWORK_KEY = new Uint8Array(32).fill(0x55);

function findPda(seeds: (Buffer | Uint8Array)[], pid: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, pid);
}

const isVerified = (d: Buffer) => d.length >= 100 && d[99] === 1;
const isDecrypted = (d: Buffer) => {
  if (d.length < 107) return false;
  const total = d.readUInt32LE(99);
  const written = d.readUInt32LE(103);
  return written === total && total > 0;
};

async function pollUntil(conn: any, acct: PublicKey, check: (d: Buffer) => boolean, ms = 120_000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try { const i = await conn.getAccountInfo(acct); if (i && check(i.data as Buffer)) return i.data as Buffer; } catch {}
    await new Promise((r) => setTimeout(r, 800));
  }
  throw new Error("Timeout");
}

interface ProposalState {
  pda: PublicKey;
  proposalId: Buffer;
  bump: number;
  yesCt: PublicKey;
  noCt: PublicKey;
  isOpen: boolean;
  totalVotes: number;
  authority: PublicKey;
}

function deriveEncryptPdas(payer: PublicKey) {
  const [configPda] = findPda([Buffer.from("encrypt_config")], ENCRYPT_PROGRAM);
  const [eventAuthority] = findPda([Buffer.from("__event_authority")], ENCRYPT_PROGRAM);
  const [depositPda, depositBump] = findPda(
    [Buffer.from("encrypt_deposit"), payer.toBuffer()],
    ENCRYPT_PROGRAM,
  );
  const [networkKeyPda] = findPda(
    [Buffer.from("network_encryption_key"), Buffer.from(NETWORK_KEY)],
    ENCRYPT_PROGRAM,
  );
  const [cpiAuthority, cpiBump] = findPda(
    [Buffer.from("__encrypt_cpi_authority")],
    VOTING_PROGRAM,
  );
  return { configPda, eventAuthority, depositPda, depositBump, networkKeyPda, cpiAuthority, cpiBump };
}

function encryptCpiAccounts(payer: PublicKey, enc: ReturnType<typeof deriveEncryptPdas>) {
  return [
    { pubkey: ENCRYPT_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.configPda, isSigner: false, isWritable: true },
    { pubkey: enc.depositPda, isSigner: false, isWritable: true },
    { pubkey: enc.cpiAuthority, isSigner: false, isWritable: false },
    { pubkey: VOTING_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: enc.networkKeyPda, isSigner: false, isWritable: false },
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: enc.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}

function VotingApp() {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [proposal, setProposalRaw] = useState<ProposalState | null>(null);
  const [tally, setTally] = useState<{ yes: number; no: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [depositCreated, setDepositCreated] = useState(false);
  const [copied, setCopied] = useState(false);

  // Wrap setProposal to also update URL
  const setProposal = useCallback((p: ProposalState | null) => {
    setProposalRaw(p);
    if (p) {
      const params = new URLSearchParams({
        proposal: p.pda.toBase58(),
        yesCt: p.yesCt.toBase58(),
        noCt: p.noCt.toBase58(),
      });
      window.history.replaceState({}, "", `?${params}`);
    } else {
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  // Load proposal from URL on mount
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
        const authority = new PublicKey(d.subarray(1, 33));
        const isOpen = d[129] === 1;
        const totalVotes = Number((d as Buffer).readBigUInt64LE(130));
        setProposalRaw({
          pda,
          proposalId: Buffer.alloc(32),
          bump: 0,
          yesCt: new PublicKey(yesStr),
          noCt: new PublicKey(noStr),
          isOpen,
          totalVotes,
          authority,
        });
      });
    }
  }, [connection]);

  const copyLink = useCallback(() => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  const sendTx = useCallback(
    async (ixs: TransactionInstruction[], signers: Keypair[] = []) => {
      if (!wallet.publicKey || !wallet.sendTransaction) throw new Error("No wallet");
      const tx = new Transaction().add(...ixs);
      const sig = await wallet.sendTransaction(tx, connection, { signers });
      await connection.confirmTransaction(sig, "confirmed");
      return sig;
    },
    [wallet, connection],
  );

  const ensureDeposit = useCallback(async () => {
    if (depositCreated || !wallet.publicKey) return;
    const enc = deriveEncryptPdas(wallet.publicKey);
    const depositInfo = await connection.getAccountInfo(enc.depositPda);
    if (depositInfo) { setDepositCreated(true); return; }
    const configInfo = await connection.getAccountInfo(enc.configPda);
    if (!configInfo) throw new Error("Encrypt config not found. Is the executor running?");
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
  }, [wallet.publicKey, connection, sendTx, depositCreated]);

  // ── Create Proposal ──
  const handleCreate = useCallback(async () => {
    if (!wallet.publicKey || !wallet.sendTransaction) return;
    setLoading(true); setStatus("Setting up deposit..."); setTally(null);
    try {
      await ensureDeposit();
      const enc = deriveEncryptPdas(wallet.publicKey);
      const proposalId = Buffer.from(Keypair.generate().publicKey.toBytes());
      const [pda, bump] = findPda([Buffer.from("proposal"), proposalId], VOTING_PROGRAM);
      const yesCt = Keypair.generate();
      const noCt = Keypair.generate();

      setStatus("Creating proposal...");
      const createData = Buffer.alloc(35);
      createData[0] = 0;
      createData[1] = bump;
      createData[2] = enc.cpiBump;
      proposalId.copy(createData, 3);

      await sendTx(
        [new TransactionInstruction({
          programId: VOTING_PROGRAM, data: createData,
          keys: [
            { pubkey: pda, isSigner: false, isWritable: true },
            { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
            { pubkey: yesCt.publicKey, isSigner: true, isWritable: true },
            { pubkey: noCt.publicKey, isSigner: true, isWritable: true },
            ...encryptCpiAccounts(wallet.publicKey, enc).map((a) =>
              a.pubkey.equals(enc.configPda) ? { ...a, isWritable: false } : a,
            ),
          ],
        })],
        [yesCt, noCt],
      );

      setProposal({ pda, proposalId, bump, yesCt: yesCt.publicKey, noCt: noCt.publicKey, isOpen: true, totalVotes: 0, authority: wallet.publicKey });
      setStatus("Proposal created. Cast your votes.");
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    } finally { setLoading(false); }
  }, [wallet, connection, sendTx, ensureDeposit]);

  // ── Cast Vote ──
  const handleVote = useCallback(async (voteYes: boolean) => {
    if (!wallet.publicKey || !wallet.sendTransaction || !proposal || !proposal.isOpen) return;
    setLoading(true); setStatus(`Casting ${voteYes ? "yes" : "no"} vote...`);
    try {
      await ensureDeposit();
      const enc = deriveEncryptPdas(wallet.publicKey);
      const voteVal = voteYes ? 1 : 0;

      const grpcClient = createEncryptWebClient(GRPC_URL);
      const ids = await grpcClient.createInput({
        chain: Chain.SOLANA,
        inputs: [{ ciphertextBytes: encryptValue(voteVal), fheType: 0 }],
        authorized: VOTING_PROGRAM.toBytes(),
        networkEncryptionPublicKey: NETWORK_KEY,
      });
      const voteCt = new PublicKey(ids[0]);

      const propInfo = await connection.getAccountInfo(proposal.pda);
      if (!propInfo) throw new Error("Proposal not found");
      const proposalId = (propInfo.data as Buffer).subarray(33, 65);

      const [voteRecord, vrBump] = findPda(
        [Buffer.from("vote"), proposalId, wallet.publicKey.toBuffer()],
        VOTING_PROGRAM
      );

      if (proposal.totalVotes > 0) {
        const yesInfo = await connection.getAccountInfo(proposal.yesCt);
        if (yesInfo && (yesInfo.data as Buffer)[99] !== 1) {
          setStatus("Waiting for previous vote to finalize...");
          await pollUntil(connection, proposal.yesCt, isVerified, 60_000);
        }
      }

      setStatus("Sending vote...");
      const ix = new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([1, vrBump, enc.cpiBump]),
        keys: [
          { pubkey: proposal.pda, isSigner: false, isWritable: true },
          { pubkey: voteRecord, isSigner: false, isWritable: true },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
          { pubkey: voteCt, isSigner: false, isWritable: true },
          { pubkey: proposal.yesCt, isSigner: false, isWritable: true },
          { pubkey: proposal.noCt, isSigner: false, isWritable: true },
          ...encryptCpiAccounts(wallet.publicKey, enc),
        ],
      });
      const tx = new Transaction().add(ix);
      tx.feePayer = wallet.publicKey;
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;

      try {
        const sim = await connection.simulateTransaction(tx);
        if (sim.value.err) {
          console.error("Simulation logs:", sim.value.logs);
          throw new Error(`Simulation failed: ${JSON.stringify(sim.value.err)}\nLogs: ${sim.value.logs?.join("\n")}`);
        }
      } catch (simErr: any) {
        if (simErr.message?.includes("Simulation failed")) throw simErr;
      }

      const sig = await wallet.sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStatus("Waiting for executor...");
      await new Promise((r) => setTimeout(r, 2000));
      await pollUntil(connection, proposal.yesCt, isVerified, 60_000);

      const updatedProp = await connection.getAccountInfo(proposal.pda);
      const newTotal = updatedProp
        ? Number((updatedProp.data as Buffer).readBigUInt64LE(130))
        : proposal.totalVotes + 1;
      setProposal({ ...proposal, totalVotes: newTotal });
      setStatus(`Vote cast. ${newTotal} total.`);
    } catch (err: any) {
      const msg = err?.message || String(err);
      console.error("Vote error:", err);
      if (msg.includes("custom program error")) {
        setStatus("Error: You may have already voted on this proposal.");
      } else {
        setStatus(`Error: ${msg}`);
      }
    } finally { setLoading(false); }
  }, [wallet, connection, proposal, sendTx, ensureDeposit]);

  // ── Close Proposal ──
  const handleClose = useCallback(async () => {
    if (!wallet.publicKey || !wallet.sendTransaction || !proposal) return;
    setLoading(true); setStatus("Closing proposal...");
    try {
      await sendTx([new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([2]),
        keys: [
          { pubkey: proposal.pda, isSigner: false, isWritable: true },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
        ],
      })]);
      setProposal({ ...proposal, isOpen: false });
      setStatus("Proposal closed.");
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    } finally { setLoading(false); }
  }, [wallet, connection, proposal, sendTx]);

  // ── Decrypt Results ──
  const handleDecrypt = useCallback(async () => {
    if (!proposal || !wallet.publicKey || !wallet.sendTransaction) return;
    setLoading(true); setStatus("Setting up deposit...");
    try {
      await ensureDeposit();
      const enc = deriveEncryptPdas(wallet.publicKey);
      const encCpi = encryptCpiAccounts(wallet.publicKey, enc).map((a) =>
        a.pubkey.equals(enc.configPda) ? { ...a, isWritable: false } : a,
      );

      // 1. Request decryption for yes tally
      setStatus("Requesting yes decryption...");
      const yesReq = Keypair.generate();
      await sendTx(
        [new TransactionInstruction({
          programId: VOTING_PROGRAM,
          data: Buffer.from([3, enc.cpiBump, 1]),
          keys: [
            { pubkey: proposal.pda, isSigner: false, isWritable: true },
            { pubkey: yesReq.publicKey, isSigner: true, isWritable: true },
            { pubkey: proposal.yesCt, isSigner: false, isWritable: false },
            ...encCpi,
          ],
        })],
        [yesReq],
      );

      // 2. Request decryption for no tally
      setStatus("Requesting no decryption...");
      const noReq = Keypair.generate();
      await sendTx(
        [new TransactionInstruction({
          programId: VOTING_PROGRAM,
          data: Buffer.from([3, enc.cpiBump, 0]),
          keys: [
            { pubkey: proposal.pda, isSigner: false, isWritable: true },
            { pubkey: noReq.publicKey, isSigner: true, isWritable: true },
            { pubkey: proposal.noCt, isSigner: false, isWritable: false },
            ...encCpi,
          ],
        })],
        [noReq],
      );

      // 3. Poll until both are decrypted
      setStatus("Waiting for decryption...");
      await pollUntil(connection, yesReq.publicKey, isDecrypted);
      await pollUntil(connection, noReq.publicKey, isDecrypted);

      // 4. Reveal yes (is_yes=1)
      setStatus("Revealing results on-chain...");
      await sendTx([new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([4, 1]),
        keys: [
          { pubkey: proposal.pda, isSigner: false, isWritable: true },
          { pubkey: yesReq.publicKey, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
        ],
      })]);

      // 5. Reveal no (is_yes=0)
      await sendTx([new TransactionInstruction({
        programId: VOTING_PROGRAM,
        data: Buffer.from([4, 0]),
        keys: [
          { pubkey: proposal.pda, isSigner: false, isWritable: true },
          { pubkey: noReq.publicKey, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
        ],
      })]);

      // 6. Read results
      const propData = (await connection.getAccountInfo(proposal.pda))!.data as Buffer;
      const yesCount = Number(propData.readBigUInt64LE(138));
      const noCount = Number(propData.readBigUInt64LE(146));

      setTally({ yes: yesCount, no: noCount });
      setStatus("Results revealed.");
    } catch (err: any) {
      console.error("Decrypt error:", err);
      setStatus(`Error: ${err.message}`);
    } finally { setLoading(false); }
  }, [proposal, wallet, connection, sendTx, ensureDeposit]);

  return (
    <div className="app-container">
      <div className="page-title">Encrypt Example</div>
      <h1>Confidential Voting</h1>
      <p className="subtitle">
        Encrypted votes — nobody sees how you voted, but the tally is computed via FHE.
      </p>

      {!proposal ? (
        <div className="card">
          <p className="info-text">
            Create a proposal. Voters cast encrypted yes/no votes.
            The tally is computed homomorphically and decrypted only when you choose.
            As the creator, only you can close voting and decrypt the results.
          </p>
          <button className="primary full-btn" onClick={handleCreate}
            disabled={!wallet.publicKey || loading}>
            {loading ? "Creating..." : "Create Proposal"}
          </button>
        </div>
      ) : (
        <>
          <div className="card">
            <div className="proposal-header">
              <span className={`badge ${proposal.isOpen ? "open" : "closed"}`}>
                {proposal.isOpen ? "Open" : "Closed"}
              </span>
              <span className="vote-count">{proposal.totalVotes} vote{proposal.totalVotes !== 1 ? "s" : ""}</span>
            </div>

            {proposal.isOpen && (
              <div className="vote-buttons">
                <button className="vote-btn yes" onClick={() => handleVote(true)} disabled={loading}>
                  Yes
                </button>
                <button className="vote-btn no" onClick={() => handleVote(false)} disabled={loading}>
                  No
                </button>
              </div>
            )}

            {wallet.publicKey && proposal.authority.equals(wallet.publicKey) ? (
              <div className="action-row">
                {proposal.isOpen && (
                  <button onClick={handleClose} disabled={loading}>Close Voting</button>
                )}
                <button className="primary" onClick={handleDecrypt} disabled={loading}>
                  {loading ? status : "Decrypt Results"}
                </button>
              </div>
            ) : (
              <p className="info-text">
                Only the proposal creator can close voting and decrypt results.
              </p>
            )}
          </div>

          {tally && (
            <div className="card results-card">
              <div className="results-header">Results</div>
              <div className="results-row">
                <div className="result-col">
                  <div className="result-value yes">{tally.yes}</div>
                  <div className="result-label">Yes</div>
                </div>
                <div className="result-divider" />
                <div className="result-col">
                  <div className="result-value no">{tally.no}</div>
                  <div className="result-label">No</div>
                </div>
              </div>
              <div className="result-outcome">
                {tally.yes > tally.no ? "Proposal Passed" : tally.yes < tally.no ? "Proposal Rejected" : "Tied"}
              </div>
            </div>
          )}

          <div className="card details">
            <p>proposal <code>{proposal.pda.toBase58()}</code></p>
            <p>yes_ct <code>{proposal.yesCt.toBase58()}</code></p>
            <p>no_ct <code>{proposal.noCt.toBase58()}</code></p>
            <button className="copy-link-btn" onClick={copyLink}>
              {copied ? "Copied!" : "Copy Voting Link"}
            </button>
          </div>

          <button className="new-btn" onClick={() => { setProposal(null); setTally(null); setStatus(""); }}>
            New Proposal
          </button>
        </>
      )}

      {status && !loading && (
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

  const refreshBal = useCallback(async () => {
    if (publicKey) setBal((await connection.getBalance(publicKey)) / LAMPORTS_PER_SOL);
  }, [publicKey, connection]);

  useEffect(() => {
    if (!publicKey) return;
    refreshBal();
    const iv = setInterval(refreshBal, 3000);
    return () => clearInterval(iv);
  }, [publicKey, refreshBal]);

  const doAirdrop = useCallback(async () => {
    if (!publicKey) return;
    setAirdropping(true);
    try {
      const sig = await connection.requestAirdrop(publicKey, 10 * LAMPORTS_PER_SOL);
      await connection.confirmTransaction(sig, "confirmed");
      refreshBal();
    } catch {}
    setAirdropping(false);
  }, [publicKey, connection, refreshBal]);

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
      {publicKey ? <VotingApp /> : (
        <div className="connect-screen"><div className="page-title">Encrypt Example</div><h1>Confidential Voting</h1><p className="subtitle">Connect your wallet to vote.</p></div>
      )}
    </>
  );
}
