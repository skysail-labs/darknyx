"use client";

import { useEffect, useRef, useState } from "react";
import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";

// ---------------------------------------------------------------------------
// Poseidon helpers — built from bundled circomlibjs, identical to SDK
// ---------------------------------------------------------------------------
type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & { F: { toObject: (x: Uint8Array) => bigint } };
let poseidonCache: PoseidonFn | null = null;

async function getPoseidon(): Promise<PoseidonFn> {
  if (poseidonCache) return poseidonCache;
  const p = await buildPoseidon();
  const fn = ((inputs: bigint[]) => p(inputs.map((i) => p.F.e(i)))) as PoseidonFn;
  fn.F = p.F;
  poseidonCache = fn;
  return fn;
}

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function randFr(): bigint {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  return n % BN254_R;
}

// Split a 32-byte pubkey into [lo_u128, hi_u128] — mirrors pubkeyToFrPair in SDK
// hi = bytes 0-15, lo = bytes 16-31
function pubkeyToFrPair(pk: Uint8Array): [bigint, bigint] {
  let lo = 0n, hi = 0n;
  for (let i = 0; i < 16; i++)  hi = (hi << 8n) | BigInt(pk[i]);
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(pk[i]);
  return [lo, hi];
}

function posH(p: PoseidonFn, ...args: bigint[]): bigint {
  return p.F.toObject(p(args));
}

// Build circuit inputs using the same derivation as devnet-trade-flow.test.ts
async function buildInputs(log: (s: string) => void) {
  const p = await getPoseidon();

  // --- VALID_WALLET_CREATE ---
  // Match makePersona() in devnet-trade-flow.test.ts:
  //   spendingKey and viewingKey are BN254 Fr scalars
  //   r0 = seed0 + 1n, r1 = seed0 + 2n, r2 = seed0 + 3n (small values, always Fr)
  //   rootKey comes from a Solana keypair pubkey (Ed25519, 32 bytes)
  const spendingKey = randFr();
  const viewingKey  = randFr();
  const seed0 = BigInt(Math.floor(Math.random() * 0xFFFFFF));
  const r0 = seed0 + 1n;
  const r1 = seed0 + 2n;
  const r2 = seed0 + 3n;

  // rootKey: 32-byte Ed25519 pubkey split into [lo_u128, hi_u128]
  const rootKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const [rootKeyLo, rootKeyHi] = pubkeyToFrPair(rootKeyBytes);

  // userCommitment computed exactly as userCommitmentFromKeys() in SDK
  const rootHash   = posH(p, 10n, rootKeyLo, rootKeyHi, r0);
  const spendHash  = posH(p, 11n, spendingKey, r1);
  const viewHash   = posH(p, 12n, viewingKey,  r2);
  const leafPair   = posH(p, 13n, rootHash, spendHash);
  const userCommit = posH(p, 14n, leafPair, viewHash);

  const wcInputs: Record<string, string | string[]> = {
    userCommitment: userCommit.toString(),
    rootKey: [rootKeyLo.toString(), rootKeyHi.toString()],
    spendingKey: spendingKey.toString(),
    viewingKey:  viewingKey.toString(),
    r0: r0.toString(),
    r1: r1.toString(),
    r2: r2.toString(),
  };
  log(`WC inputs ready (rootKeyLo < 2^128: ${rootKeyLo < 2n**128n}, rootKeyHi < 2^128: ${rootKeyHi < 2n**128n})`);

  // --- VALID_SPEND / VALID_INPUT shared witness ---
  const ownerBlinding = randFr();
  const nonce = randFr();
  const blindingR = randFr();
  // tokenMint: 32-byte address split into [lo_u128, hi_u128]
  const mintBytes = crypto.getRandomValues(new Uint8Array(32));
  const [mintLo, mintHi] = pubkeyToFrPair(mintBytes);
  const amount = 1000n;

  const ownerCommit = posH(p, 1n, spendingKey, ownerBlinding);
  const noteCommit  = posH(p, 2n, mintLo, mintHi, amount, ownerCommit, nonce, blindingR);
  const nullifierVal = posH(p, 3n, spendingKey, noteCommit);

  const zeroPath = Array(20).fill("0");
  const zeroIdx  = Array(20).fill("0");
  // Build Merkle root by hashing noteCommit up 20 levels with zero siblings
  let root = noteCommit;
  for (let i = 0; i < 20; i++) root = posH(p, root, 0n);

  const spendInputs: Record<string, string | string[]> = {
    merkleRoot: root.toString(),
    nullifier: nullifierVal.toString(),
    tokenMint: [mintLo.toString(), mintHi.toString()],
    amount: amount.toString(),
    spendingKey: spendingKey.toString(),
    ownerCommitmentBlinding: ownerBlinding.toString(),
    nonce: nonce.toString(),
    blindingR: blindingR.toString(),
    merklePath: zeroPath,
    merkleIndices: zeroIdx,
  };
  const inputInputs: Record<string, string | string[]> = {
    merkleRoot: root.toString(),
    noteCommitment: noteCommit.toString(),
    tokenMint: [mintLo.toString(), mintHi.toString()],
    amount: amount.toString(),
    spendingKey: spendingKey.toString(),
    ownerCommitmentBlinding: ownerBlinding.toString(),
    nonce: nonce.toString(),
    blindingR: blindingR.toString(),
    merklePath: zeroPath,
    merkleIndices: zeroIdx,
  };

  return { wcInputs, spendInputs, inputInputs };
}

// ---------------------------------------------------------------------------
// IndexedDB artifact cache — keyed by URL (includes ?v=N cache-bust).
// On cold load: network fetch + store. Warm: IDB read only, zero network.
// ---------------------------------------------------------------------------
const IDB_NAME = "zk-bench-artifacts";
const IDB_STORE = "bufs";
const IDB_VERSION = 1;

function openArtifactDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet(db: IDBDatabase, key: string): Promise<Uint8Array | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readonly");
    const req = tx.objectStore(IDB_STORE).get(key);
    req.onsuccess = () => resolve(req.result as Uint8Array | undefined);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    const req = tx.objectStore(IDB_STORE).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function fetchBuf(
  url: string,
  db: IDBDatabase | null,
  onSource: (source: "idb" | "network") => void,
): Promise<Uint8Array> {
  if (db) {
    const cached = await idbGet(db, url);
    if (cached) {
      onSource("idb");
      return cached;
    }
  }
  onSource("network");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed: ${url} -> ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (db) {
    // write-back in background; don't block proving
    idbPut(db, url, buf).catch(() => {/* ignore — cache write failure is non-fatal */});
  }
  return buf;
}

// ---------------------------------------------------------------------------
// WASM module cache — snarkjs calls WebAssembly.compile(wasmBuf) internally
// on every fullProve call. We patch WebAssembly.compile to return a cached
// Module when the same bytes are passed again, skipping the ~150ms compile.
// The cache key is the wasm buffer's identity (===), so we hold a ref to the
// exact same Uint8Array we pass to fullProve.
// ---------------------------------------------------------------------------
const _wasmModuleCache = new Map<Uint8Array, WebAssembly.Module>();
const _origCompile = WebAssembly.compile.bind(WebAssembly);

function installWasmCompileCache() {
  (WebAssembly as unknown as Record<string, unknown>).compile = async function(
    bytes: BufferSource
  ): Promise<WebAssembly.Module> {
    // Only cache Uint8Array hits — other callers (e.g. blake2b wasm) pass through
    if (bytes instanceof Uint8Array) {
      const cached = _wasmModuleCache.get(bytes);
      if (cached) return cached;
      const mod = await _origCompile(bytes);
      _wasmModuleCache.set(bytes, mod);
      return mod;
    }
    return _origCompile(bytes as ArrayBuffer);
  };
}

async function precompileWasm(wasmBuf: Uint8Array): Promise<void> {
  const ab = wasmBuf.buffer.slice(wasmBuf.byteOffset, wasmBuf.byteOffset + wasmBuf.byteLength) as ArrayBuffer;
  const mod = await _origCompile(ab);
  _wasmModuleCache.set(wasmBuf, mod);
}

// ---------------------------------------------------------------------------
// Benchmark runner — runs entirely on the main thread using bundled snarkjs,
// exactly mirroring how the SDK tests call snarkjs.groth16.fullProve().
// ---------------------------------------------------------------------------
interface RunResult { label: string; elapsed: number; run: number; }

// v3 forces bypass of browser's immutable cache from the original demo commit
const V = "?v=3";
const CIRCUITS = [
  { label: "VALID_WALLET_CREATE", wasmUrl: `/circuits/valid_wallet_create/circuit.wasm${V}`, zkeyUrl: `/circuits/valid_wallet_create/circuit.zkey${V}`, inputsKey: "wcInputs" as const },
  { label: "VALID_INPUT",         wasmUrl: `/circuits/valid_input/circuit.wasm${V}`,         zkeyUrl: `/circuits/valid_input/circuit.zkey${V}`,         inputsKey: "inputInputs" as const },
  { label: "VALID_SPEND",         wasmUrl: `/circuits/valid_spend/circuit.wasm${V}`,         zkeyUrl: `/circuits/valid_spend/circuit.zkey${V}`,         inputsKey: "spendInputs" as const },
] as const;

const CIRCUIT_COLOR: Record<string, string> = {
  "VALID_WALLET_CREATE": "#a78bfa",
  "VALID_INPUT":         "#34d399",
  "VALID_SPEND":         "#f87171",
};

export default function ZkBenchPage() {
  const [logs, setLogs] = useState<string[]>([]);
  const [runs, setRuns] = useState<RunResult[]>([]);
  const [averages, setAverages] = useState<Record<string, number> | null>(null);
  const [fetchMs, setFetchMs] = useState<number | null>(null);
  const [fetchSources, setFetchSources] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = (msg: string) => setLogs(prev => [...prev, msg]);

  async function startBench() {
    setLogs(["Building circuit inputs (Poseidon, same derivation as SDK)..."]);
    setRuns([]);
    setAverages(null);
    setFetchMs(null);
    setFetchSources({});
    setError(null);
    setRunning(true);

    try {
      const inputs = await buildInputs(addLog);

      // Open IDB — non-fatal if unavailable (private browsing, storage denied)
      let db: IDBDatabase | null = null;
      try { db = await openArtifactDb(); } catch { addLog("IndexedDB unavailable — falling back to network only"); }

      addLog("Fetching circuit artifacts in parallel (IDB → network)...");

      const sources: Record<string, string> = {};
      const t0 = performance.now();
      // reset sources state for this run
      setFetchSources({});
      const bufs = await Promise.all(
        CIRCUITS.map(c => Promise.all([
          fetchBuf(c.wasmUrl, db, s => { sources[c.label + ".wasm"] = s; }),
          fetchBuf(c.zkeyUrl, db, s => { sources[c.label + ".zkey"] = s; }),
        ]))
      );
      const fMs = Math.round(performance.now() - t0);
      setFetchMs(fMs);
      setFetchSources({...sources});
      bufs.forEach(([wasm, zkey], i) => {
        const l = CIRCUITS[i].label;
        const wasmSrc = sources[l + ".wasm"] === "idb" ? "idb ✓" : "network";
        const zkeySrc = sources[l + ".zkey"] === "idb" ? "idb ✓" : "network";
        addLog(`  ${l}: wasm=${wasm.length}B (${wasmSrc}) zkey=${zkey.length}B (${zkeySrc})`);
      });

      // Install cache patch once, then pre-compile all three wasm modules in parallel.
      // Every subsequent fullProve call hits the cache instead of recompiling.
      installWasmCompileCache();
      addLog("Pre-compiling wasm modules...");
      const tCompile = performance.now();
      await Promise.all(bufs.map(([wasm]) => precompileWasm(wasm)));
      const compileMs = Math.round(performance.now() - tCompile);
      addLog(`Wasm compiled in ${compileMs}ms. Starting proofs (${CIRCUITS.length} circuits × 3 runs)...`);

      const results: RunResult[] = [];
      for (let ci = 0; ci < CIRCUITS.length; ci++) {
        const c = CIRCUITS[ci];
        const [wasmBuf, zkeyBuf] = bufs[ci];
        const circuitInputs = inputs[c.inputsKey];

        for (let i = 0; i < 3; i++) {
          addLog(`${c.label} run ${i + 1}...`);
          const t = performance.now();
          // wasmBuf is the same Uint8Array reference that's cached — compile() returns
          // the pre-built Module immediately, skipping the ~150ms compile per call.
          await groth16.fullProve(circuitInputs, wasmBuf, zkeyBuf);
          const elapsed = Math.round(performance.now() - t);
          const r: RunResult = { label: c.label, elapsed, run: i + 1 };
          results.push(r);
          setRuns(prev => [...prev, r]);
          addLog(`  → ${elapsed}ms`);
        }
      }

      const avg = (label: string) => {
        const times = results.filter(r => r.label === label).map(r => r.elapsed);
        return Math.round(times.reduce((a, b) => a + b, 0) / times.length);
      };
      const avgWC = avg("VALID_WALLET_CREATE");
      const avgIN = avg("VALID_INPUT");
      const avgSP = avg("VALID_SPEND");
      setAverages({ "VALID_WALLET_CREATE": avgWC, "VALID_INPUT": avgIN, "VALID_SPEND": avgSP });
      addLog(`Done. Wasm compile (one-time): ${compileMs}ms`);
    } catch (e) {
      const msg = e instanceof Error ? e.message + (e.stack ? "\n" + e.stack : "") : String(e);
      setError(msg);
    } finally {
      setRunning(false);
    }
  }

  const avgs = averages;

  return (
    <div style={{ fontFamily: "monospace", background: "#0f0f0f", color: "#e5e5e5", minHeight: "100vh", padding: "2rem", maxWidth: "680px" }}>
      <h1 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: "0.2rem" }}>ZK Prover Benchmark</h1>
      <p style={{ color: "#555", fontSize: "0.72rem", marginBottom: "1.5rem", lineHeight: 1.6 }}>
        Real browser Groth16 proving time — snarkjs bundled, wasm pre-compiled once (reused across runs), main-thread.<br />
        3 runs per circuit. valid_spend 5.4MB zkey · valid_input 5.2MB · valid_wallet_create 1.4MB
      </p>

      <button
        onClick={startBench}
        disabled={running}
        style={{
          background: running ? "#1a1a1a" : "#7c3aed",
          color: running ? "#444" : "#fff",
          border: "1px solid " + (running ? "#2a2a2a" : "#7c3aed"),
          borderRadius: "6px", padding: "0.5rem 1.1rem",
          cursor: running ? "not-allowed" : "pointer",
          fontSize: "0.82rem", fontFamily: "monospace", marginBottom: "1.75rem",
        }}
      >
        {running ? "● Running... (UI may freeze during proving)" : "▶ Run Benchmark"}
      </button>

      {runs.length > 0 && (
        <div style={{ marginBottom: "1.75rem" }}>
          <div style={{ color: "#444", fontSize: "0.68rem", letterSpacing: "0.06em", marginBottom: "0.6rem" }}>LIVE RESULTS</div>
          {runs.map((r, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: "0.7rem", marginBottom: "0.28rem" }}>
              <span style={{ color: CIRCUIT_COLOR[r.label], width: "21ch", fontSize: "0.78rem" }}>{r.label}</span>
              <span style={{ color: "#3a3a3a", fontSize: "0.72rem", width: "3ch" }}>#{r.run}</span>
              <div style={{ background: CIRCUIT_COLOR[r.label], height: "9px", width: `${Math.min(r.elapsed / 15, 300)}px`, borderRadius: "2px" }} />
              <span style={{ color: "#ccc", fontSize: "0.78rem" }}>{r.elapsed}ms</span>
            </div>
          ))}
        </div>
      )}

      {avgs && (
        <div style={{ background: "#111", border: "1px solid #222", borderRadius: "8px", padding: "1rem 1.2rem", marginBottom: "1.75rem" }}>
          <div style={{ color: "#444", fontSize: "0.68rem", letterSpacing: "0.06em", marginBottom: "0.7rem" }}>AVERAGES (3 RUNS)</div>
          {Object.entries(avgs).map(([label, ms]) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.4rem" }}>
              <span style={{ color: CIRCUIT_COLOR[label], fontSize: "0.82rem" }}>{label}</span>
              <span style={{ color: "#fff", fontWeight: 700 }}>{ms}ms</span>
            </div>
          ))}
          {fetchMs !== null && (
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.4rem" }}>
              <span style={{ color: "#555", fontSize: "0.82rem" }}>
                artifact fetch ({
                  Object.values(fetchSources).every(s => s === "idb")
                    ? "idb cache ✓"
                    : Object.values(fetchSources).some(s => s === "idb")
                      ? "partial idb"
                      : "cold, network"
                }, parallel)
              </span>
              <span style={{ color: "#555" }}>{fetchMs}ms</span>
            </div>
          )}
          <div style={{ borderTop: "1px solid #1e1e1e", marginTop: "0.7rem", paddingTop: "0.7rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <span style={{ color: "#888", fontSize: "0.78rem" }}>withdraw flow estimate</span>
              <span style={{ color: "#fbbf24", fontWeight: 700, fontSize: "1rem" }}>
                ~{avgs["VALID_INPUT"] + avgs["VALID_SPEND"] + 150 + 400}ms
              </span>
            </div>
            <div style={{ color: "#333", fontSize: "0.67rem", marginTop: "0.25rem" }}>
              VALID_INPUT + VALID_SPEND + 150ms Merkle fetch + 400ms Solana confirm
            </div>
          </div>
        </div>
      )}

      {logs.length > 0 && (
        <div style={{ background: "#080808", border: "1px solid #1a1a1a", borderRadius: "5px", padding: "0.6rem 0.9rem", maxHeight: "200px", overflowY: "auto", fontSize: "0.7rem", color: "#444", lineHeight: 1.7 }}>
          {logs.map((l, i) => <div key={i}>{l}</div>)}
          <div ref={logsEndRef} />
        </div>
      )}

      {error && (
        <div style={{ color: "#f87171", background: "#150808", border: "1px solid #450a0a", borderRadius: "6px", padding: "0.7rem", marginTop: "1rem", fontSize: "0.72rem", whiteSpace: "pre-wrap" }}>
          {error}
        </div>
      )}
    </div>
  );
}
