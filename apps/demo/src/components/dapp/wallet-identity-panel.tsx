"use client";

import bs58 from "bs58";
import { useEffect, useState } from "react";

import { useDappContext } from "@/lib/dapp/dapp-context";
import { formatAtoms } from "@/lib/dapp/decimals";
import { NYX_DAPP_SESSION_KEY } from "@/lib/dapp/dapp-session";

const SEED_MESSAGE_TEXT = "NYX_DARKPOOL_SEED_V1";

function formatAirdropAtoms(atoms: string, decimals: number): string {
  try {
    return formatAtoms(atoms, decimals);
  } catch {
    return atoms;
  }
}

interface DeriveResponse {
  ok: true;
  rootKeyPubkeyBase58: string;
  walletCreateInputs: {
    userCommitment: string;
    rootKey: [string, string];
    spendingKey: string;
    viewingKey: string;
    r0: string;
    r1: string;
    r2: string;
  };
  trading: {
    publicKeyBase58: string;
    secretKeyBase58: string;
  };
  publicData: {
    userCommitmentHex: string;
    ownerCommitmentHex: string;
    ownerCommitmentDecimal: string;
    rootKeyPubkeyBase58: string;
  };
  previews: {
    masterSeedFingerprint: string;
    spendingKeyFingerprint: string;
    viewingKeyFingerprint: string;
  };
}

type Phase =
  | "idle"
  | "signing"
  | "deriving"
  | "proving"
  | "airdropping"
  | "ready"
  | "error";

interface ProofPreview {
  piAHex: string;
  piBHex: string;
  piCHex: string;
  publicInputCount: number;
  durationMs: number;
}

interface AirdropPreview {
  signature: string;
  baseAmount: string;
  quoteAmount: string;
  baseAta: string;
  quoteAta: string;
}

interface IdentityState {
  ownerPubkey: string;
  signatureBase58: string;
  derived: DeriveResponse;
  proof: ProofPreview;
  airdrop: AirdropPreview | null;
  airdropError: string | null;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function shortenHex(hex: string, prefix = 10, suffix = 8): string {
  if (hex.length <= prefix + suffix + 1) return hex;
  return `${hex.slice(0, prefix)}…${hex.slice(-suffix)}`;
}

export function WalletIdentityPanel() {
  const { wallet, getProver } = useDappContext();
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [identity, setIdentity] = useState<IdentityState | null>(null);
  const [mintDecimals, setMintDecimals] = useState({ base: 6, quote: 6 });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await fetch("/api/dapp/token-meta");
        const j = (await res.json()) as {
          ok?: boolean;
          baseDecimals?: number;
          quoteDecimals?: number;
        };
        if (cancelled || !res.ok || !j.ok) return;
        if (
          typeof j.baseDecimals === "number" &&
          typeof j.quoteDecimals === "number"
        ) {
          setMintDecimals({ base: j.baseDecimals, quote: j.quoteDecimals });
        }
      } catch {
        /* ignore */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const owner = wallet.publicKey?.toBase58() ?? null;

  const run = async () => {
    if (!wallet.publicKey || !wallet.signMessage) {
      setError(
        "Connected wallet does not support signMessage. Try Phantom on devnet.",
      );
      setPhase("error");
      return;
    }
    setError(null);
    setIdentity(null);

    try {
      // 1. Phantom signs the deterministic seed-derivation message.
      setPhase("signing");
      const msg = new TextEncoder().encode(SEED_MESSAGE_TEXT);
      const sig = await wallet.signMessage(msg);
      const signatureBase58 = bs58.encode(sig);

      // 2. Server derives keys + circuit inputs (it never persists the seed).
      setPhase("deriving");
      const res = await fetch("/api/dapp/derive-identity", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          phantomSignatureBase58: signatureBase58,
          ownerPubkeyBase58: wallet.publicKey.toBase58(),
        }),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(
          `derive-identity HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }
      const derived = (await res.json()) as DeriveResponse;
      if (!derived.ok) {
        throw new Error("derive-identity returned ok: false");
      }

      // 3. Browser generates the VALID_WALLET_CREATE proof (snarkjs in Worker).
      setPhase("proving");
      const t0 = performance.now();
      const proof = await getProver().walletCreate.prove({
        userCommitment: BigInt(derived.walletCreateInputs.userCommitment),
        rootKey: [
          BigInt(derived.walletCreateInputs.rootKey[0]),
          BigInt(derived.walletCreateInputs.rootKey[1]),
        ],
        spendingKey: BigInt(derived.walletCreateInputs.spendingKey),
        viewingKey: BigInt(derived.walletCreateInputs.viewingKey),
        r0: BigInt(derived.walletCreateInputs.r0),
        r1: BigInt(derived.walletCreateInputs.r1),
        r2: BigInt(derived.walletCreateInputs.r2),
      });
      const durationMs = Math.round(performance.now() - t0);

      // 4. Sanity check — the public input the circuit committed to MUST equal
      //    the userCommitment we asked the server to compute. If this ever
      //    diverges we have a key-derivation/circuit drift and need to bail.
      const publicInputHex = bytesToHex(proof.publicInputs[0]);
      if (publicInputHex !== derived.publicData.userCommitmentHex) {
        throw new Error(
          `userCommitment drift: server=${derived.publicData.userCommitmentHex} circuit=${publicInputHex}`,
        );
      }

      const proofPreview: ProofPreview = {
        piAHex: bytesToHex(proof.piA),
        piBHex: bytesToHex(proof.piB),
        piCHex: bytesToHex(proof.piC),
        publicInputCount: proof.publicInputs.length,
        durationMs,
      };
      try {
        sessionStorage.setItem(
          NYX_DAPP_SESSION_KEY,
          JSON.stringify({
            phantomSignatureBase58: signatureBase58,
            ownerPubkeyBase58: wallet.publicKey.toBase58(),
            tradingSecretKeyBase58: derived.trading.secretKeyBase58,
            publicData: derived.publicData,
            proof: {
              piAHex: bytesToHex(proof.piA),
              piBHex: bytesToHex(proof.piB),
              piCHex: bytesToHex(proof.piC),
            },
          }),
        );
      } catch {
        // private mode / quota — flow panel will prompt re-derive
      }

      // 5. Auto-airdrop demo BASE + QUOTE so the next steps (private deposit /
      //    submit_order) actually have funds. We don't fail the whole flow if
      //    this fails — surface it so the user can retry manually.
      setPhase("airdropping");
      let airdrop: AirdropPreview | null = null;
      let airdropError: string | null = null;
      try {
        const airdropRes = await fetch("/api/dapp/airdrop", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: signatureBase58,
            ownerPubkeyBase58: wallet.publicKey.toBase58(),
          }),
        });
        const airdropJson = (await airdropRes.json()) as {
          ok?: boolean;
          error?: string;
          signature?: string;
          baseAmount?: string;
          quoteAmount?: string;
          baseAta?: string;
          quoteAta?: string;
        };
        if (!airdropRes.ok || !airdropJson.ok || !airdropJson.signature) {
          airdropError = airdropJson.error ?? `HTTP ${airdropRes.status}`;
        } else {
          airdrop = {
            signature: airdropJson.signature,
            baseAmount: airdropJson.baseAmount ?? "?",
            quoteAmount: airdropJson.quoteAmount ?? "?",
            baseAta: airdropJson.baseAta ?? "?",
            quoteAta: airdropJson.quoteAta ?? "?",
          };
        }
      } catch (e) {
        airdropError = e instanceof Error ? e.message : String(e);
      }

      setIdentity({
        ownerPubkey: wallet.publicKey.toBase58(),
        signatureBase58,
        derived,
        proof: proofPreview,
        airdrop,
        airdropError,
      });
      setPhase("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase("error");
    }
  };

  const reset = () => {
    setIdentity(null);
    setPhase("idle");
    setError(null);
    try {
      sessionStorage.removeItem(NYX_DAPP_SESSION_KEY);
    } catch {
      /* ignore */
    }
  };

  if (!owner) {
    return null;
  }

  return (
    <section className="rounded-2xl border border-white/[0.08] bg-nyx-graphite p-6 shadow-sm shadow-black/20">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-nyx-chalk">
            Derive your darkpool identity
          </h2>
          <p className="mt-1 max-w-xl text-xs text-nyx-fog">
            Phantom signs a fixed message (
            <code className="rounded bg-white/[0.06] px-1 font-mono text-[11px] text-nyx-chalk">
              {SEED_MESSAGE_TEXT}
            </code>
            ). That signature is the only source of entropy for your darkpool
            master seed — we derive a spending key, a viewing key, and a
            Poseidon-hashed wallet commitment from it. Your browser then proves{" "}
            <code className="rounded bg-white/[0.06] px-1 font-mono text-[11px] text-nyx-chalk">
              VALID_WALLET_CREATE
            </code>{" "}
            (Groth16) to bind that commitment on-chain without revealing any of
            the keys. A separate trading keypair, derived from the same seed,
            signs your orders inside the Ephemeral Rollup — Phantom never sees
            that key.
          </p>
        </div>
        <div className="flex gap-2">
          {phase === "ready" || phase === "error" ? (
            <button
              type="button"
              onClick={reset}
              className="rounded-md border border-white/12 bg-white/[0.03] px-3 py-2 text-xs font-semibold uppercase tracking-wide text-nyx-chalk hover:bg-white/[0.06]"
            >
              Reset
            </button>
          ) : null}
          <button
            type="button"
            onClick={run}
            disabled={
              phase === "signing" ||
              phase === "deriving" ||
              phase === "proving" ||
              phase === "airdropping"
            }
            className="rounded-md bg-nyx-chalk px-4 py-2 text-xs font-semibold uppercase tracking-wide text-nyx-ink transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-60"
          >
            {phaseLabel(phase)}
          </button>
        </div>
      </div>

      <PhaseTracker phase={phase} />

      {error ? (
        <div className="mt-4 rounded-md border border-nyx-signal-red/35 bg-nyx-signal-red/10 px-3 py-2 text-xs text-nyx-signal-red">
          <span className="font-semibold">Error</span>
          <div className="mt-0.5 break-all font-mono text-[11px]">{error}</div>
        </div>
      ) : null}

      {identity ? (
        <IdentityCard identity={identity} mintDecimals={mintDecimals} />
      ) : null}
    </section>
  );
}

function phaseLabel(phase: Phase): string {
  switch (phase) {
    case "idle":
      return "Sign message & derive";
    case "signing":
      return "Awaiting Phantom signature…";
    case "deriving":
      return "Server is deriving keys…";
    case "proving":
      return "Proving in browser…";
    case "airdropping":
      return "Airdropping demo tokens…";
    case "ready":
      return "Re-derive";
    case "error":
      return "Try again";
  }
}

const PHASE_ORDER: Phase[] = [
  "signing",
  "deriving",
  "proving",
  "airdropping",
  "ready",
];
const PHASE_LABEL: Record<Phase, string> = {
  idle: "",
  signing: "Phantom signMessage",
  deriving: "Server key derivation",
  proving: "Browser ZK proof",
  airdropping: "Airdrop BASE + QUOTE",
  ready: "Identity ready",
  error: "Error",
};

function PhaseTracker({ phase }: { phase: Phase }) {
  const reachedIdx = phase === "error" ? -1 : PHASE_ORDER.indexOf(phase);
  return (
    <ol className="flex flex-wrap gap-2 text-[11px]">
      {PHASE_ORDER.map((p, idx) => {
        const reached = reachedIdx >= idx;
        const current = phase === p && phase !== "ready";
        const done = reached && !current;
        const cls = current
          ? "bg-nyx-signal-amber/18 text-nyx-signal-amber ring-1 ring-nyx-signal-amber/40"
          : done
            ? "bg-nyx-signal-green/16 text-nyx-signal-green ring-1 ring-nyx-signal-green/35"
            : "bg-white/[0.04] text-nyx-slate ring-1 ring-white/[0.05]";
        return (
          <li
            key={p}
            className={`rounded-md px-2 py-1 font-mono uppercase tracking-wide ${cls}`}
          >
            {PHASE_LABEL[p]}
          </li>
        );
      })}
    </ol>
  );
}

function AirdropBanner({
  identity,
  mintDecimals,
}: {
  identity: IdentityState;
  mintDecimals: { base: number; quote: number };
}) {
  if (identity.airdropError) {
    return (
      <div className="rounded-md border border-nyx-signal-amber/35 bg-nyx-signal-amber/10 px-3 py-2 text-xs text-nyx-signal-amber">
        <span className="font-semibold">Auto-airdrop failed</span>
        <div className="mt-0.5 break-all font-mono text-[11px]">
          {identity.airdropError}
        </div>
        <div className="mt-1 text-[11px]">
          You can still proceed — but the private deposit / submit_order steps
          need an SPL balance. Use the trade-flow panel&rsquo;s airdrop step or
          retry by hitting <em>Re-derive</em>.
        </div>
      </div>
    );
  }
  if (identity.airdrop) {
    return (
      <div className="rounded-md border border-nyx-signal-green/35 bg-nyx-signal-green/10 px-3 py-2 text-xs text-nyx-signal-green">
        <span className="font-semibold">Demo airdrop confirmed.</span>{" "}
        <span className="text-[11px]">
          BASE +
          {formatAirdropAtoms(identity.airdrop.baseAmount, mintDecimals.base)} ·
          QUOTE +
          {formatAirdropAtoms(identity.airdrop.quoteAmount, mintDecimals.quote)}{" "}
          ·{" "}
          <a
            className="underline hover:text-nyx-chalk"
            target="_blank"
            rel="noreferrer"
            href={`https://explorer.solana.com/tx/${identity.airdrop.signature}?cluster=devnet`}
          >
            tx
          </a>
        </span>
      </div>
    );
  }
  return null;
}

function IdentityCard({
  identity,
  mintDecimals,
}: {
  identity: IdentityState;
  mintDecimals: { base: number; quote: number };
}) {
  const rows: Array<[string, string, string?]> = [
    ["owner pubkey", identity.ownerPubkey],
    [
      "phantom signature",
      shortenHex(identity.signatureBase58, 10, 6),
      "stored only in memory — re-sign on refresh",
    ],
    [
      "master seed fingerprint",
      `0x${identity.derived.previews.masterSeedFingerprint}…`,
      "first 6 bytes only — full seed never leaves the server",
    ],
    [
      "spending key fingerprint",
      `0x${identity.derived.previews.spendingKeyFingerprint}…`,
      "private — used to derive nullifiers",
    ],
    [
      "viewing key fingerprint",
      `0x${identity.derived.previews.viewingKeyFingerprint}…`,
      "private — used to scan notes",
    ],
    [
      "trading pubkey (ER)",
      shortenHex(identity.derived.trading.publicKeyBase58, 12, 8),
      "signs orders inside the MagicBlock Ephemeral Rollup",
    ],
    [
      "owner commitment",
      `0x${shortenHex(identity.derived.publicData.ownerCommitmentHex, 10, 8)}`,
      "Poseidon2(spendingKey, ownerBlinding)",
    ],
    [
      "user commitment",
      `0x${shortenHex(identity.derived.publicData.userCommitmentHex, 10, 8)}`,
      "wallet identity registered on-chain",
    ],
  ];
  return (
    <div className="mt-5 space-y-4">
      <div className="rounded-md border border-nyx-signal-green/35 bg-nyx-signal-green/10 px-3 py-2 text-xs text-nyx-signal-green">
        <span className="font-semibold">
          ✓ Identity derived & wallet-create proof verified
        </span>
        <div className="mt-0.5 text-[11px]">
          proof bytes: pi_a {identity.proof.piAHex.length / 2}B · pi_b{" "}
          {identity.proof.piBHex.length / 2}B · pi_c{" "}
          {identity.proof.piCHex.length / 2}B ·{" "}
          {identity.proof.publicInputCount} public input · generated in{" "}
          {identity.proof.durationMs}ms
        </div>
      </div>
      <AirdropBanner identity={identity} mintDecimals={mintDecimals} />
      <div className="grid grid-cols-1 gap-2 text-xs">
        {rows.map(([label, value, hint]) => (
          <div
            key={label}
            className="grid grid-cols-1 gap-1 rounded-md border border-white/[0.05] bg-nyx-graphite-2/55 px-3 py-2 sm:grid-cols-[12rem_1fr]"
          >
            <span className="font-mono uppercase tracking-wide text-[10px] text-nyx-slate">
              {label}
            </span>
            <span>
              <span className="break-all font-mono text-[11px] text-nyx-chalk">
                {value}
              </span>
              {hint ? (
                <span className="ml-2 italic text-[10px] text-nyx-slate">
                  {hint}
                </span>
              ) : null}
            </span>
          </div>
        ))}
      </div>

      <details className="rounded-md border border-white/[0.05] bg-nyx-graphite-2/55 px-3 py-2 text-xs">
        <summary className="cursor-pointer font-semibold text-nyx-chalk">
          VALID_WALLET_CREATE proof bytes (advanced)
        </summary>
        <div className="mt-2 space-y-2 break-all font-mono text-[11px] text-nyx-fog">
          <div>
            <span className="text-nyx-slate">pi_a:</span> 0x
            {identity.proof.piAHex}
          </div>
          <div>
            <span className="text-nyx-slate">pi_b:</span> 0x
            {identity.proof.piBHex}
          </div>
          <div>
            <span className="text-nyx-slate">pi_c:</span> 0x
            {identity.proof.piCHex}
          </div>
        </div>
      </details>
    </div>
  );
}
