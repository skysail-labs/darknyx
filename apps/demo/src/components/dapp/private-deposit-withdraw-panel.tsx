"use client";

import { useEffect, useState } from "react";

import { useDappContext } from "@/lib/dapp/dapp-context";
import { formatAtoms, toAtoms } from "@/lib/dapp/decimals";
import { instructionFromJson, type InstructionJson } from "@/lib/dapp/ix-json";
import {
  readDappSessionForOwner,
  type DappSessionV1,
} from "@/lib/dapp/dapp-session";

type DepositTracking = {
  leafIndex: string;
  priorRightPathHex: string[];
  commitmentHex: string;
  recoveryNonce: string;
  innerHash: string;
  amount: string;
  side: "base" | "quote";
  tokenMintBase58: string;
};

type ReceiptLine = { label: string; signature: string };

type PanelStep = "idle" | "deposited" | "proving" | "withdrawn";

interface MintBalance {
  ata: string;
  exists: boolean;
  amount: string;
  mintBase58: string;
  decimals: number;
}

interface BalancesResponse {
  ok: boolean;
  error?: string;
  base?: MintBalance;
  quote?: MintBalance;
}

// Default is now in *human* token units (was previously raw atoms — which is
// what made the explorer show 10000 → 0.01 for 6-decimal QUOTE).
const DEFAULT_AMOUNT = process.env.NEXT_PUBLIC_DEMO_PRIVATE_AMOUNT ?? "10";

function txUrl(sig: string) {
  return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
}

function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function PrivateDepositWithdrawPanel() {
  const { forwarder, getProver, wallet } = useDappContext();
  const [session, setSession] = useState<DappSessionV1 | null>(null);
  const [step, setStep] = useState<PanelStep>("idle");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [side, setSide] = useState<"base" | "quote">("quote");
  const [amount, setAmount] = useState(DEFAULT_AMOUNT);
  const [tracking, setTracking] = useState<DepositTracking | null>(null);
  const [receipt, setReceipt] = useState<ReceiptLine[]>([]);
  const [proverMs, setProverMs] = useState<number | null>(null);
  const [balances, setBalances] = useState<BalancesResponse | null>(null);
  const connectedOwner = wallet.publicKey?.toBase58() ?? null;

  const fetchBalances = async (ownerPubkeyBase58: string) => {
    try {
      const res = await fetch("/api/dapp/balances", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ownerPubkeyBase58 }),
      });
      const json = (await res.json()) as BalancesResponse;
      setBalances(json);
    } catch (e) {
      setBalances({
        ok: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  };

  useEffect(() => {
    // SSR renders this component with a null session; hydration on the client
    // then reads sessionStorage and re-renders. See the matching note in
    // dapp-trade-flow-panel.tsx — same hydration constraint applies here.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSession(readDappSessionForOwner(connectedOwner));
    const s = readDappSessionForOwner(connectedOwner);
    if (s) {
      void fetchBalances(s.ownerPubkeyBase58);
    } else {
      setBalances(null);
    }
  }, [connectedOwner]);

  const refresh = () => {
    const s = readDappSessionForOwner(connectedOwner);
    setSession(s);
    if (s) {
      void fetchBalances(s.ownerPubkeyBase58);
    } else {
      setBalances(null);
    }
  };

  const balanceForSide = (s: "base" | "quote"): bigint | null => {
    const b = s === "base" ? balances?.base : balances?.quote;
    if (!b) return null;
    try {
      return BigInt(b.amount);
    } catch {
      return null;
    }
  };

  const decimalsForSide = (s: "base" | "quote"): number | null => {
    const b = s === "base" ? balances?.base : balances?.quote;
    return b ? b.decimals : null;
  };

  const append = (lines: ReceiptLine[]) => setReceipt((r) => [...r, ...lines]);

  const runDeposit = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) throw new Error("Complete the identity step above first.");
    const dec = decimalsForSide(side);
    if (dec == null) {
      throw new Error(
        "Token decimals not loaded yet — hit Refresh and try again.",
      );
    }
    let wantAtoms: bigint;
    try {
      wantAtoms = toAtoms(amount, dec);
    } catch (e) {
      throw new Error(e instanceof Error ? e.message : String(e));
    }
    if (wantAtoms <= 0n) throw new Error("Amount must be > 0.");
    const have = balanceForSide(side);
    if (have != null && wantAtoms > have) {
      throw new Error(
        [
          `Amount ${amount} ${side.toUpperCase()} (${wantAtoms} atoms) exceeds your balance ${formatAtoms(have, dec)} (${have} atoms).`,
          "Lower the amount, or hit Refresh to retry the auto-airdrop.",
        ].join(" "),
      );
    }
    setBusy(true);
    setError(null);
    const res = await fetch("/api/dapp/private-deposit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        side,
        // API expects raw u64 atoms; UI input is in human token units.
        amount: wantAtoms.toString(),
        nonce: (BigInt(Date.now()) + 7_777n).toString(),
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      error?: string;
      instructions?: InstructionJson[];
      tracking?: DepositTracking;
    };
    if (!res.ok || !json.ok || !json.instructions?.length || !json.tracking) {
      throw new Error(json.error ?? `HTTP ${res.status}`);
    }
    const ixs = json.instructions.map(instructionFromJson);
    const sig = await forwarder.sendAndConfirm(ixs);
    append([{ label: `private deposit (${side})`, signature: sig }]);
    setTracking(json.tracking);
    setStep("deposited");
    setBusy(false);
    void fetchBalances(s.ownerPubkeyBase58);
  };

  const runWithdraw = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) throw new Error("Session expired — re-derive your identity above.");
    if (!tracking) throw new Error("Run the deposit step first.");
    setBusy(true);
    setError(null);

    const prep = await fetch("/api/dapp/withdraw-prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        tokenMintBase58: tracking.tokenMintBase58,
        amount: tracking.amount,
        recoveryNonce: tracking.recoveryNonce,
        innerHash: tracking.innerHash,
        leafIndex: tracking.leafIndex,
        priorRightPathHex: tracking.priorRightPathHex,
      }),
    });
    const prepJson = (await prep.json()) as {
      ok?: boolean;
      error?: string;
      proverInputs?: {
        merkleRoot: string;
        nullifier: string;
        tokenMint: [string, string];
        amount: string;
        spendingKey: string;
        ownerCommitmentBlinding: string;
        innerHash: string;
        merklePath: string[];
        merkleIndices: string[];
      };
      ixContext?: {
        commitmentHex: string;
        nullifierHex: string;
        merkleRootHex: string;
      };
    };
    if (
      !prep.ok ||
      !prepJson.ok ||
      !prepJson.proverInputs ||
      !prepJson.ixContext
    ) {
      throw new Error(prepJson.error ?? `HTTP ${prep.status}`);
    }

    setStep("proving");
    const start = performance.now();
    const proof = await getProver().spend.prove({
      merkleRoot: BigInt(prepJson.proverInputs.merkleRoot),
      nullifier: BigInt(prepJson.proverInputs.nullifier),
      tokenMint: [
        BigInt(prepJson.proverInputs.tokenMint[0]),
        BigInt(prepJson.proverInputs.tokenMint[1]),
      ],
      amount: BigInt(prepJson.proverInputs.amount),
      spendingKey: BigInt(prepJson.proverInputs.spendingKey),
      ownerCommitmentBlinding: BigInt(
        prepJson.proverInputs.ownerCommitmentBlinding,
      ),
      innerHash: BigInt(prepJson.proverInputs.innerHash),
      merklePath: prepJson.proverInputs.merklePath.map((p) => BigInt(p)),
      merkleIndices: prepJson.proverInputs.merkleIndices.map((i) => Number(i)),
    });
    setProverMs(Math.round(performance.now() - start));

    const fin = await fetch("/api/dapp/withdraw-finalize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        tokenMintBase58: tracking.tokenMintBase58,
        amount: tracking.amount,
        commitmentHex: prepJson.ixContext.commitmentHex,
        nullifierHex: prepJson.ixContext.nullifierHex,
        merkleRootHex: prepJson.ixContext.merkleRootHex,
        proof: {
          piA: bytesToHex(proof.piA),
          piB: bytesToHex(proof.piB),
          piC: bytesToHex(proof.piC),
        },
      }),
    });
    const finJson = (await fin.json()) as {
      ok?: boolean;
      error?: string;
      instruction?: InstructionJson;
    };
    if (!fin.ok || !finJson.ok || !finJson.instruction) {
      throw new Error(finJson.error ?? `HTTP ${fin.status}`);
    }
    const sig = await forwarder.sendAndConfirm([
      instructionFromJson(finJson.instruction),
    ]);
    append([{ label: `withdraw via VALID_SPEND (${side})`, signature: sig }]);
    setStep("withdrawn");
    setBusy(false);
  };

  const onClick = async () => {
    try {
      refresh();
      if (!readDappSessionForOwner(connectedOwner)) return;
      if (step === "idle") await runDeposit();
      else if (step === "deposited") await runWithdraw();
    } catch (e) {
      let msg = e instanceof Error ? e.message : String(e);
      if (/insufficient funds/i.test(msg)) {
        msg += [
          "",
          "This is your wallet's plain SPL balance — not your shielded pool balance.",
          "Lower the amount, or hit Re-derive in the identity panel to top up demo BASE/QUOTE.",
        ].join("\n");
      }
      setError(msg);
      setBusy(false);
    }
  };

  const reset = () => {
    setTracking(null);
    setStep("idle");
    setReceipt([]);
    setError(null);
    setProverMs(null);
  };

  const s0 = session ?? readDappSessionForOwner(connectedOwner);
  const label =
    step === "idle"
      ? "Private deposit"
      : step === "deposited"
        ? "Withdraw via VALID_SPEND"
        : step === "proving"
          ? "Proving in browser…"
          : "Done";

  return (
    <section className="rounded-2xl border border-white/[0.08] bg-nyx-graphite p-6 shadow-sm shadow-black/20">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-nyx-chalk">
            Private deposit / withdraw
          </h2>
          <p className="mt-1 max-w-xl text-xs text-nyx-fog">
            End-to-end privacy primitive. A deposit hashes a fresh shielded note
            — a Poseidon commitment over{" "}
            <span className="font-mono">(token, amount, owner, blinding)</span>{" "}
            — and inserts it into the on-chain Merkle tree. To withdraw, your
            browser proves{" "}
            <code className="mx-1 rounded bg-white/[0.06] px-1 text-nyx-chalk">
              VALID_SPEND
            </code>{" "}
            in Groth16: it reveals a nullifier (so the note can&rsquo;t be
            double-spent) and asserts a Merkle inclusion witness for that
            commitment — without disclosing which leaf is yours, who deposited
            it, or how much it&rsquo;s worth. Run withdraw <em>before</em>{" "}
            placing a trade on the same identity, otherwise new leaves
            invalidate the cached witness.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={refresh}
            className="rounded-md border border-white/12 bg-white/[0.03] px-3 py-2 text-xs font-semibold text-nyx-chalk hover:bg-white/[0.06]"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={reset}
            className="rounded-md border border-white/12 bg-white/[0.03] px-3 py-2 text-xs font-semibold text-nyx-chalk hover:bg-white/[0.06]"
          >
            Reset
          </button>
        </div>
      </div>

      {!s0 ? (
        <p className="text-sm text-nyx-fog">
          Finish the identity step above — session will appear here.
        </p>
      ) : (
        <>
          <div className="mb-3 grid grid-cols-1 gap-2 text-[11px] text-nyx-chalk sm:grid-cols-2">
            <div className="rounded-md border border-white/[0.05] bg-nyx-graphite-2/55 px-3 py-2">
              <div className="font-mono uppercase tracking-wide text-[10px] text-nyx-slate">
                BASE balance
              </div>
              <div className="mt-0.5 font-mono">
                {balances?.base
                  ? `${formatAtoms(balances.base.amount, balances.base.decimals)} BASE`
                  : "?"}
                {balances?.base && !balances.base.exists ? (
                  <span className="ml-2 text-nyx-signal-amber">
                    (no ATA yet)
                  </span>
                ) : null}
              </div>
            </div>
            <div className="rounded-md border border-white/[0.05] bg-nyx-graphite-2/55 px-3 py-2">
              <div className="font-mono uppercase tracking-wide text-[10px] text-nyx-slate">
                QUOTE balance
              </div>
              <div className="mt-0.5 font-mono">
                {balances?.quote
                  ? `${formatAtoms(balances.quote.amount, balances.quote.decimals)} QUOTE`
                  : "?"}
                {balances?.quote && !balances.quote.exists ? (
                  <span className="ml-2 text-nyx-signal-amber">
                    (no ATA yet)
                  </span>
                ) : null}
              </div>
            </div>
            {balances && !balances.ok ? (
              <div className="sm:col-span-2 rounded-md border border-nyx-signal-red/35 bg-nyx-signal-red/10 px-3 py-2 text-nyx-signal-red">
                balance lookup failed: {balances.error}
              </div>
            ) : null}
          </div>

          <div className="mb-4 flex flex-wrap items-end gap-3">
            <label className="text-xs text-nyx-fog">
              Side
              <select
                className="ml-2 rounded border border-white/12 bg-white/[0.03] px-2 py-1 font-mono text-sm text-nyx-chalk"
                value={side}
                onChange={(e) => setSide(e.target.value as "base" | "quote")}
                disabled={step !== "idle"}
              >
                <option value="quote">QUOTE</option>
                <option value="base">BASE</option>
              </select>
            </label>
            <label className="text-xs text-nyx-fog">
              Amount
              <input
                className="ml-2 w-32 rounded border border-white/12 bg-white/[0.03] px-2 py-1 font-mono text-sm text-nyx-chalk"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                disabled={step !== "idle"}
              />
            </label>
          </div>

          {tracking ? (
            <div className="mb-3 rounded-md border border-white/[0.05] bg-nyx-graphite-2/55 px-3 py-2 text-[11px] text-nyx-chalk">
              <div>
                leaf <span className="font-mono">{tracking.leafIndex}</span> ·
                note commitment
              </div>
              <div
                className="mt-0.5 truncate font-mono text-nyx-slate"
                title={tracking.commitmentHex}
              >
                {tracking.commitmentHex.slice(0, 32)}…
                {tracking.commitmentHex.slice(-12)}
              </div>
            </div>
          ) : null}

          {proverMs != null ? (
            <p className="mb-2 text-[11px] text-nyx-slate">
              VALID_SPEND proof generated in{" "}
              <span className="font-mono">{proverMs} ms</span> (browser)
            </p>
          ) : null}

          <button
            type="button"
            disabled={busy || step === "withdrawn" || step === "proving"}
            onClick={() => void onClick()}
            className="rounded-md bg-indigo-700 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-white hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Working…" : label}
          </button>

          {error ? (
            <div className="mt-3 rounded-md border border-nyx-signal-red/35 bg-nyx-signal-red/10 px-3 py-2 text-xs text-nyx-signal-red">
              {error}
            </div>
          ) : null}

          {step === "withdrawn" ? (
            <div className="mt-4 rounded-md border border-nyx-signal-green/35 bg-nyx-signal-green/10 px-3 py-2 text-xs text-nyx-signal-green">
              <span className="font-semibold">Withdraw confirmed.</span> Your
              shielded note has been spent — the on-chain nullifier is now
              recorded, so this note can never be re-spent or linked back to its
              deposit.
            </div>
          ) : null}

          {receipt.length > 0 ? (
            <div className="mt-5">
              <h3 className="text-sm font-semibold text-nyx-chalk">Receipt</h3>
              <ul className="mt-2 space-y-1 text-xs">
                {receipt.map((r, i) => (
                  <li
                    key={`${r.signature}-${i}`}
                    className="font-mono text-nyx-chalk"
                  >
                    <span className="text-nyx-slate">{r.label}</span> ·{" "}
                    <a
                      className="text-nyx-accent hover:underline"
                      href={txUrl(r.signature)}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {r.signature.slice(0, 10)}…
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}
