"use client";

import { useCallback, useEffect, useState } from "react";

import { useDappContext } from "@/lib/dapp/dapp-context";
import { readDappSession } from "@/lib/dapp/dapp-session";
import { instructionFromJson, type InstructionJson } from "@/lib/dapp/ix-json";
import { NYX_TRADE_WITHDRAW_KEY } from "@/lib/dapp/trade-withdraw-storage";

type Stored = {
  tradeWithdrawBuyerBase: {
    matchId: string;
    leafIndex: string;
    amount: string;
    nonce: string;
    blindingR: string;
    commitmentHex: string;
    tokenMintBase58: string;
    vaultLeafCountAfter: string;
  };
  ownerCommitmentHex: string;
};

function txUrl(sig: string) {
  return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
}

function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function TradeBaseWithdrawPanel() {
  const { forwarder, getProver } = useDappContext();
  const [stored, setStored] = useState<Stored | null>(null);
  const [step, setStep] = useState<"idle" | "proving" | "done">("idle");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [proverMs, setProverMs] = useState<number | null>(null);

  const refresh = useCallback(() => {
    try {
      const raw = sessionStorage.getItem(NYX_TRADE_WITHDRAW_KEY);
      setStored(raw ? (JSON.parse(raw) as Stored) : null);
    } catch {
      setStored(null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const clearHint = () => {
    try {
      sessionStorage.removeItem(NYX_TRADE_WITHDRAW_KEY);
    } catch {
      /* ignore */
    }
    setStored(null);
    setStep("idle");
    setReceipt(null);
    setProverMs(null);
    setError(null);
  };

  const runWithdraw = async () => {
    const s = readDappSession();
    if (!s) throw new Error("Session missing — re-derive identity.");
    if (!stored)
      throw new Error("Nothing to withdraw — complete trade step 5 first.");
    setBusy(true);
    setError(null);
    try {
      const prep = await fetch("/api/dapp/trade-withdraw-prepare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          phantomSignatureBase58: s.phantomSignatureBase58,
          ownerPubkeyBase58: s.ownerPubkeyBase58,
          ownerCommitmentHex: stored.ownerCommitmentHex,
          matchId: stored.tradeWithdrawBuyerBase.matchId,
          tokenMintBase58: stored.tradeWithdrawBuyerBase.tokenMintBase58,
          amount: stored.tradeWithdrawBuyerBase.amount,
          nonce: stored.tradeWithdrawBuyerBase.nonce,
          blindingR: stored.tradeWithdrawBuyerBase.blindingR,
          leafIndex: stored.tradeWithdrawBuyerBase.leafIndex,
          commitmentHex: stored.tradeWithdrawBuyerBase.commitmentHex,
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
          nonce: string;
          blindingR: string;
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
      const t0 = performance.now();
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
        nonce: BigInt(prepJson.proverInputs.nonce),
        blindingR: BigInt(prepJson.proverInputs.blindingR),
        merklePath: prepJson.proverInputs.merklePath.map((p) => BigInt(p)),
        merkleIndices: prepJson.proverInputs.merkleIndices.map((i) =>
          Number(i),
        ),
      });
      setProverMs(Math.round(performance.now() - t0));

      const fin = await fetch("/api/dapp/withdraw-finalize", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          phantomSignatureBase58: s.phantomSignatureBase58,
          ownerPubkeyBase58: s.ownerPubkeyBase58,
          tokenMintBase58: stored.tradeWithdrawBuyerBase.tokenMintBase58,
          amount: stored.tradeWithdrawBuyerBase.amount,
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
      setReceipt(sig);
      setStep("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStep("idle");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-zinc-900">
            Withdraw trade BASE (VALID_SPEND)
          </h2>
          <p className="mt-1 max-w-xl text-xs text-zinc-600">
            After step 5 settles on L1, your matched{" "}
            <span className="font-semibold">BASE</span> leg lives as shielded{" "}
            <code className="mx-1 rounded bg-zinc-100 px-1 font-mono text-[11px]">
              note_c
            </code>
            . This panel proves ownership in-browser and calls{" "}
            <code className="mx-1 rounded bg-zinc-100 px-1 font-mono text-[11px]">
              withdraw
            </code>{" "}
            to your BASE ATA. You cannot &ldquo;list all leaves that are
            mine&rdquo; from chain data alone — note commitments are opaque;
            this demo only tracks the one BASE note produced by your last
            counter-and-match settle (stored in session when step 5 completes).
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={refresh}
            className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-50"
          >
            Refresh
          </button>
          {stored ? (
            <button
              type="button"
              onClick={clearHint}
              className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-50"
            >
              Clear
            </button>
          ) : null}
        </div>
      </div>

      {!stored ? (
        <p className="text-sm text-zinc-600">
          No pending trade BASE note. Finish{" "}
          <span className="font-semibold">Counterparty + run_batch</span> in the
          trade panel — the server runs L1{" "}
          <code className="rounded bg-zinc-100 px-1 text-[11px]">
            lock_note
          </code>{" "}
          +{" "}
          <code className="rounded bg-zinc-100 px-1 text-[11px]">
            tee_forced_settle
          </code>{" "}
          and stores the note here.
        </p>
      ) : (
        <>
          <div className="mb-3 rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-[11px] text-zinc-700">
            <div>
              match{" "}
              <span className="font-mono">
                {stored.tradeWithdrawBuyerBase.matchId}
              </span>{" "}
              · leaf{" "}
              <span className="font-mono">
                {stored.tradeWithdrawBuyerBase.leafIndex}
              </span>{" "}
              · amount (raw u64){" "}
              <span className="font-mono">
                {stored.tradeWithdrawBuyerBase.amount}
              </span>
            </div>
            <div
              className="mt-0.5 truncate font-mono text-zinc-500"
              title={stored.tradeWithdrawBuyerBase.commitmentHex}
            >
              {stored.tradeWithdrawBuyerBase.commitmentHex.slice(0, 24)}…
            </div>
            <div className="mt-1 text-[10px] text-zinc-500">
              vault leaf_count after settle:{" "}
              {stored.tradeWithdrawBuyerBase.vaultLeafCountAfter}
            </div>
          </div>

          {proverMs != null ? (
            <p className="mb-2 text-[11px] text-zinc-500">
              VALID_SPEND proof:{" "}
              <span className="font-mono">{proverMs} ms</span>
            </p>
          ) : null}

          <button
            type="button"
            disabled={busy || step === "done"}
            onClick={() => {
              void runWithdraw();
            }}
            className="rounded-md bg-teal-800 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-white hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy
              ? "Working…"
              : step === "done"
                ? "Withdrawn"
                : "Withdraw BASE to wallet"}
          </button>

          {error ? (
            <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              {error}
            </div>
          ) : null}

          {step === "done" && receipt ? (
            <div className="mt-4 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-900">
              <span className="font-semibold">Withdraw confirmed.</span>{" "}
              <a
                className="ml-1 underline"
                href={txUrl(receipt)}
                target="_blank"
                rel="noreferrer"
              >
                Explorer
              </a>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}
