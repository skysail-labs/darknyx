"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Connection, Keypair, Transaction } from "@solana/web3.js";
import bs58 from "bs58";

import { useDappContext } from "@/lib/dapp/dapp-context";
import { formatAtoms, toAtoms } from "@/lib/dapp/decimals";
import { instructionFromJson, type InstructionJson } from "@/lib/dapp/ix-json";
import {
  readDappSessionForOwner,
  type DappSessionV1,
} from "@/lib/dapp/dapp-session";

import { NYX_TRADE_WITHDRAW_KEY } from "@/lib/dapp/trade-withdraw-storage";

const ER_RPC =
  process.env.NEXT_PUBLIC_DEMO_ER_RPC_URL ?? "https://devnet.magicblock.app";

type TokenMeta = {
  baseDecimals: number;
  quoteDecimals: number;
  exchangeQuotePerBaseAtomic: string;
  orderPriceLimit: string;
};

type FlowStep =
  | "idle"
  | "registered"
  | "slot_ready"
  | "deposited"
  | "order_er"
  | "matched";

interface ReceiptLine {
  label: string;
  signature: string;
  cluster: "l1" | "er";
}

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

function txUrl(sig: string) {
  return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
}

export function DappTradeFlowPanel() {
  const { forwarder, connection: l1, wallet } = useDappContext();
  const er = useMemo(() => new Connection(ER_RPC, "confirmed"), []);

  const [session, setSession] = useState<DappSessionV1 | null>(null);
  const [step, setStep] = useState<FlowStep>("idle");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [slotIdx, setSlotIdx] = useState<number | null>(null);
  /** Human BASE size; converted with mint decimals from `/api/dapp/token-meta`. */
  const [baseAmount, setBaseAmount] = useState(
    process.env.NEXT_PUBLIC_DEMO_BASE_HUMAN ?? "1",
  );
  const [depositNonce] = useState(() =>
    (BigInt(Date.now()) + 333_333n).toString(),
  );
  const [tokenMeta, setTokenMeta] = useState<TokenMeta | null>(null);
  const connectedOwner = wallet.publicKey?.toBase58() ?? null;

  const baseDecimals = tokenMeta?.baseDecimals ?? 6;
  const quoteDecimals = tokenMeta?.quoteDecimals ?? 6;
  const quotePerBaseAtomic = useMemo(
    () => BigInt(tokenMeta?.exchangeQuotePerBaseAtomic ?? "100"),
    [tokenMeta?.exchangeQuotePerBaseAtomic],
  );
  const orderPriceLimitStr = tokenMeta?.orderPriceLimit ?? "100";
  const humanQuotePerBase = useMemo(
    () =>
      quotePerBaseAtomic *
      10n ** BigInt(Math.max(0, baseDecimals - quoteDecimals)),
    [quotePerBaseAtomic, baseDecimals, quoteDecimals],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await fetch("/api/dapp/token-meta");
        const j = (await res.json()) as {
          ok?: boolean;
          baseDecimals?: number;
          quoteDecimals?: number;
          exchangeQuotePerBaseAtomic?: string;
          orderPriceLimit?: string;
        };
        if (cancelled || !res.ok || !j.ok) return;
        if (
          typeof j.baseDecimals === "number" &&
          typeof j.quoteDecimals === "number" &&
          j.exchangeQuotePerBaseAtomic &&
          j.orderPriceLimit
        ) {
          setTokenMeta({
            baseDecimals: j.baseDecimals,
            quoteDecimals: j.quoteDecimals,
            exchangeQuotePerBaseAtomic: j.exchangeQuotePerBaseAtomic,
            orderPriceLimit: j.orderPriceLimit,
          });
        }
      } catch {
        /* keep built-in defaults */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const [depositNote, setDepositNote] = useState<{
    commitmentHex: string;
    amount: string;
  } | null>(null);
  const orderCtxRef = useRef<{ orderIdHex: string; expirySlot: string } | null>(
    null,
  );
  const [receipt, setReceipt] = useState<ReceiptLine[]>([]);
  const [balances, setBalances] = useState<BalancesResponse | null>(null);

  const fetchBalances = useCallback(async (ownerPubkeyBase58: string) => {
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
  }, []);

  const refresh = useCallback(() => {
    const s = readDappSessionForOwner(connectedOwner);
    setSession(s);
    if (s) {
      void fetchBalances(s.ownerPubkeyBase58);
    } else {
      setBalances(null);
    }
  }, [connectedOwner, fetchBalances]);

  useEffect(() => {
    // SSR renders this component with a null session; hydration on the client
    // then reads sessionStorage and re-renders. setState here is intentional —
    // a lazy initializer would touch `sessionStorage` during SSR and crash, and
    // skipping the read would leave a logged-in user looking like a fresh one
    // until they touch the form.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSession(readDappSessionForOwner(connectedOwner));
    const s = readDappSessionForOwner(connectedOwner);
    if (s) {
      void fetchBalances(s.ownerPubkeyBase58);
    } else {
      setBalances(null);
    }
  }, [connectedOwner, fetchBalances]);

  const appendReceipt = (lines: ReceiptLine[]) => {
    setReceipt((r) => [...r, ...lines]);
  };

  const runRegister = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) throw new Error("Complete the identity step above first.");
    setBusy(true);
    setError(null);
    const res = await fetch("/api/dapp/register-wallet", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        proof: s.proof,
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      error?: string;
      alreadyRegistered?: boolean;
      walletPdaBase58?: string;
      instruction?: InstructionJson;
    };
    if (!res.ok || !json.ok)
      throw new Error(json.error ?? `HTTP ${res.status}`);
    if (json.alreadyRegistered) {
      appendReceipt([
        {
          label: `wallet already registered (PDA ${json.walletPdaBase58?.slice(0, 8) ?? ""}…)`,
          signature: "skipped",
          cluster: "l1",
        },
      ]);
    } else if (json.instruction) {
      const sig = await forwarder.sendAndConfirm([
        instructionFromJson(json.instruction),
      ]);
      appendReceipt([
        { label: "create_wallet (L1)", signature: sig, cluster: "l1" },
      ]);
    } else {
      throw new Error("register-wallet: missing instruction in response");
    }
    setStep("registered");
    setBusy(false);
  };

  const runInitSlot = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) throw new Error("No session");
    setBusy(true);
    setError(null);
    const res = await fetch("/api/dapp/init-slot", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        tradingSecretKeyBase58: s.tradingSecretKeyBase58,
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      slotIdx?: number;
      error?: string;
    };
    if (!res.ok || !json.ok || json.slotIdx === undefined)
      throw new Error(json.error ?? `HTTP ${res.status}`);
    setSlotIdx(json.slotIdx);
    setStep("slot_ready");
    setBusy(false);
  };

  const baseAtomsForCurrentInput = (): bigint => {
    let baseAtoms: bigint;
    try {
      baseAtoms = toAtoms(baseAmount, baseDecimals);
    } catch (e) {
      throw new Error(e instanceof Error ? e.message : String(e));
    }
    if (baseAtoms <= 0n) throw new Error("Base amount must be > 0");
    return baseAtoms;
  };

  const runDeposit = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) throw new Error("No session");
    const baseAtoms = baseAtomsForCurrentInput();
    const quoteAtoms = baseAtoms * quotePerBaseAtomic;
    const priceLim = BigInt(orderPriceLimitStr);
    const bidNotional = baseAtoms * priceLim;
    if (quoteAtoms < bidNotional) {
      throw new Error(
        `Quote deposit (${formatAtoms(quoteAtoms, quoteDecimals)} QUOTE) is smaller than ` +
          `the bid notional (${formatAtoms(bidNotional, quoteDecimals)} QUOTE). ` +
          `Lower the base size or the order price so the shielded deposit covers the trade.`,
      );
    }
    setBusy(true);
    setError(null);
    const res = await fetch("/api/dapp/deposit-prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        side: "quote",
        amount: quoteAtoms.toString(),
        nonce: depositNonce,
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      instruction?: InstructionJson;
      preview?: { noteCommitmentHex: string };
      error?: string;
    };
    if (!res.ok || !json.ok || !json.instruction)
      throw new Error(json.error ?? `HTTP ${res.status}`);
    const sig = await forwarder.sendAndConfirm([
      instructionFromJson(json.instruction),
    ]);
    appendReceipt([
      { label: "deposit quote collateral (L1)", signature: sig, cluster: "l1" },
    ]);
    setDepositNote({
      commitmentHex: json.preview?.noteCommitmentHex ?? "",
      amount: quoteAtoms.toString(),
    });
    setStep("deposited");
    setBusy(false);
    void fetchBalances(s.ownerPubkeyBase58);
  };

  const runSubmitOrderEr = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s || slotIdx == null || !depositNote?.commitmentHex) {
      throw new Error("Complete slot + deposit steps first.");
    }
    const baseAtoms = baseAtomsForCurrentInput();
    const priceLim = BigInt(orderPriceLimitStr || "0");
    const noteAmt = BigInt(depositNote.amount);
    const required = baseAtoms * priceLim;
    if (required > noteAmt) {
      throw new Error(
        `Bid notional (${formatAtoms(required, quoteDecimals)} QUOTE) exceeds your shielded ` +
          `quote note (${formatAtoms(noteAmt, quoteDecimals)} QUOTE). ` +
          `Lower the base size or price limit, or deposit more quote.`,
      );
    }
    setBusy(true);
    setError(null);
    const trading = Keypair.fromSecretKey(
      bs58.decode(s.tradingSecretKeyBase58),
    );
    const now = await l1.getSlot("confirmed");
    const expiry = BigInt(now) + 500n;
    const orderId = crypto.getRandomValues(new Uint8Array(16));
    const orderIdHex = Buffer.from(orderId).toString("hex");
    orderCtxRef.current = { orderIdHex, expirySlot: expiry.toString() };

    const res = await fetch("/api/dapp/build-submit-order", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        tradingSecretKeyBase58: s.tradingSecretKeyBase58,
        slotIdx,
        side: 0,
        // API expects raw u64 atoms.
        amount: baseAtoms.toString(),
        priceLimit: orderPriceLimitStr,
        noteAmount: depositNote.amount,
        expirySlot: expiry.toString(),
        noteCommitmentHex: depositNote.commitmentHex,
        userOwnerCommitmentHex: s.publicData.ownerCommitmentHex,
        orderIdHex,
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      instruction?: InstructionJson;
      error?: string;
    };
    if (!res.ok || !json.ok || !json.instruction)
      throw new Error(json.error ?? `HTTP ${res.status}`);
    const tx = new Transaction().add(instructionFromJson(json.instruction));
    const { blockhash, lastValidBlockHeight } =
      await er.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.feePayer = trading.publicKey;
    tx.sign(trading);
    const sig = await er.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      preflightCommitment: "confirmed",
    });
    await er.confirmTransaction(
      { signature: sig, blockhash, lastValidBlockHeight },
      "confirmed",
    );
    appendReceipt([
      { label: "submit_order bid (PER)", signature: sig, cluster: "er" },
    ]);
    setStep("order_er");
    setBusy(false);
  };

  const runCounterMatch = async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s || slotIdx == null) throw new Error("Missing slot");
    setBusy(true);
    setError(null);
    const ctx = orderCtxRef.current;
    if (!ctx?.orderIdHex || !ctx.expirySlot) {
      throw new Error(
        "Internal: order id / expiry missing — submit_order step must run first.",
      );
    }
    const baseAtoms = baseAtomsForCurrentInput();
    const res = await fetch("/api/dapp/counter-and-match", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        phantomSignatureBase58: s.phantomSignatureBase58,
        ownerPubkeyBase58: s.ownerPubkeyBase58,
        tradingSecretKeyBase58: s.tradingSecretKeyBase58,
        userSlotIdx: slotIdx,
        userSide: 0,
        // API expects raw u64 atoms (matches what submit_order on-chain used).
        userAmount: baseAtoms.toString(),
        userPriceLimit: orderPriceLimitStr,
        userNoteAmount: depositNote?.amount ?? "0",
        userNoteCommitmentHex: depositNote?.commitmentHex ?? "",
        userOwnerCommitmentHex: s.publicData.ownerCommitmentHex,
        userOrderIdHex: ctx.orderIdHex,
        userExpirySlot: ctx.expirySlot,
      }),
    });
    const json = (await res.json()) as {
      ok?: boolean;
      signatures?: ReceiptLine[];
      error?: string;
      tradeWithdrawBuyerBase?: {
        matchId: string;
        leafIndex: string;
        amount: string;
        nonce: string;
        blindingR: string;
        commitmentHex: string;
        tokenMintBase58: string;
        vaultLeafCountAfter: string;
      };
    };
    if (!res.ok || !json.ok || !json.signatures)
      throw new Error(json.error ?? `HTTP ${res.status}`);
    appendReceipt(json.signatures);
    if (json.tradeWithdrawBuyerBase) {
      try {
        sessionStorage.setItem(
          NYX_TRADE_WITHDRAW_KEY,
          JSON.stringify({
            tradeWithdrawBuyerBase: json.tradeWithdrawBuyerBase,
            ownerCommitmentHex: s.publicData.ownerCommitmentHex,
          }),
        );
      } catch {
        /* private mode */
      }
    }
    setStep("matched");
    setBusy(false);
    void fetchBalances(s.ownerPubkeyBase58);
  };

  const nextAction = async () => {
    try {
      refresh();
      if (!readDappSessionForOwner(connectedOwner)) return;
      if (step === "idle") await runRegister();
      else if (step === "registered") await runInitSlot();
      else if (step === "slot_ready") await runDeposit();
      else if (step === "deposited") await runSubmitOrderEr();
      else if (step === "order_er") await runCounterMatch();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  const s0 = session ?? readDappSessionForOwner(connectedOwner);
  const label =
    step === "matched"
      ? "Done"
      : step === "idle"
        ? "Register wallet on-chain"
        : step === "registered"
          ? "Init + delegate PER slot"
          : step === "slot_ready"
            ? "Deposit quote collateral"
            : step === "deposited"
              ? "Submit bid on PER"
              : step === "order_er"
                ? "Match privately & settle on L1"
                : "Continue";

  return (
    <section className="rounded-2xl border border-white/[0.08] bg-nyx-graphite p-6 shadow-sm shadow-black/20">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-nyx-chalk">
            Trade on devnet
          </h2>
          <p className="mt-1 max-w-xl text-xs text-nyx-fog">
            Place a shielded bid that&rsquo;s matched inside the MagicBlock
            Private Ephemeral Rollup. Your order&rsquo;s size, side, and
            price-limit stay encrypted on the rollup; only a TEE-signed match
            result lands on L1, where the vault writes fresh shielded notes for
            buyer and seller. The demo pegs{" "}
            <span className="font-mono font-semibold text-nyx-chalk">
              1 BASE = {humanQuotePerBase.toString()} QUOTE
            </span>{" "}
            against a mock oracle (±5% circuit breaker), so the default bid
            clears without any taker price discovery.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          className="rounded-md border border-white/12 bg-white/[0.03] px-3 py-2 text-xs font-semibold text-nyx-chalk hover:bg-white/[0.06]"
        >
          Refresh
        </button>
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
              Base size (BASE)
              <input
                className="ml-2 w-28 rounded border border-white/12 bg-white/[0.03] px-2 py-1 font-mono text-sm text-nyx-chalk"
                value={baseAmount}
                onChange={(e) => setBaseAmount(e.target.value)}
                disabled={step !== "idle" && step !== "registered"}
              />
            </label>
            <span className="text-xs font-mono text-nyx-slate">
              {(() => {
                try {
                  const ba = toAtoms(baseAmount || "0", baseDecimals);
                  const qa = ba * quotePerBaseAtomic;
                  return `quote leg: ${formatAtoms(qa, quoteDecimals)} QUOTE · nonce ${depositNonce}`;
                } catch {
                  return `invalid amount · nonce ${depositNonce}`;
                }
              })()}
            </span>
          </div>

          {slotIdx != null ? (
            <p className="mb-2 text-xs text-nyx-fog">
              PER slot:{" "}
              <span className="font-mono font-semibold">{slotIdx}</span>
            </p>
          ) : null}

          <button
            type="button"
            disabled={busy || step === "matched"}
            onClick={() => void nextAction()}
            className="rounded-md bg-emerald-800 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Working…" : label}
          </button>

          {error ? (
            <div className="mt-3 rounded-md border border-nyx-signal-red/35 bg-nyx-signal-red/10 px-3 py-2 text-xs text-nyx-signal-red">
              {error}
            </div>
          ) : null}

          {step === "matched" ? (
            <div className="mt-4 rounded-md border border-nyx-signal-green/35 bg-nyx-signal-green/10 px-3 py-2 text-xs text-nyx-signal-green">
              <span className="font-semibold">Settlement complete.</span> Your
              BASE fill landed as a fresh shielded note. Withdrawing that note
              on-chain needs a synchronized Merkle witness — that&rsquo;s wired
              up to an indexer in the next milestone.
            </div>
          ) : null}

          {receipt.length > 0 ? (
            <div className="mt-5">
              <h3 className="text-sm font-semibold text-nyx-chalk">
                Transaction receipt
              </h3>
              <ul className="mt-2 space-y-1 text-xs">
                {receipt.map((r, i) => (
                  <li
                    key={`${r.signature}-${i}`}
                    className="font-mono text-nyx-chalk"
                  >
                    <span className="text-nyx-slate">{r.label}</span>
                    {r.signature && r.signature !== "skipped" ? (
                      <>
                        {" "}
                        ·{" "}
                        <a
                          className="text-nyx-accent hover:underline"
                          href={txUrl(r.signature)}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {r.signature.slice(0, 10)}…
                        </a>{" "}
                        <span className="text-nyx-slate">
                          ({r.cluster === "er" ? "PER" : "L1"})
                        </span>
                      </>
                    ) : (
                      <span className="ml-2 text-nyx-slate">(no tx)</span>
                    )}
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
