"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import bs58 from "bs58";
import { Connection, Keypair, Transaction } from "@solana/web3.js";

import { useDappContext } from "@/lib/dapp/dapp-context";
import { formatAtoms, toAtoms } from "@/lib/dapp/decimals";
import { instructionFromJson, type InstructionJson } from "@/lib/dapp/ix-json";
import {
  readDappSessionForOwner,
  NYX_DAPP_SESSION_KEY,
  type DappSessionV1,
} from "@/lib/dapp/dapp-session";
import { NYX_TRADE_WITHDRAW_KEY } from "@/lib/dapp/trade-withdraw-storage";

/* -------------------------------------------------------------------------- */
/* CONSTANTS                                                                   */
/* -------------------------------------------------------------------------- */

const SEED_MESSAGE_TEXT = "NYX_DARKPOOL_SEED_V1";
const ER_RPC =
  process.env.NEXT_PUBLIC_DEMO_ER_RPC_URL ?? "https://devnet.magicblock.app";

// Module-level singleton — avoids creating a new WebSocket connection on every render
let _erConnection: Connection | null = null;
function getErConnection(): Connection {
  if (!_erConnection) _erConnection = new Connection(ER_RPC, "confirmed");
  return _erConnection;
}

const SCRAMBLE_CHARS =
  "0123456789abcdefABCDEF!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

/* -------------------------------------------------------------------------- */
/* TYPES                                                                       */
/* -------------------------------------------------------------------------- */

type ModalStep = "identity" | "trade" | "deposit";

interface LogLine {
  label: string;
  value: string;
  href?: string;
}

interface StepContent {
  title: string;
  operation: string;
  lines: LogLine[];
  done: boolean;
  error: string | null;
  busy: boolean;
}

/* -------------------------------------------------------------------------- */
/* SCRAMBLE HOOK                                                               */
/* -------------------------------------------------------------------------- */

function useScramble(text: string, active: boolean): string {
  const [display, setDisplay] = useState(text);
  useEffect(() => {
    if (!active) { setDisplay(text); return; }
    let frame = 0;
    const id = setInterval(() => {
      setDisplay(
        text
          .split("")
          .map((ch, i) =>
            i < frame / 2
              ? ch
              : SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)]
          )
          .join("")
      );
      frame++;
      if (frame > text.length * 2) clearInterval(id);
    }, 30);
    return () => clearInterval(id);
  }, [text, active]);
  return display;
}

/* -------------------------------------------------------------------------- */
/* IN-PLACE TRANSITION HOOK                                                    */
/* -------------------------------------------------------------------------- */

function useStepTransition(
  lines: LogLine[],
  active: boolean,
  onDone: () => void
): { opacity: number; scrambled: string[] } {
  const [opacity, setOpacity] = useState(1);
  const [scrambled, setScrambled] = useState<string[]>([]);

  useEffect(() => {
    if (!active) { setOpacity(1); setScrambled([]); return; }
    const totalMs = 900;
    const intervalMs = 40;
    let elapsed = 0;
    const allTexts = ["TITLE", ...lines.map((l) => `${l.label}: ${l.value}`)];
    setScrambled(allTexts);
    setOpacity(1);

    const id = setInterval(() => {
      elapsed += intervalMs;
      const progress = elapsed / totalMs;
      setOpacity(1 - progress);
      setScrambled(
        allTexts.map((full) =>
          full.split("").map(() =>
            Math.random() > progress
              ? SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)]
              : " "
          ).join("")
        )
      );
      if (elapsed >= totalMs) { clearInterval(id); onDone(); }
    }, intervalMs);

    return () => clearInterval(id);
  }, [active, lines, onDone]);

  return { opacity, scrambled };
}

/* -------------------------------------------------------------------------- */
/* TRANSITION CONTENT — renders title + lines in-place, scrambles on exit     */
/* -------------------------------------------------------------------------- */

function TransitionContent({
  lines, active, onDone, title,
}: {
  lines: LogLine[]; active: boolean; onDone: () => void; title: string;
}) {
  const { opacity, scrambled } = useStepTransition(lines, active, onDone);

  return (
    <div style={{ opacity }}>
      {/* Empty first line */}
      <div style={{ height: "28px" }} />
      {/* Title — scrambled */}
      <div style={{ height: "28px" }} className="flex items-center">
        <span className="text-[17px] font-bold uppercase tracking-[0.18em]"
          style={{ fontFamily: "'JetBrains Mono', monospace", color: "#d96820" }}>
          {scrambled[0]?.slice(0, title.length) ?? title}
        </span>
      </div>
      {/* 1-line gap */}
      <div style={{ height: "28px" }} />
      {/* Lines — scrambled */}
      {scrambled.slice(1).map((line, i) => (
        <div key={i} className="font-mono text-[11px] text-[#c8b898]" style={{ height: "28px", display: "flex", alignItems: "center" }}>
          {line}
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* LOG LINE COMPONENT                                                          */
/* -------------------------------------------------------------------------- */

function LogEntry({ line, fresh }: { line: LogLine; fresh: boolean }) {
  const _ = useScramble(`${line.label}: ${line.value}`, fresh);
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 font-mono text-[11px]" style={{ height: "28px", alignItems: "center" }}>
      <span className="text-[#6b6b74]">{line.label}:</span>
      {line.href ? (
        <a
          href={line.href}
          target="_blank"
          rel="noreferrer"
          className="text-[#d96820] underline underline-offset-2 hover:text-[#f08040]"
        >
          {line.value}
        </a>
      ) : (
        <span className="break-all text-[#c8b898]">{line.value}</span>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* NOTEBOOK MODAL                                                              */
/* -------------------------------------------------------------------------- */

export function FlowModal({
  open,
  onClose,
  initialStep,
}: {
  open: boolean;
  onClose: () => void;
  initialStep?: ModalStep;
}) {
  if (!open) return null;
  return <FlowModalInner onClose={onClose} initialStep={initialStep} />;
}

function FlowModalInner({
  onClose,
  initialStep,
}: {
  onClose: () => void;
  initialStep?: ModalStep;
}) {
  const { wallet, forwarder, connection: l1, getProver } = useDappContext();
  const er = getErConnection();

  const [currentStep, setCurrentStep] = useState<ModalStep>(initialStep ?? "identity");
  const [transitioning, setTransitioning] = useState(false);
  const [pendingStep, setPendingStep] = useState<ModalStep | null>(null);
  const [transitionLines, setTransitionLines] = useState<LogLine[]>([]);

  // Per-step state
  const [identityLines, setIdentityLines] = useState<LogLine[]>([]);
  const [identityDone, setIdentityDone] = useState(false);
  const [identityBusy, setIdentityBusy] = useState(false);
  const [identityError, setIdentityError] = useState<string | null>(null);

  const [tradeLines, setTradeLines] = useState<LogLine[]>([]);
  const [tradeDone, setTradeDone] = useState(false);
  const [tradeBusy, setTradeBusy] = useState(false);
  const [tradeError, setTradeError] = useState<string | null>(null);
  const [tradeStep, setTradeStep] = useState<
    "idle" | "registered" | "slot_ready" | "deposited" | "order_er" | "matched"
  >("idle");
  const [tradeSession, setTradeSession] = useState<DappSessionV1 | null>(null);
  const slotIdxRef = useRef<number | null>(null);
  const depositNoteRef = useRef<{ commitmentHex: string; amount: string } | null>(null);
  const orderCtxRef = useRef<{ orderIdHex: string; expirySlot: string } | null>(null);
  const depositNonceRef = useRef(
    (BigInt(Date.now()) + 333_333n).toString()
  );
  const tokenMetaRef = useRef<{
    baseDecimals: number;
    quoteDecimals: number;
    exchangeQuotePerBaseAtomic: string;
    orderPriceLimit: string;
  } | null>(null);

  const [depositLines, setDepositLines] = useState<LogLine[]>([]);
  const [depositDone, setDepositDone] = useState(false);
  const [depositBusy, setDepositBusy] = useState(false);
  const [depositError, setDepositError] = useState<string | null>(null);
  const [depositStep, setDepositStep] = useState<
    "idle" | "deposited" | "proving" | "withdrawn"
  >("idle");
  const depositTrackingRef = useRef<{
    leafIndex: string;
    priorRightPathHex: string[];
    commitmentHex: string;
    nonce: string;
    blindingR: string;
    amount: string;
    side: "base" | "quote";
    tokenMintBase58: string;
  } | null>(null);

  const connectedOwner = wallet.publicKey?.toBase58() ?? null;

  // Load token meta once
  useEffect(() => {
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
        if (
          res.ok &&
          j.ok &&
          typeof j.baseDecimals === "number" &&
          typeof j.quoteDecimals === "number" &&
          j.exchangeQuotePerBaseAtomic &&
          j.orderPriceLimit
        ) {
          tokenMetaRef.current = {
            baseDecimals: j.baseDecimals,
            quoteDecimals: j.quoteDecimals,
            exchangeQuotePerBaseAtomic: j.exchangeQuotePerBaseAtomic,
            orderPriceLimit: j.orderPriceLimit,
          };
        }
      } catch { /* ignore */ }
    })();
  }, []);

  /* ------------------------------------------------------------------------ */
  /* TRANSITION BETWEEN STEPS                                                  */
  /* ------------------------------------------------------------------------ */

  const goToStep = useCallback(
    (next: ModalStep, currentLines: LogLine[]) => {
      setTransitionLines(currentLines);
      setTransitioning(true);
      setPendingStep(next);
    },
    []
  );

  const handleTransitionDone = useCallback(() => {
    setTransitioning(false);
    if (pendingStep) {
      setCurrentStep(pendingStep);
      setPendingStep(null);
    }
  }, [pendingStep]);

  /* ------------------------------------------------------------------------ */
  /* STEP 1: IDENTITY                                                          */
  /* ------------------------------------------------------------------------ */

  const runIdentity = useCallback(async () => {
    if (!wallet.publicKey || !wallet.signMessage) {
      setIdentityError("Wallet does not support signMessage. Try Phantom on devnet.");
      return;
    }
    setIdentityBusy(true);
    setIdentityError(null);
    setIdentityLines([]);

    try {
      setIdentityLines([{ label: "status", value: "Awaiting Phantom signature…" }]);
      const msg = new TextEncoder().encode(SEED_MESSAGE_TEXT);
      const sig = await wallet.signMessage(msg);
      const signatureBase58 = bs58.encode(sig);

      setIdentityLines([{ label: "status", value: "Deriving keys on server…" }]);
      const res = await fetch("/api/dapp/derive-identity", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          phantomSignatureBase58: signatureBase58,
          ownerPubkeyBase58: wallet.publicKey.toBase58(),
        }),
      });
      if (!res.ok) throw new Error(`derive-identity HTTP ${res.status}`);
      const derived = (await res.json()) as {
        ok: boolean;
        walletCreateInputs: {
          userCommitment: string;
          rootKey: [string, string];
          spendingKey: string;
          viewingKey: string;
          r0: string; r1: string; r2: string;
        };
        trading: { publicKeyBase58: string; secretKeyBase58: string };
        publicData: {
          userCommitmentHex: string;
          ownerCommitmentHex: string;
          rootKeyPubkeyBase58: string;
        };
        previews: {
          masterSeedFingerprint: string;
          spendingKeyFingerprint: string;
          viewingKeyFingerprint: string;
        };
      };
      if (!derived.ok) throw new Error("derive-identity returned ok: false");

      setIdentityLines([{ label: "status", value: "Generating VALID_WALLET_CREATE proof…" }]);
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
      const proofMs = Math.round(performance.now() - t0);

      try {
        sessionStorage.setItem(
          NYX_DAPP_SESSION_KEY,
          JSON.stringify({
            phantomSignatureBase58: signatureBase58,
            ownerPubkeyBase58: wallet.publicKey.toBase58(),
            tradingSecretKeyBase58: derived.trading.secretKeyBase58,
            publicData: derived.publicData,
            proof: {
              piAHex: Array.from(proof.piA, (x) => x.toString(16).padStart(2, "0")).join(""),
              piBHex: Array.from(proof.piB, (x) => x.toString(16).padStart(2, "0")).join(""),
              piCHex: Array.from(proof.piC, (x) => x.toString(16).padStart(2, "0")).join(""),
            },
          })
        );
      } catch { /* private mode */ }

      setIdentityLines([{ label: "status", value: "Airdropping demo tokens…" }]);
      let airdropLine: LogLine;
      try {
        const ar = await fetch("/api/dapp/airdrop", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: signatureBase58,
            ownerPubkeyBase58: wallet.publicKey.toBase58(),
          }),
        });
        const aj = (await ar.json()) as {
          ok?: boolean; signature?: string; baseAmount?: string; quoteAmount?: string;
        };
        if (aj.ok && aj.signature) {
          airdropLine = {
            label: "airdrop",
            value: `${aj.signature.slice(0, 10)}…`,
            href: `https://explorer.solana.com/tx/${aj.signature}?cluster=devnet`,
          };
        } else {
          airdropLine = { label: "airdrop", value: "failed (continue anyway)" };
        }
      } catch {
        airdropLine = { label: "airdrop", value: "failed (continue anyway)" };
      }

      const finalLines: LogLine[] = [
        { label: "owner", value: wallet.publicKey.toBase58().slice(0, 16) + "…" },
        { label: "spending key", value: `0x${derived.previews.spendingKeyFingerprint}…` },
        { label: "viewing key", value: `0x${derived.previews.viewingKeyFingerprint}…` },
        { label: "trading pubkey", value: derived.trading.publicKeyBase58.slice(0, 14) + "…" },
        { label: "user commitment", value: `0x${derived.publicData.userCommitmentHex.slice(0, 16)}…` },
        { label: "proof", value: `Groth16 · ${proofMs}ms · pi_a ${proof.piA.length}B` },
        airdropLine,
      ];
      setIdentityLines(finalLines);
      setIdentityDone(true);
      setIdentityBusy(false);
    } catch (e) {
      setIdentityError(e instanceof Error ? e.message : String(e));
      setIdentityBusy(false);
    }
  }, [wallet, getProver]);

  /* ------------------------------------------------------------------------ */
  /* STEP 2: TRADE                                                             */
  /* ------------------------------------------------------------------------ */

  const runNextTradeStep = useCallback(async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) {
      setTradeError("Complete the identity step first.");
      return;
    }
    setTradeSession(s);
    setTradeBusy(true);
    setTradeError(null);
    const meta = tokenMetaRef.current;
    const baseDecimals = meta?.baseDecimals ?? 6;
    const quoteDecimals = meta?.quoteDecimals ?? 6;
    const quotePerBaseAtomic = BigInt(meta?.exchangeQuotePerBaseAtomic ?? "100");
    const orderPriceLimitStr = meta?.orderPriceLimit ?? "100";
    const baseAmount = process.env.NEXT_PUBLIC_DEMO_BASE_HUMAN ?? "1";

    const appendTrade = (lines: LogLine[]) =>
      setTradeLines((prev) => [...prev, ...lines]);

    try {
      if (tradeStep === "idle") {
        setTradeLines([{ label: "status", value: "Registering wallet on-chain…" }]);
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
          ok?: boolean; error?: string; alreadyRegistered?: boolean;
          walletPdaBase58?: string; instruction?: InstructionJson;
        };
        if (!res.ok || !json.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
        if (json.alreadyRegistered) {
          appendTrade([{ label: "create_wallet", value: "already registered (skipped)" }]);
        } else if (json.instruction) {
          const sig = await forwarder.sendAndConfirm([instructionFromJson(json.instruction)]);
          appendTrade([{
            label: "create_wallet (L1)",
            value: `${sig.slice(0, 10)}…`,
            href: `https://explorer.solana.com/tx/${sig}?cluster=devnet`,
          }]);
        }
        setTradeStep("registered");

      } else if (tradeStep === "registered") {
        setTradeLines((p) => [...p, { label: "status", value: "Initialising PER slot…" }]);
        const res = await fetch("/api/dapp/init-slot", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: s.phantomSignatureBase58,
            ownerPubkeyBase58: s.ownerPubkeyBase58,
            tradingSecretKeyBase58: s.tradingSecretKeyBase58,
          }),
        });
        const json = (await res.json()) as { ok?: boolean; slotIdx?: number; error?: string };
        if (!res.ok || !json.ok || json.slotIdx === undefined)
          throw new Error(json.error ?? `HTTP ${res.status}`);
        slotIdxRef.current = json.slotIdx;
        appendTrade([{ label: "PER slot", value: String(json.slotIdx) }]);
        setTradeStep("slot_ready");

      } else if (tradeStep === "slot_ready") {
        setTradeLines((p) => [...p, { label: "status", value: "Depositing quote collateral…" }]);
        const baseAtoms = toAtoms(baseAmount, baseDecimals);
        const quoteAtoms = baseAtoms * quotePerBaseAtomic;
        const res = await fetch("/api/dapp/deposit-prepare", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: s.phantomSignatureBase58,
            ownerPubkeyBase58: s.ownerPubkeyBase58,
            side: "quote",
            amount: quoteAtoms.toString(),
            nonce: depositNonceRef.current,
          }),
        });
        const json = (await res.json()) as {
          ok?: boolean; error?: string;
          instruction?: InstructionJson;
          preview?: { noteCommitmentHex: string };
        };
        if (!res.ok || !json.ok || !json.instruction)
          throw new Error(json.error ?? `HTTP ${res.status}`);
        const sig = await forwarder.sendAndConfirm([instructionFromJson(json.instruction)]);
        depositNoteRef.current = {
          commitmentHex: json.preview?.noteCommitmentHex ?? "",
          amount: quoteAtoms.toString(),
        };
        appendTrade([{
          label: "deposit quote (L1)",
          value: `${sig.slice(0, 10)}… · ${formatAtoms(quoteAtoms, quoteDecimals)} QUOTE`,
          href: `https://explorer.solana.com/tx/${sig}?cluster=devnet`,
        }]);
        setTradeStep("deposited");

      } else if (tradeStep === "deposited") {
        const dn = depositNoteRef.current;
        if (!dn || slotIdxRef.current == null) throw new Error("Missing deposit / slot");
        setTradeLines((p) => [...p, { label: "status", value: "Submitting bid on PER…" }]);
        const baseAtoms = toAtoms(baseAmount, baseDecimals);
        const priceLim = BigInt(orderPriceLimitStr);
        const trading = Keypair.fromSecretKey(bs58.decode(s.tradingSecretKeyBase58));
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
            slotIdx: slotIdxRef.current,
            side: 0, amount: baseAtoms.toString(),
            priceLimit: orderPriceLimitStr,
            noteAmount: dn.amount, expirySlot: expiry.toString(),
            noteCommitmentHex: dn.commitmentHex,
            userOwnerCommitmentHex: s.publicData.ownerCommitmentHex,
            orderIdHex,
          }),
        });
        const json = (await res.json()) as { ok?: boolean; error?: string; instruction?: InstructionJson };
        if (!res.ok || !json.ok || !json.instruction) throw new Error(json.error ?? `HTTP ${res.status}`);
        const tx = new Transaction().add(instructionFromJson(json.instruction));
        const { blockhash, lastValidBlockHeight } = await er.getLatestBlockhash("confirmed");
        tx.recentBlockhash = blockhash;
        tx.feePayer = trading.publicKey;
        tx.sign(trading);
        const sig = await er.sendRawTransaction(tx.serialize(), { skipPreflight: false, preflightCommitment: "confirmed" });
        await er.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");
        appendTrade([{
          label: "submit_order (PER)",
          value: `${sig.slice(0, 10)}…`,
          href: `https://explorer.solana.com/tx/${sig}?cluster=er`,
        }]);
        setTradeStep("order_er");

      } else if (tradeStep === "order_er") {
        const ctx = orderCtxRef.current;
        if (!ctx || slotIdxRef.current == null) throw new Error("Missing order context");
        setTradeLines((p) => [...p, { label: "status", value: "Matching & settling on L1…" }]);
        const baseAtoms = toAtoms(baseAmount, baseDecimals);
        const dn = depositNoteRef.current;
        const res = await fetch("/api/dapp/counter-and-match", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: s.phantomSignatureBase58,
            ownerPubkeyBase58: s.ownerPubkeyBase58,
            tradingSecretKeyBase58: s.tradingSecretKeyBase58,
            userSlotIdx: slotIdxRef.current,
            userSide: 0,
            userAmount: baseAtoms.toString(),
            userPriceLimit: orderPriceLimitStr,
            userNoteAmount: dn?.amount ?? "0",
            userNoteCommitmentHex: dn?.commitmentHex ?? "",
            userOwnerCommitmentHex: s.publicData.ownerCommitmentHex,
            userOrderIdHex: ctx.orderIdHex,
            userExpirySlot: ctx.expirySlot,
          }),
        });
        const json = (await res.json()) as {
          ok?: boolean; error?: string;
          signatures?: { label: string; signature: string; cluster: string }[];
          tradeWithdrawBuyerBase?: Record<string, string>;
        };
        if (!res.ok || !json.ok || !json.signatures) throw new Error(json.error ?? `HTTP ${res.status}`);
        for (const r of json.signatures) {
          appendTrade([{
            label: r.label,
            value: r.signature !== "skipped" ? `${r.signature.slice(0, 10)}…` : "skipped",
            href: r.signature !== "skipped"
              ? `https://explorer.solana.com/tx/${r.signature}?cluster=devnet`
              : undefined,
          }]);
        }
        if (json.tradeWithdrawBuyerBase) {
          try {
            sessionStorage.setItem(
              NYX_TRADE_WITHDRAW_KEY,
              JSON.stringify({
                tradeWithdrawBuyerBase: json.tradeWithdrawBuyerBase,
                ownerCommitmentHex: s.publicData.ownerCommitmentHex,
              })
            );
          } catch { /* private mode */ }
        }
        setTradeStep("matched");
        setTradeDone(true);
      }
      setTradeBusy(false);
    } catch (e) {
      setTradeError(e instanceof Error ? e.message : String(e));
      setTradeBusy(false);
    }
  }, [connectedOwner, tradeStep, forwarder, l1]);

  /* ------------------------------------------------------------------------ */
  /* STEP 3: PRIVATE DEPOSIT/WITHDRAW                                         */
  /* ------------------------------------------------------------------------ */

  const runNextDepositStep = useCallback(async () => {
    const s = readDappSessionForOwner(connectedOwner);
    if (!s) { setDepositError("Complete the identity step first."); return; }
    setDepositBusy(true);
    setDepositError(null);

    const appendDeposit = (lines: LogLine[]) =>
      setDepositLines((prev) => [...prev, ...lines]);

    try {
      if (depositStep === "idle") {
        setDepositLines([{ label: "status", value: "Preparing private deposit…" }]);
        const dec = 6;
        const wantAtoms = toAtoms(
          process.env.NEXT_PUBLIC_DEMO_PRIVATE_AMOUNT ?? "10",
          dec
        );
        const res = await fetch("/api/dapp/private-deposit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: s.phantomSignatureBase58,
            ownerPubkeyBase58: s.ownerPubkeyBase58,
            side: "quote",
            amount: wantAtoms.toString(),
            nonce: (BigInt(Date.now()) + 7_777n).toString(),
          }),
        });
        const json = (await res.json()) as {
          ok?: boolean; error?: string;
          instructions?: InstructionJson[];
          tracking?: {
            leafIndex: string; priorRightPathHex: string[];
            commitmentHex: string; nonce: string; blindingR: string;
            amount: string; side: "base" | "quote"; tokenMintBase58: string;
          };
        };
        if (!res.ok || !json.ok || !json.instructions?.length || !json.tracking)
          throw new Error(json.error ?? `HTTP ${res.status}`);
        const sig = await forwarder.sendAndConfirm(
          json.instructions.map(instructionFromJson)
        );
        depositTrackingRef.current = json.tracking;
        appendDeposit([
          { label: "private deposit (quote)", value: `${sig.slice(0, 10)}…`, href: `https://explorer.solana.com/tx/${sig}?cluster=devnet` },
          { label: "leaf index", value: json.tracking.leafIndex },
          { label: "commitment", value: `0x${json.tracking.commitmentHex.slice(0, 16)}…` },
        ]);
        setDepositStep("deposited");

      } else if (depositStep === "deposited") {
        const tracking = depositTrackingRef.current;
        if (!tracking) throw new Error("Run deposit step first.");
        setDepositLines((p) => [...p, { label: "status", value: "Preparing VALID_SPEND witness…" }]);

        const prep = await fetch("/api/dapp/withdraw-prepare", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            phantomSignatureBase58: s.phantomSignatureBase58,
            ownerPubkeyBase58: s.ownerPubkeyBase58,
            tokenMintBase58: tracking.tokenMintBase58,
            amount: tracking.amount, nonce: tracking.nonce,
            blindingR: tracking.blindingR, leafIndex: tracking.leafIndex,
            priorRightPathHex: tracking.priorRightPathHex,
          }),
        });
        const prepJson = (await prep.json()) as {
          ok?: boolean; error?: string;
          proverInputs?: {
            merkleRoot: string; nullifier: string; tokenMint: [string, string];
            amount: string; spendingKey: string; ownerCommitmentBlinding: string;
            nonce: string; blindingR: string; merklePath: string[]; merkleIndices: string[];
          };
          ixContext?: { commitmentHex: string; nullifierHex: string; merkleRootHex: string };
        };
        if (!prep.ok || !prepJson.ok || !prepJson.proverInputs || !prepJson.ixContext)
          throw new Error(prepJson.error ?? `HTTP ${prep.status}`);

        setDepositLines((p) => [...p, { label: "status", value: "Generating VALID_SPEND proof in browser…" }]);
        setDepositStep("proving");
        const t0 = performance.now();
        const proof = await getProver().spend.prove({
          merkleRoot: BigInt(prepJson.proverInputs.merkleRoot),
          nullifier: BigInt(prepJson.proverInputs.nullifier),
          tokenMint: [BigInt(prepJson.proverInputs.tokenMint[0]), BigInt(prepJson.proverInputs.tokenMint[1])],
          amount: BigInt(prepJson.proverInputs.amount),
          spendingKey: BigInt(prepJson.proverInputs.spendingKey),
          ownerCommitmentBlinding: BigInt(prepJson.proverInputs.ownerCommitmentBlinding),
          nonce: BigInt(prepJson.proverInputs.nonce),
          blindingR: BigInt(prepJson.proverInputs.blindingR),
          merklePath: prepJson.proverInputs.merklePath.map((p) => BigInt(p)),
          merkleIndices: prepJson.proverInputs.merkleIndices.map((i) => Number(i)),
        });
        const proofMs = Math.round(performance.now() - t0);

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
              piA: Buffer.from(proof.piA).toString("hex"),
              piB: Buffer.from(proof.piB).toString("hex"),
              piC: Buffer.from(proof.piC).toString("hex"),
            },
          }),
        });
        const finJson = (await fin.json()) as {
          ok?: boolean; error?: string; instruction?: InstructionJson;
        };
        if (!fin.ok || !finJson.ok || !finJson.instruction)
          throw new Error(finJson.error ?? `HTTP ${fin.status}`);
        const sig = await forwarder.sendAndConfirm([instructionFromJson(finJson.instruction)]);
        appendDeposit([
          { label: "VALID_SPEND proof", value: `${proofMs}ms` },
          { label: "withdraw (L1)", value: `${sig.slice(0, 10)}…`, href: `https://explorer.solana.com/tx/${sig}?cluster=devnet` },
          { label: "nullifier recorded", value: `0x${prepJson.ixContext.nullifierHex.slice(0, 16)}…` },
        ]);
        setDepositStep("withdrawn");
        setDepositDone(true);
      }
      setDepositBusy(false);
    } catch (e) {
      setDepositError(e instanceof Error ? e.message : String(e));
      setDepositBusy(false);
    }
  }, [connectedOwner, depositStep, forwarder, getProver]);

  /* ------------------------------------------------------------------------ */
  /* DERIVED CONTENT FOR CURRENT STEP                                          */
  /* ------------------------------------------------------------------------ */

  const stepContent: StepContent = useMemo(() => {
    if (currentStep === "identity") {
      const busy = identityBusy;
      const phase = identityBusy
        ? identityLines[identityLines.length - 1]?.value ?? "Working…"
        : null;
      return {
        title: "Derive your darkpool identity",
        operation: "derive_identity",
        lines: identityLines,
        done: identityDone,
        error: identityError,
        busy,
        _phase: phase,
      } as StepContent & { _phase: string | null };
    }
    if (currentStep === "trade") {
      const tradeLabel =
        tradeStep === "idle" ? "Register wallet"
          : tradeStep === "registered" ? "Init PER slot"
            : tradeStep === "slot_ready" ? "Deposit collateral"
              : tradeStep === "deposited" ? "Submit bid on PER"
                : tradeStep === "order_er" ? "Match & settle"
                  : "Done";
      return {
        title: "Trade on devnet",
        operation: tradeLabel,
        lines: tradeLines,
        done: tradeDone,
        error: tradeError,
        busy: tradeBusy,
      };
    }
    return {
      title: "Private deposit / withdraw",
      operation: depositStep === "idle" ? "private_deposit"
        : depositStep === "deposited" ? "VALID_SPEND withdraw"
          : depositStep === "proving" ? "proving in browser…"
            : "Done",
      lines: depositLines,
      done: depositDone,
      error: depositError,
      busy: depositBusy,
    };
  }, [
    currentStep,
    identityBusy, identityLines, identityDone, identityError,
    tradeStep, tradeLines, tradeDone, tradeError, tradeBusy,
    depositStep, depositLines, depositDone, depositError, depositBusy,
  ]);

  /* ------------------------------------------------------------------------ */
  /* NEXT BUTTON                                                               */
  /* ------------------------------------------------------------------------ */

  const handlePrimary = () => {
    if (currentStep === "identity") {
      if (!identityDone) { void runIdentity(); }
      else { goToStep("trade", identityLines); }
    } else if (currentStep === "trade") {
      if (!tradeDone) { void runNextTradeStep(); }
      else { goToStep("deposit", tradeLines); }
    } else {
      void runNextDepositStep();
    }
  };

  const primaryLabel = () => {
    if (currentStep === "identity") {
      if (identityBusy) return "Working…";
      if (identityDone) return "Next → Trade on devnet";
      return "Sign & derive identity";
    }
    if (currentStep === "trade") {
      if (tradeBusy) return "Working…";
      if (tradeDone) return "Next → Private deposit / withdraw";
      return tradeStep === "idle" ? "Register wallet on-chain"
        : tradeStep === "registered" ? "Init PER slot"
          : tradeStep === "slot_ready" ? "Deposit collateral"
            : tradeStep === "deposited" ? "Submit bid on PER"
              : "Match & settle";
    }
    if (depositBusy) return "Working…";
    if (depositDone) return "Trade again";
    return depositStep === "idle" ? "Private deposit"
      : depositStep === "deposited" ? "Withdraw via VALID_SPEND"
        : "Proving…";
  };

  const handleTradeAgain = () => {
    setTradeStep("idle");
    setTradeLines([]);
    setTradeDone(false);
    setTradeError(null);
    slotIdxRef.current = null;
    depositNoteRef.current = null;
    orderCtxRef.current = null;
    goToStep("trade", depositLines);
  };

  /* ------------------------------------------------------------------------ */
  /* RENDER                                                                    */
  /* ------------------------------------------------------------------------ */

  const isConnected = !!wallet.publicKey;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(5,6,8,0.85)", backdropFilter: "blur(6px)" }}
    >
      {/* Notebook */}
      <div
        className="relative flex w-full max-w-2xl flex-col overflow-hidden"
        style={{
          background: "#0d0f12",
          border: "1px solid rgba(217,104,32,0.18)",
          borderRadius: "4px",
          boxShadow: "0 0 0 1px rgba(0,0,0,0.8), 0 32px 80px rgba(0,0,0,0.7)",
          minHeight: "480px",
          maxHeight: "80vh",
        }}
      >
        {/* Notebook ruled lines background */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage:
              "repeating-linear-gradient(transparent, transparent 27px, rgba(217,104,32,0.06) 27px, rgba(217,104,32,0.06) 28px)",
            backgroundPosition: "0 48px",
          }}
        />

        {/* Left margin rule */}
        <div
          className="pointer-events-none absolute bottom-0 left-12 top-0"
          style={{ borderLeft: "1px solid rgba(217,104,32,0.12)" }}
        />

        {/* Header bar */}
        <div
          className="relative flex items-center justify-between border-b px-4 py-3"
          style={{ borderColor: "rgba(217,104,32,0.15)" }}
        >
          {/* Step tabs */}
          <div className="flex items-center gap-1">
            {(["identity", "trade", "deposit"] as ModalStep[]).map((s, i) => (
              <button
                key={s}
                onClick={() => {
                  if (s === "identity" || (s === "trade" && identityDone) || (s === "deposit" && tradeDone)) {
                    if (s !== currentStep) goToStep(s, stepContent.lines);
                  }
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] uppercase tracking-[0.14em] transition-colors"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  color:
                    currentStep === s
                      ? "#d96820"
                      : (s === "trade" && !identityDone) || (s === "deposit" && !tradeDone)
                        ? "rgba(107,107,116,0.4)"
                        : "rgba(107,107,116,0.8)",
                  borderBottom: currentStep === s ? "1px solid #d96820" : "1px solid transparent",
                }}
              >
                <span style={{ color: currentStep === s ? "#d96820" : "rgba(107,107,116,0.5)" }}>
                  {i + 1}.
                </span>
                {s === "identity" ? "Identity" : s === "trade" ? "Trade" : "Deposit"}
              </button>
            ))}
          </div>

          {/* Operation label top-right */}
          <div className="flex items-center gap-3">
            <span
              className="text-[10px] uppercase tracking-[0.18em]"
              style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(217,104,32,0.6)" }}
            >
              {stepContent.operation}
            </span>
            <button
              onClick={onClose}
              className="flex h-5 w-5 items-center justify-center text-[#6b6b74] transition-colors hover:text-[#c8b898]"
              style={{ fontSize: "16px", lineHeight: 1 }}
            >
              ×
            </button>
          </div>
        </div>

        {/* Content area */}
        <div className="relative flex-1 overflow-y-auto pl-16 pr-12" style={{ lineHeight: "28px" }}>
          {transitioning ? (
            <TransitionContent
              lines={transitionLines}
              active={transitioning}
              onDone={handleTransitionDone}
              title={stepContent.title}
            />
          ) : (
          <>
          {/* Empty first line */}
          <div style={{ height: "28px" }} />
          {/* Title */}
          <div style={{ height: "28px" }} className="flex items-center">
            <span className="text-[17px] font-bold uppercase tracking-[0.18em]"
              style={{ fontFamily: "'JetBrains Mono', monospace", color: "#d96820" }}>
              {stepContent.title}
            </span>
          </div>
          {/* 1-line gap */}
          <div style={{ height: "28px" }} />

          {!isConnected ? (
            <p
              className="text-[12px]"
              style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(107,107,116,0.7)", lineHeight: "28px" }}
            >
              Connect your Phantom wallet on Solana devnet to begin.
            </p>
          ) : stepContent.lines.length === 0 && !stepContent.busy ? (
            <p
              className="text-[12px]"
              style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(107,107,116,0.5)", lineHeight: "28px" }}
            >
              {currentStep === "identity"
                ? "Sign a message with Phantom to derive your darkpool keys."
                : currentStep === "trade"
                  ? "Register your wallet on-chain and begin the trade flow."
                  : "Make a private deposit and withdraw via VALID_SPEND."}
            </p>
          ) : (
            <div>
              {stepContent.lines.map((line, i) => (
                <LogEntry key={i} line={line} fresh={i === stepContent.lines.length - 1 && !stepContent.done} />
              ))}
            </div>
          )}

          {stepContent.error && (
            <div
              className="mt-4 rounded px-3 py-2 text-[11px]"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                background: "rgba(200,50,50,0.1)",
                border: "1px solid rgba(200,50,50,0.25)",
                color: "#e05050",
              }}
            >
              error: {stepContent.error}
            </div>
          )}

          {stepContent.done && currentStep === "deposit" && (
            <div
              className="mt-4 rounded px-3 py-2 text-[11px]"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                background: "rgba(50,200,100,0.08)",
                border: "1px solid rgba(50,200,100,0.2)",
                color: "rgba(80,200,120,0.9)",
              }}
            >
              ✓ Full flow complete. Nullifier recorded on-chain — this note can never be re-spent or traced.
            </div>
          )}
          </>
          )}
        </div>

        {/* Footer — action button */}
        <div
          className="relative flex items-center justify-between border-t px-12 py-4"
          style={{ borderColor: "rgba(217,104,32,0.12)" }}
        >
          <span
            className="text-[10px] uppercase tracking-[0.16em]"
            style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(107,107,116,0.35)" }}
          >
            {currentStep === "identity" ? "step 1 / 3"
              : currentStep === "trade" ? "step 2 / 3"
                : "step 3 / 3"}
          </span>

          {depositDone ? (
            <button
              onClick={handleTradeAgain}
              className="rounded px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.12em] transition-colors"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                background: "rgba(217,104,32,0.12)",
                border: "1px solid rgba(217,104,32,0.3)",
                color: "#d96820",
              }}
            >
              Trade again →
            </button>
          ) : (
            <button
              onClick={handlePrimary}
              disabled={stepContent.busy || !isConnected || transitioning || (currentStep === "deposit" && depositStep === "proving")}
              className="rounded px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.12em] transition-all"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                background: stepContent.busy ? "rgba(217,104,32,0.08)" : "rgba(217,104,32,0.15)",
                border: "1px solid rgba(217,104,32,0.35)",
                color: stepContent.busy ? "rgba(217,104,32,0.5)" : "#d96820",
                cursor: stepContent.busy ? "not-allowed" : "pointer",
              }}
            >
              {primaryLabel()}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
