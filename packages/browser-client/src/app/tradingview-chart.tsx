import { useEffect, useMemo, useRef, useState } from "react";

const SYMBOL_MAP: Readonly<Record<string, string>> = {
  "SOL-USDC": "COINBASE:SOLUSD",
};

export type ChartInterval = "1" | "15" | "60" | "240" | "D";

const QUICK_INTERVALS: ReadonlyArray<{
  value: ChartInterval;
  label: string;
}> = [
  { value: "1", label: "1m" },
  { value: "15", label: "15m" },
  { value: "60", label: "1h" },
  { value: "240", label: "4h" },
  { value: "D", label: "1D" },
];

interface ChartMessage {
  channel: "darknyx-tradingview-v1";
  status: "ready" | "failed";
  symbol: string;
  interval: ChartInterval;
}

function isChartMessage(value: unknown): value is ChartMessage {
  if (!value || typeof value !== "object") return false;
  const message = value as Partial<ChartMessage>;
  return (
    message.channel === "darknyx-tradingview-v1" &&
    (message.status === "ready" || message.status === "failed") &&
    typeof message.symbol === "string" &&
    QUICK_INTERVALS.some((entry) => entry.value === message.interval)
  );
}

export interface TradingViewChartProps {
  marketSymbol?: string;
  interval?: ChartInterval;
}

/**
 * Host-owned external market context.
 *
 * TradingView never runs in this document. For the local recording build the
 * widget bootstrap is served from the 127.0.0.1 sibling origin while the
 * custody app stays on localhost, so it cannot read the custody document.
 */
export function TradingViewChart({
  marketSymbol,
  interval: initialInterval = "D",
}: TradingViewChartProps) {
  const iframe = useRef<HTMLIFrameElement>(null);
  const [interval, setInterval] = useState<ChartInterval>(initialInterval);
  const [status, setStatus] = useState<"loading" | "ready" | "failed">(
    "loading",
  );
  const loadedOnce = useRef(false);
  const loadTimeout = useRef<number | undefined>(undefined);
  const tvSymbol = marketSymbol ? SYMBOL_MAP[marketSymbol] : undefined;
  const intervalLabel =
    QUICK_INTERVALS.find((entry) => entry.value === interval)?.label ??
    interval;
  const src = useMemo(() => {
    if (!tvSymbol) return undefined;
    const params = new URLSearchParams({ symbol: tvSymbol, interval });
    return `http://127.0.0.1:8080/tradingview.html#${params.toString()}`;
  }, [interval, tvSymbol]);

  useEffect(() => {
    if (!src || !tvSymbol) return;
    setStatus("loading");
    loadTimeout.current = window.setTimeout(() => setStatus("failed"), 12_000);
    const receive = (event: MessageEvent<unknown>) => {
      if (event.source !== iframe.current?.contentWindow) return;
      if (
        event.origin !== "http://127.0.0.1:8080" ||
        !isChartMessage(event.data)
      )
        return;
      if (event.data.symbol !== tvSymbol || event.data.interval !== interval)
        return;
      if (loadTimeout.current !== undefined)
        window.clearTimeout(loadTimeout.current);
      setStatus(event.data.status);
      if (event.data.status === "ready") loadedOnce.current = true;
    };
    window.addEventListener("message", receive);
    return () => {
      if (loadTimeout.current !== undefined)
        window.clearTimeout(loadTimeout.current);
      window.removeEventListener("message", receive);
    };
  }, [interval, src, tvSymbol]);

  return (
    <div className="chart-frame">
      <div className="chart-frame-head">
        <span className="eyebrow">
          {marketSymbol ?? "Market"} · public reference
        </span>
        {tvSymbol && (
          <div
            className="chart-intervals"
            role="group"
            aria-label="Chart interval"
            aria-busy={status === "loading"}
          >
            {QUICK_INTERVALS.map((entry) => (
              <button
                key={entry.value}
                type="button"
                className={interval === entry.value ? "active" : ""}
                aria-pressed={interval === entry.value}
                onClick={() => setInterval(entry.value)}
              >
                {entry.label}
              </button>
            ))}
          </div>
        )}
        <span className="chart-source">
          <i aria-hidden="true" />
          Live external data · TradingView
        </span>
      </div>
      <div className="chart-frame-body">
        {src ? (
          <>
            <div>
              <iframe
                key={src}
                ref={iframe}
                src={src}
                title={`${marketSymbol} public price chart`}
                sandbox="allow-scripts allow-same-origin"
                referrerPolicy="no-referrer"
                onError={() => setStatus("failed")}
              />
            </div>
            {status !== "ready" && (
              <p className="chart-fallback" role="status">
                {status === "failed"
                  ? "The external price chart is unavailable. Trading and private account controls remain independent."
                  : loadedOnce.current
                    ? `Switching to ${intervalLabel} candles…`
                    : "Loading the public SOL/USD chart…"}
              </p>
            )}
          </>
        ) : (
          <p className="chart-fallback">
            Public charting is configured for SOL-USDC only.
          </p>
        )}
      </div>
    </div>
  );
}
