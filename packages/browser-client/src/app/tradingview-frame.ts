const EMBED_SRC =
  "https://s3.tradingview.com/external-embedding/embed-widget-advanced-chart.js";
const ALLOWED_SYMBOLS = new Set(["COINBASE:SOLUSD"]);
const ALLOWED_INTERVALS = new Set(["1", "15", "60", "240", "D"]);

function configuration(): { symbol: string; interval: string } | null {
  const params = new URLSearchParams(location.hash.slice(1));
  const symbol = params.get("symbol") ?? "";
  const interval = params.get("interval") ?? "";
  return ALLOWED_SYMBOLS.has(symbol) && ALLOWED_INTERVALS.has(interval)
    ? { symbol, interval }
    : null;
}

function report(
  status: "ready" | "failed",
  config: { symbol: string; interval: string },
): void {
  parent.postMessage(
    {
      channel: "darknyx-tradingview-v1",
      status,
      symbol: config.symbol,
      interval: config.interval,
    },
    "*",
  );
}

const config = configuration();
const host = document.getElementById("tradingview-frame");
Object.assign(document.documentElement.style, {
  width: "100%",
  height: "100%",
  background: "#100e0c",
  colorScheme: "dark",
});
Object.assign(document.body.style, {
  width: "100%",
  height: "100%",
  margin: "0",
  overflow: "hidden",
  background: "#100e0c",
});
if (!config || !host) {
  document.body.textContent = "Unsupported chart configuration";
} else {
  Object.assign(host.style, { width: "100%", height: "100%" });
  const script = document.createElement("script");
  script.src = EMBED_SRC;
  script.async = true;
  script.type = "text/javascript";
  script.referrerPolicy = "no-referrer";
  script.text = JSON.stringify({
    autosize: true,
    symbol: config.symbol,
    interval: config.interval,
    timezone: "Etc/UTC",
    theme: "dark",
    style: "1",
    locale: "en",
    backgroundColor: "#100e0c",
    gridColor: "rgba(244, 241, 235, 0.06)",
    withdateranges: true,
    hide_top_toolbar: true,
    hide_legend: false,
    hide_side_toolbar: true,
    allow_symbol_change: false,
    save_image: false,
    details: false,
    hotlist: false,
    calendar: false,
    support_host: "https://www.tradingview.com",
  });
  script.addEventListener("error", () => report("failed", config));
  host.append(script);

  let waited = 0;
  const poll = window.setInterval(() => {
    waited += 250;
    if (host.querySelector("iframe")) {
      window.clearInterval(poll);
      report("ready", config);
    } else if (waited >= 10_000) {
      window.clearInterval(poll);
      report("failed", config);
    }
  }, 250);
}
