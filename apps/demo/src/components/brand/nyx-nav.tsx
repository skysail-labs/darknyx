import Link from "next/link";

import { NyxLockup } from "./nyx-mark";

interface NyxNavProps {
  /** "ink" = dark page, "chalk" = light page */
  tone?: "ink" | "chalk";
  /**
   * Where the "Launch dapp" button points. Defaults to /dapp.
   * Set to null to suppress the button (e.g. ON the dapp page itself).
   */
  launchHref?: string | null;
  /** Active page hint — applied to nav links for subtle emphasis. */
  active?: "home" | "architecture" | "dapp" | null;
}

const LINKS: Array<{ label: string; href: string; key: NonNullable<NyxNavProps["active"]> }> = [
  { label: "Overview", href: "/landing", key: "home" },
  { label: "Architecture", href: "/architecture", key: "architecture" },
];

export function NyxNav({ tone = "ink", launchHref = "/dapp", active = null }: NyxNavProps) {
  const isInk = tone === "ink";

  return (
    <header
      className="sticky top-0 z-30 w-full border-b"
      style={{
        background: isInk ? "#050608" : "var(--nyx-chalk)",
        borderColor: isInk ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)",
      }}
    >
      <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-3 sm:px-7">
        <Link href="/" className="flex items-center gap-2">
          <NyxLockup size={22} tone={tone === "ink" ? "chalk" : "ink"} />
        </Link>

        <nav className="hidden items-center gap-6 md:flex">
          {LINKS.map((l) => (
            <Link
              key={l.key}
              href={l.href}
              className="transition-colors"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "11px",
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: active === l.key
                  ? (isInk ? "#d96820" : "var(--nyx-ink)")
                  : (isInk ? "rgba(174,172,176,0.7)" : "var(--nyx-slate)"),
              }}
            >
              {l.label}
            </Link>
          ))}
        </nav>

        {launchHref ? (
          <Link
            href="/landing"
            className="group inline-flex items-center gap-2 transition-opacity hover:opacity-80"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "11px",
              fontWeight: 600,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              padding: "6px 14px",
              borderRadius: "2px",
              background: "rgba(217,104,32,0.15)",
              border: "1px solid rgba(217,104,32,0.35)",
              color: "#d96820",
            }}
          >
            <span>Coming Soon on Mainnet</span>
            {/* <svg
              width="10"
              height="10"
              viewBox="0 0 11 11"
              fill="none"
              className="transition-transform group-hover:translate-x-0.5"
              aria-hidden="true"
            >
              <path
                d="M2 5.5h7m0 0L5.5 2m3.5 3.5L5.5 9"
                stroke="currentColor"
                strokeWidth="1.4"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg> */}
          </Link>
        ) : (
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.5)" }}>
            devnet
          </span>
        )}
      </div>
    </header>
  );
}
