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

const LINKS: Array<{
  label: string;
  href: string;
  key: NonNullable<NyxNavProps["active"]>;
}> = [
  { label: "Overview", href: "/", key: "home" },
  { label: "Architecture", href: "/architecture", key: "architecture" },
];

export function NyxNav({
  tone = "ink",
  launchHref = "/dapp",
  active = null,
}: NyxNavProps) {
  const isInk = tone === "ink";

  const linkBase = isInk
    ? "text-[13px] text-nyx-fog hover:text-nyx-chalk transition-colors"
    : "text-[13px] text-nyx-slate hover:text-nyx-ink transition-colors";
  const linkActive = isInk ? "text-nyx-chalk" : "text-nyx-ink";

  const ctaBase = isInk
    ? "group inline-flex items-center gap-2 rounded-sm border border-nyx-chalk/20 bg-nyx-chalk text-nyx-ink"
    : "group inline-flex items-center gap-2 rounded-sm border border-nyx-ink/15 bg-nyx-ink text-nyx-chalk";

  return (
    <header
      className={
        isInk
          ? "sticky top-0 z-30 w-full border-b border-white/[0.06] bg-nyx-ink/80 backdrop-blur"
          : "sticky top-0 z-30 w-full border-b border-black/[0.06] bg-nyx-chalk/85 backdrop-blur"
      }
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
              className={`${linkBase} ${active === l.key ? linkActive : ""}`}
            >
              {l.label}
            </Link>
          ))}
        </nav>

        {launchHref ? (
          <Link
            href={launchHref}
            className={`${ctaBase} px-3.5 py-2 text-[12px] font-semibold uppercase tracking-[0.12em] transition hover:opacity-90`}
          >
            <span>Launch dapp</span>
            <svg
              width="11"
              height="11"
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
            </svg>
          </Link>
        ) : (
          <span className="text-[11px] font-mono uppercase tracking-[0.18em] text-nyx-fog">
            devnet
          </span>
        )}
      </div>
    </header>
  );
}
