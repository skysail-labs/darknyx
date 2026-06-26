import type { CSSProperties } from "react";

interface NyxMarkProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
  /** Render the half-moon as if rising — clip starts below the horizon and slides up. */
  rising?: boolean;
}

/**
 * The DarkNyx "Horizon" mark — half-moon settling onto two horizon lines.
 * Inherits `currentColor` so callers can `text-nyx-chalk` / `text-nyx-ink`.
 *
 * Source: apps/demo/design-system/svg/nyx-mark.svg
 */
export function NyxMark({
  size = 32,
  className,
  style,
  rising = false,
}: NyxMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 120 120"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={style}
      aria-hidden="true"
    >
      <defs>
        <clipPath id={`nyx-mark-hor-${rising ? "r" : "s"}`}>
          <rect x="0" y="0" width="120" height="66" />
        </clipPath>
      </defs>
      <circle
        cx="60"
        cy="60"
        r="36"
        fill="currentColor"
        clipPath={`url(#nyx-mark-hor-${rising ? "r" : "s"})`}
      />
      <rect x="18" y="66" width="84" height="4" fill="currentColor" />
      <rect
        x="18"
        y="78"
        width="60"
        height="4"
        fill="currentColor"
        opacity="0.5"
      />
    </svg>
  );
}

/**
 * Lockup: mark + "darknyx" wordmark, single horizontal unit. Use in headers.
 */
export function NyxLockup({
  size = 24,
  tone = "chalk",
}: {
  size?: number;
  tone?: "chalk" | "ink";
}) {
  const color = tone === "chalk" ? "var(--nyx-chalk)" : "var(--nyx-ink)";
  return (
    <div className="flex items-center gap-2 select-none" style={{ color }}>
      <NyxMark size={size} />
      <span
        className="nyx-display"
        style={{
          fontSize: `${Math.round(size * 0.75)}px`,
          letterSpacing: "-0.03em",
          fontWeight: 600,
        }}
      >
        dark
        <span style={{ opacity: 0.55, fontWeight: 400 }}>nyx</span>
      </span>
    </div>
  );
}
