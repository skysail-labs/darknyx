import { X } from "lucide-react";
import { useCallback, useEffect, useId, useRef, type ReactNode } from "react";

import type { OrderLifecycleKind } from "./types.js";

/** Middle-elides an address or identifier without losing its distinguishing ends. */
export function short(value: string, head = 5, tail = 4): string {
  return value.length > head + tail + 1
    ? `${value.slice(0, head)}…${value.slice(-tail)}`
    : value;
}

export const lifecycleCopy: Record<OrderLifecycleKind, string> = {
  submitting: "Submitting",
  open: "Open",
  pending_settlement: "Pending settlement",
  partially_filled: "Partially filled",
  fully_filled: "Settled",
  settlement_failed: "Settlement failed",
  cancelled: "Cancelled",
  expired: "Expired",
  closed: "Closed while offline",
  ambiguous: "Reconciling",
  rejected: "Rejected",
};

/**
 * Maps a lifecycle state onto the four product tones. Tone is never the only
 * carrier of meaning — every call site pairs it with `lifecycleCopy`.
 */
export function stateTone(
  kind: OrderLifecycleKind,
): "good" | "bad" | "pending" | "neutral" {
  if (kind === "fully_filled") return "good";
  if (
    kind === "settlement_failed" ||
    kind === "rejected" ||
    kind === "cancelled" ||
    kind === "expired" ||
    kind === "closed"
  )
    return "bad";
  if (kind === "open") return "neutral";
  return "pending";
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

export interface DialogProps {
  open: boolean;
  title: string;
  description?: string;
  onClose(): void;
  children: ReactNode;
  footer?: ReactNode;
  width?: "narrow" | "wide";
}

/**
 * Modal dialog with the accessibility behaviour the product requires: Escape
 * closes, focus moves in on open and returns to the invoker on close, and Tab
 * cycles inside the panel so the trade surface behind it is unreachable.
 */
export function Dialog({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  width = "wide",
}: DialogProps) {
  const panel = useRef<HTMLDivElement>(null);
  const restoreTo = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const descriptionId = useId();

  const trapFocus = useCallback(
    (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panel.current) return;
      const focusable = Array.from(
        panel.current.querySelectorAll<HTMLElement>(FOCUSABLE),
      ).filter((node) => node.offsetParent !== null);
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;
      if (event.shiftKey && (active === first || active === panel.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (!open) return;
    restoreTo.current = document.activeElement as HTMLElement | null;
    const focusable = panel.current?.querySelector<HTMLElement>(FOCUSABLE);
    (focusable ?? panel.current)?.focus();
    window.addEventListener("keydown", trapFocus);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", trapFocus);
      document.body.style.overflow = previousOverflow;
      restoreTo.current?.focus();
    };
  }, [open, trapFocus]);

  if (!open) return null;

  return (
    <div className="dialog-layer">
      <button
        className="dialog-scrim"
        type="button"
        tabIndex={-1}
        aria-hidden="true"
        onClick={onClose}
      />
      <div
        className={`dialog-panel is-${width}`}
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
      >
        <header className="dialog-head">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && <p id={descriptionId}>{description}</p>}
          </div>
          <button
            className="icon-button"
            type="button"
            onClick={onClose}
            aria-label={`Close ${title.toLowerCase()}`}
          >
            <X aria-hidden="true" />
          </button>
        </header>
        <div className="dialog-body">{children}</div>
        {footer && <footer className="dialog-foot">{footer}</footer>}
      </div>
    </div>
  );
}

export interface SegmentedProps<T extends string> {
  label: string;
  value: T;
  options: Array<{ value: T; label: string; hint?: string }>;
  onChange(value: T): void;
  className?: string;
}

/** Single-choice control rendered as real buttons so it is keyboard reachable. */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
  className,
}: SegmentedProps<T>) {
  return (
    <div
      className={`segmented ${className ?? ""}`}
      role="group"
      aria-label={label}
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={value === option.value ? "active" : ""}
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.hint && <small>{option.hint}</small>}
        </button>
      ))}
    </div>
  );
}
