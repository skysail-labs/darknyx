import { useEffect, useState, type ReactNode } from "react";

import { TraderShell } from "./trader-shell.js";
import type { TraderShellController, TraderShellSnapshot } from "./types.js";

export interface TraderProductProps {
  controller: TraderShellController;
  /** Disable only when the trusted host owns boot sequencing explicitly. */
  autoStart?: boolean;
  /** Price-chart region supplied by the host; see `TraderShellProps.chartSlot`. */
  chartSlot?: ReactNode;
}

/** React bridge over the page-safe observable controller contract. */
export function TraderProduct({
  controller,
  autoStart = true,
  chartSlot,
}: TraderProductProps) {
  const [snapshot, setSnapshot] = useState<TraderShellSnapshot>(() =>
    controller.snapshot(),
  );

  useEffect(() => controller.subscribe(setSnapshot), [controller]);
  useEffect(() => {
    if (autoStart) void controller.start();
  }, [autoStart, controller]);

  return (
    <TraderShell
      snapshot={snapshot}
      actions={controller.actions}
      chartSlot={chartSlot}
    />
  );
}
