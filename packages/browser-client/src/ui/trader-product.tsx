import { useEffect, useState } from "react";

import { TraderShell } from "./trader-shell.js";
import type { TraderShellController, TraderShellSnapshot } from "./types.js";

export interface TraderProductProps {
  controller: TraderShellController;
  /** Disable only when the trusted host owns boot sequencing explicitly. */
  autoStart?: boolean;
}

/** React bridge over the page-safe observable controller contract. */
export function TraderProduct({
  controller,
  autoStart = true,
}: TraderProductProps) {
  const [snapshot, setSnapshot] = useState<TraderShellSnapshot>(() =>
    controller.snapshot(),
  );

  useEffect(() => controller.subscribe(setSnapshot), [controller]);
  useEffect(() => {
    if (autoStart) void controller.start();
  }, [autoStart, controller]);

  return <TraderShell snapshot={snapshot} actions={controller.actions} />;
}
