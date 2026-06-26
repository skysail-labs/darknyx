import { NyxMark } from "./nyx-mark";

export function NyxFooter({ tone = "ink" }: { tone?: "ink" | "chalk" }) {
  const isInk = tone === "ink";
  return (
    <footer
      className={
        isInk
          ? "border-t border-white/[0.06] bg-nyx-ink py-10 text-nyx-fog"
          : "border-t border-black/[0.06] bg-nyx-chalk py-10 text-nyx-slate"
      }
    >
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-5 sm:px-7 md:flex-row md:items-end md:justify-between">
        <div className="flex items-center gap-3">
          <NyxMark
            size={28}
            className={isInk ? "text-nyx-chalk" : "text-nyx-ink"}
          />
          <div>
            <div
              className={
                isInk
                  ? "text-[13px] font-medium text-nyx-chalk"
                  : "text-[13px] font-medium text-nyx-ink"
              }
            >
              darknyx
            </div>
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] opacity-60">
              identity v1 · devnet
            </div>
          </div>
        </div>

        <div className="flex flex-wrap gap-x-6 gap-y-2 text-[12px]">
          <a
            className="hover:text-nyx-accent"
            href="https://github.com/skysail-labs/darknyx"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
          <a
            className="hover:text-nyx-accent"
            href="https://x.com/DarknyxProtocol/"
            target="_blank"
            rel="noreferrer"
          >
            X
          </a>
        </div>

        <div className="font-mono text-[10px] uppercase tracking-[0.16em] opacity-50">
          settle in the dark · prove in the light
        </div>
      </div>
    </footer>
  );
}
