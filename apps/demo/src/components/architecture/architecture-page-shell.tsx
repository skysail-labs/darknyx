"use client";

import { useRef, useEffect, useCallback } from "react";
import { ArchitectureHero } from "@/components/architecture/architecture-hero";
import { ArchitectureExplorer } from "@/components/architecture/architecture-explorer";

export function ArchitecturePageShell() {
  const scrollRef = useRef<HTMLDivElement>(null);
  const explorerRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLDivElement>(null);
  const isProgrammatic = useRef(false);

  const scrollToExplorer = useCallback(() => {
    isProgrammatic.current = true;
    explorerRef.current?.scrollIntoView({ behavior: "smooth" });
    setTimeout(() => { isProgrammatic.current = false; }, 800);
  }, []);

  const scrollToHero = useCallback(() => {
    isProgrammatic.current = true;
    heroRef.current?.scrollIntoView({ behavior: "smooth" });
    setTimeout(() => { isProgrammatic.current = false; }, 800);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    const block = (e: Event) => {
      if (!isProgrammatic.current) e.preventDefault();
    };

    el.addEventListener("wheel", block, { passive: false });
    el.addEventListener("touchmove", block, { passive: false });
    el.addEventListener("keydown", (e: KeyboardEvent) => {
      const blocked = ["ArrowUp", "ArrowDown", "PageUp", "PageDown", "Space", " "];
      if (blocked.includes(e.key)) block(e);
    });

    return () => {
      el.removeEventListener("wheel", block);
      el.removeEventListener("touchmove", block);
    };
  }, []);

  return (
    <div
      ref={scrollRef}
      style={{
        height: "calc(100dvh - 40px)",
        overflowY: "scroll",
        scrollbarWidth: "none",
      }}
      className="[&::-webkit-scrollbar]:hidden"
    >
      <div ref={heroRef}>
        <ArchitectureHero onScrollDown={scrollToExplorer} />
      </div>
      <div ref={explorerRef}>
        <ArchitectureExplorer onScrollUp={scrollToHero} />
      </div>
    </div>
  );
}
