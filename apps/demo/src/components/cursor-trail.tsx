"use client";

import { useEffect, useRef } from "react";

const HEX = "0123456789abcdef";
const CRYPTO_FRAGMENTS = [
  "0x", "ff", "a3", "4f", "d1", "7e", "b2", "9c",
  "Σ", "∅", "⊕", "∇", "λ", "π", "δ", "φ",
];

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  chars: string[];      // current displayed chars, scramble over time
  targetChars: string[]; // original chars
  age: number;          // 0..1, increases each frame
  maxAge: number;       // frames until dead
  size: number;
  opacity: number;
}

function randomHexChunk(len = 4): string {
  let s = "";
  for (let i = 0; i < len; i++) s += HEX[Math.floor(Math.random() * 16)];
  return s;
}

function randomFragment(): string {
  if (Math.random() < 0.6) {
    return `0x${randomHexChunk(Math.random() < 0.5 ? 2 : 4)}`;
  }
  return CRYPTO_FRAGMENTS[Math.floor(Math.random() * CRYPTO_FRAGMENTS.length)];
}

function scrambleChar(c: string): string {
  if (c === "x" || c === "0") return c;
  return HEX[Math.floor(Math.random() * 16)];
}

export function CursorTrail() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particles = useRef<Particle[]>([]);
  const mouse = useRef({ x: -999, y: -999 });
  const rafRef = useRef<number>(0);
  const lastSpawn = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Resize canvas to full viewport
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    // Track mouse
    const onMove = (e: MouseEvent) => {
      mouse.current = { x: e.clientX, y: e.clientY };
    };
    window.addEventListener("mousemove", onMove);

    // Spawn particles on move
    const spawnParticles = (now: number) => {
      if (now - lastSpawn.current < 30) return; // max ~33 spawns/sec
      lastSpawn.current = now;

      const count = Math.floor(Math.random() * 2) + 1;
      for (let i = 0; i < count; i++) {
        const text = randomFragment();
        const chars = text.split("");
        particles.current.push({
          x: mouse.current.x + (Math.random() - 0.5) * 10,
          y: mouse.current.y + (Math.random() - 0.5) * 10,
          vx: (Math.random() - 0.5) * 0.6,
          vy: -Math.random() * 0.8 - 0.2, // slight upward drift
          chars: [...chars],
          targetChars: [...chars],
          age: 0,
          maxAge: 50 + Math.random() * 40, // ~800ms–1.4s at 60fps
          size: 10 + Math.random() * 3,
          opacity: 1,
        });
      }
    };

    const draw = (now: number) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      spawnParticles(now);

      const alive: Particle[] = [];
      for (const p of particles.current) {
        p.age++;
        const progress = p.age / p.maxAge; // 0..1

        // Position drift
        p.x += p.vx;
        p.y += p.vy;

        // Scramble chars as progress increases past 0.4
        if (progress > 0.4) {
          const scrambleIntensity = (progress - 0.4) / 0.6; // 0..1
          p.chars = p.targetChars.map((c) =>
            Math.random() < scrambleIntensity ? scrambleChar(c) : c
          );
        }

        // Opacity: full until 60%, then fade out
        p.opacity = progress < 0.6 ? 1 : 1 - (progress - 0.6) / 0.4;

        if (p.age < p.maxAge) alive.push(p);

        // Draw
        // Glow: near-cursor particles are brighter
        const glowAlpha = p.opacity * 0.25;
        ctx.save();
        ctx.globalAlpha = glowAlpha;
        ctx.fillStyle = "#5b6af0";
        ctx.filter = "blur(6px)";
        ctx.font = `${p.size + 2}px "JetBrains Mono", monospace`;
        ctx.fillText(p.chars.join(""), p.x, p.y);
        ctx.restore();

        // Main text
        ctx.save();
        ctx.globalAlpha = p.opacity * 0.75;
        // Color shifts from chalk → fog → accent as it scrambles
        const r = Math.round(174 + (91 - 174) * Math.max(0, (progress - 0.4) / 0.6));
        const g = Math.round(172 + (106 - 172) * Math.max(0, (progress - 0.4) / 0.6));
        const b = Math.round(176 + (240 - 176) * Math.max(0, (progress - 0.4) / 0.6));
        ctx.fillStyle = `rgb(${r},${g},${b})`;
        ctx.font = `${p.size}px "JetBrains Mono", monospace`;
        ctx.fillText(p.chars.join(""), p.x, p.y);
        ctx.restore();
      }

      particles.current = alive;
      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-[9999]"
      aria-hidden="true"
    />
  );
}
