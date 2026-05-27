"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

/* -------------------------------------------------------------------------- */
/* LOGO MASK — 30×20 grid                                                     */
/* -------------------------------------------------------------------------- */

const COLS = 30;
const ROWS = 20;

function buildLogoMask(): boolean[][] {
  const mask: boolean[][] = Array.from({ length: ROWS }, () => Array(COLS).fill(false));
  const cx = 14.5, cy = 9, r = 8;
  for (let row = 0; row < ROWS; row++) {
    for (let col = 0; col < COLS; col++) {
      const dx = col - cx, dy = row - cy;
      if (dy <= 0.5 && Math.sqrt(dx * dx + dy * dy) <= r + 0.3) mask[row][col] = true;
    }
  }
  for (let col = 3; col <= 26; col++) { mask[11][col] = true; mask[12][col] = true; }
  for (let col = 3; col <= 19; col++) { mask[14][col] = true; }
  return mask;
}

const LOGO_MASK = buildLogoMask();

/* -------------------------------------------------------------------------- */
/* PIXEL FONT — 5×7 bitmap for lowercase a-z                                  */
/* Each letter: array of 5-bit rows (top to bottom, MSB = leftmost pixel)     */
/* -------------------------------------------------------------------------- */

const PIXEL_FONT: Record<string, number[]> = {
  d: [0b00010, 0b00010, 0b01110, 0b10010, 0b10010, 0b10010, 0b01110],
  a: [0b00000, 0b00000, 0b01110, 0b00010, 0b01110, 0b10010, 0b01110],
  r: [0b00000, 0b00000, 0b10110, 0b11001, 0b10000, 0b10000, 0b10000],
  k: [0b10000, 0b10000, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
  n: [0b00000, 0b00000, 0b11010, 0b10110, 0b10010, 0b10010, 0b10010],
  y: [0b00000, 0b00000, 0b10010, 0b10010, 0b01110, 0b00010, 0b01100],
  x: [0b00000, 0b00000, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001],
};

/* Build pixel positions for a word. Returns array of {x, y, isDark} */
function buildWordPixels(word: string, darkSplit: number): Array<{ x: number; y: number; dark: boolean }> {
  const LETTER_W = 5;
  const LETTER_H = 7;
  const KERNING = 1; // gap between letters
  const pixels: Array<{ x: number; y: number; dark: boolean }> = [];

  let cursorX = 0;
  for (let li = 0; li < word.length; li++) {
    const ch = word[li];
    const bitmap = PIXEL_FONT[ch];
    if (!bitmap) { cursorX += LETTER_W + KERNING; continue; }
    const isDark = li >= darkSplit; // "nyx" part
    for (let row = 0; row < LETTER_H; row++) {
      for (let bit = 0; bit < LETTER_W; bit++) {
        if (bitmap[row] & (1 << (LETTER_W - 1 - bit))) {
          pixels.push({ x: cursorX + bit, y: row, dark: isDark });
        }
      }
    }
    cursorX += LETTER_W + KERNING;
  }
  return pixels;
}

// "dark" = chars 0-3 (orange), "nyx" = chars 4-6 (darker)
const WORD_PIXELS = buildWordPixels("darknyx", 4);

/* -------------------------------------------------------------------------- */
/* PARTICLE                                                                   */
/* -------------------------------------------------------------------------- */

interface Particle {
  col: number; row: number;
  x: number; y: number;
  base: number;
  size: number;
}

/* -------------------------------------------------------------------------- */
/* STATIC SVG MARK — top-left header, no animation                           */
/* -------------------------------------------------------------------------- */

function NyxStaticMark() {
  const dots: [number, number][] = [
    [10,0],[12,0],[14,0],[16,0],
    [8,2],[10,2],[12,2],[14,2],[16,2],[18,2],
    [6,4],[8,4],[10,4],[12,4],[14,4],[16,4],[18,4],[20,4],
    [6,6],[8,6],[10,6],[12,6],[14,6],[16,6],[18,6],[20,6],
    [2,10],[4,10],[6,10],[8,10],[10,10],[12,10],[14,10],[16,10],[18,10],[20,10],[22,10],[24,10],
    [2,14],[4,14],[6,14],[8,14],[10,14],[12,14],
  ];
  return (
    <svg width="28" height="18" viewBox="0 0 28 18" fill="none" aria-hidden="true">
      {dots.map(([x, y], i) => (
        <rect key={i} x={x} y={y} width={2} height={2}
          fill={y <= 6 ? "#d96820" : y === 10 ? "#b84e10" : "#8a3808"}
          opacity={y <= 4 ? 0.9 : y === 6 ? 0.75 : y === 10 ? 0.65 : 0.45}
        />
      ))}
    </svg>
  );
}

/* -------------------------------------------------------------------------- */
/* MAIN COMPONENT                                                             */
/* -------------------------------------------------------------------------- */

export function PixelLogoCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const router = useRouter();
  const animRef = useRef<number>(0);
  const layoutRef = useRef({ originX: 0, originY: 0, CELL: 0, PIXEL: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    if (!ctx) return;
    const cvs: HTMLCanvasElement = canvas;

    let W = window.innerWidth;
    let H = window.innerHeight;
    cvs.width = W;
    cvs.height = H;

    const PIXEL = Math.min(Math.floor(Math.min(W, H) / 60), 7);
    const GAP = 1;
    const CELL = PIXEL + GAP;
    const gridW = COLS * CELL;
    const gridH = ROWS * CELL;
    const originX = (W - gridW) / 2;
    const originY = (H - gridH) / 2;
    layoutRef.current = { originX, originY, CELL, PIXEL };

    const particles: Particle[] = [];
    for (let row = 0; row < ROWS; row++) {
      for (let col = 0; col < COLS; col++) {
        const active = LOGO_MASK[row][col];
        particles.push({
          col, row,
          x: originX + col * CELL + PIXEL / 2,
          y: originY + row * CELL + PIXEL / 2,
          base: active ? 1 : 0,
          size: PIXEL * 0.88,
        });
      }
    }

    // "darknyx" = 7 letters × (5+1 kerning) - 1 trailing kerning = 41 pixel-cols wide
    const wordPixelW = 41;
    // Scale so the word spans exactly gridW pixels, aligning with logo left/right edges
    const PS = gridW / wordPixelW;

    const wordX = originX; // flush with left edge of logo grid
    const logoBottom = originY + gridH;
    const wordY = logoBottom + CELL * 0.5;

    function draw() {
      if (cvs.width !== window.innerWidth || cvs.height !== window.innerHeight) {
        W = window.innerWidth; H = window.innerHeight;
        cvs.width = W; cvs.height = H;
      }

      // solid dark background
      ctx.fillStyle = "#050608";
      ctx.fillRect(0, 0, W, H);

      // vertical grid lines
      ctx.lineWidth = 1;
      const gs = CELL;
      for (let gx = ((originX % gs) + gs) % gs; gx < W; gx += gs) {
        ctx.strokeStyle = "rgba(255,255,255,0.08)";
        ctx.beginPath(); ctx.moveTo(Math.round(gx) + 0.5, 0); ctx.lineTo(Math.round(gx) + 0.5, H); ctx.stroke();
      }

      // logo pixels
      ctx.fillStyle = "#d96820";
      for (const p of particles) {
        if (p.base === 0) continue;
        const half = p.size / 2;
        ctx.fillRect(Math.round(p.x - half), Math.round(p.y - half), Math.round(p.size), Math.round(p.size));
      }

      // "darknyx" pixel word below logo
      const dotSize = Math.max(1, PS * 0.82);
      for (const { x, y, dark } of WORD_PIXELS) {
        ctx.fillStyle = dark ? "#7a3810" : "#d96820";
        const px = wordX + x * PS + (PS - dotSize) / 2;
        const py = wordY + y * PS + (PS - dotSize) / 2;
        ctx.fillRect(Math.round(px), Math.round(py), Math.round(dotSize), Math.round(dotSize));
      }

      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  return (
    <div className="fixed inset-0 bg-[#050608]">
      {/* HEADER */}
      <header className="absolute top-0 left-0 right-0 z-10 flex items-center px-8 py-5">
        <div className="flex items-center gap-2.5 select-none">
          <NyxStaticMark />
          <span
            className="text-[13px] font-medium tracking-[0.06em]"
            style={{ fontFamily: "'JetBrains Mono', monospace", color: "#c8b898" }}
          >
            DarkNyx
          </span>
        </div>
        <span
          className="absolute left-1/2 -translate-x-1/2 text-[11px] uppercase tracking-[0.22em] pointer-events-none"
          style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(160,140,110,0.45)" }}
        >
          Click on logo to enter DarkNyx
        </span>
      </header>

      {/* CANVAS */}
      <canvas
        ref={canvasRef}
        onClick={(e) => {
          const { originX, originY, CELL } = layoutRef.current;
          const col = Math.floor((e.clientX - originX) / CELL);
          const row = Math.floor((e.clientY - originY) / CELL);
          if (col >= 0 && col < COLS && row >= 0 && row < ROWS && LOGO_MASK[row][col]) {
            router.push("/landing");
          }
        }}
        onMouseMove={(e) => {
          const { originX, originY, CELL } = layoutRef.current;
          const col = Math.floor((e.clientX - originX) / CELL);
          const row = Math.floor((e.clientY - originY) / CELL);
          const onLogo = col >= 0 && col < COLS && row >= 0 && row < ROWS && LOGO_MASK[row][col];
          e.currentTarget.style.cursor = onLogo ? "pointer" : "default";
        }}
        className="absolute inset-0 w-full h-full"
        aria-label="DarkNyx — click logo to enter"
      />
    </div>
  );
}
