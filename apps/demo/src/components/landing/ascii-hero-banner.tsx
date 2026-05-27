"use client";

import { useEffect, useRef } from "react";

const CHARS =
  "ASDGKDFSWRKWRWORNWRWKKKWRKR";

interface Cell {
  char: string;
  target: boolean;
  glow: boolean;
  switchAt: number;
}

export function AsciiHeroBanner({ contained = false }: { contained?: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const frameRef = useRef(0);
  const animRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current!;
    if (!canvas) return;

    const ctx = canvas.getContext("2d")!;

    const DPR = window.devicePixelRatio || 1;

    const FONT_SIZE = 9;
    const CHAR_W = 7;
    const LINE_H = 10;

    const resize = () => {
      const width = contained
        ? (canvas.parentElement?.offsetWidth ?? 480)
        : window.innerWidth;
      const height = contained ? 340 : 620;

      canvas.width = width * DPR;
      canvas.height = height * DPR;

      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

      build(width, height);
    };

    let cells: Cell[][] = [];

    function randChar() {
      return CHARS[Math.floor(Math.random() * CHARS.length)];
    }

    function build(width: number, height: number) {
      const COLS = Math.floor(width / CHAR_W);
      const ROWS = Math.floor(height / LINE_H);

      cells = [];

      for (let y = 0; y < ROWS; y++) {
        const row: Cell[] = [];

        for (let x = 0; x < COLS; x++) {
          row.push({
            char: randChar(),
            target: false,
            glow: false,
            switchAt: Math.random() * 40,
          });
        }

        cells.push(row);
      }

      const centerX = Math.floor(COLS / 2);
      const centerY = Math.floor(ROWS / 2);

      const logo: string[] = [
        "            █████████████            ",
        "         ███████████████████         ",
        "      █████████████████████████       ",
        "     ███████████████████████████     ",
        "     ███████████████████████████     ",
        "     ███████████████████████████     ",
        "  ████████████████████████████████   ",
        "  ███████████████████████████         ",
      ];

      const logoWidth = logo[0].length;
      const logoHeight = logo.length;

      const letters: Record<string, string[]> = {
        D: ["████ ", "█   █", "█   █", "█   █", "████ "],
        A: [" ███ ", "█   █", "█████", "█   █", "█   █"],
        R: ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
        K: ["█  █ ", "█ █  ", "██   ", "█ █  ", "█  █ "],
        N: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
        Y: ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "],
        X: ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
      };

      const text = "DARKNYX";
      const textWidth = text.length * 7;
      const totalHeight = logoHeight + 10;

      const logoStartX = Math.floor(centerX - logoWidth / 2);
      const logoStartY = Math.floor(centerY - totalHeight / 2);

      for (let y = 0; y < logo.length; y++) {
        for (let x = 0; x < logo[y].length; x++) {
          if (logo[y][x] !== " ") {
            const gx = logoStartX + x;
            const gy = logoStartY + y;
            if (cells[gy]?.[gx]) {
              cells[gy][gx].target = true;
              cells[gy][gx].glow = true;
            }
          }
        }
      }

      const textStartX = Math.floor(centerX - textWidth / 2);
      const textStartY = logoStartY + logoHeight + 5;
      let cursor = textStartX;

      for (const ch of text) {
        const bitmap = letters[ch];
        for (let py = 0; py < bitmap.length; py++) {
          for (let px = 0; px < bitmap[py].length; px++) {
            if (bitmap[py][px] !== " ") {
              const gx = cursor + px;
              const gy = textStartY + py;
              if (cells[gy]?.[gx]) {
                cells[gy][gx].target = true;
                cells[gy][gx].glow = true;
              }
            }
          }
        }
        cursor += 7;
      }

      for (let i = 0; i < 80; i++) {
        const x = Math.floor(Math.random() * COLS);
        const y = Math.floor(Math.random() * ROWS);
      }
    }

    function draw() {
      frameRef.current++;

      const frame = frameRef.current;

      const width = canvas.width / DPR;
      const height = canvas.height / DPR;

      ctx.fillStyle = "#050505";
      ctx.fillRect(0, 0, width, height);

      // dotted matrix grid
      ctx.fillStyle = "rgba(255,255,255,0.08)";

      for (let x = 0; x < width; x += 12) {
        for (let y = 0; y < height; y += 12) {
          ctx.fillRect(x, y, 1, 1);
        }
      }

      ctx.font = `${FONT_SIZE}px monospace`;
      ctx.textBaseline = "top";

      for (let y = 0; y < cells.length; y++) {
        for (let x = 0; x < cells[y].length; x++) {
          const cell = cells[y][x];

          if (frame >= cell.switchAt) {
            cell.char = randChar();

            cell.switchAt =
              frame +
              (cell.target
                ? 5 + Math.random() * 10
                : 20 + Math.random() * 80);
          }

          const px = x * CHAR_W;
          const py = y * LINE_H;

          if (cell.glow) {
            ctx.fillStyle = "rgba(217, 104, 32, 0.98)";
            ctx.shadowBlur = 14;
            ctx.shadowColor = "rgba(217, 104, 32, 0.95)";
          } else if (cell.target) {
            ctx.fillStyle = "rgba(217, 104, 32, 0.55)";
            ctx.shadowBlur = 0;
          } else {
            ctx.fillStyle = "rgba(255,255,255,0.10)";
            ctx.shadowBlur = 0;
          }

          ctx.fillText(cell.char, px, py);
        }
      }

      // scanlines
      ctx.fillStyle = "rgba(255,255,255,0.03)";

      for (let y = 0; y < height; y += 4) {
        ctx.fillRect(0, y, width, 1);
      }

      animRef.current = requestAnimationFrame(draw);
    }

    resize();

    window.addEventListener("resize", resize);

    draw();

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener("resize", resize);
    };
  }, []);

  if (contained) {
    return (
      <div className="relative overflow-hidden" style={{ borderRadius: "2px", background: "#050505" }}>
        <canvas ref={canvasRef} className="block w-full" style={{ height: "340px" }} />
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_30%,black_100%)]" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-linear-to-b from-black/50 to-transparent" />
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-16 bg-linear-to-t from-black/60 to-transparent" />
      </div>
    );
  }

  return (
    <section className="relative w-full overflow-hidden border-b border-white/10 bg-[#050505]">
      <canvas ref={canvasRef} className="block w-full" style={{ height: "620px" }} />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_20%,black_100%)]" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-32 bg-linear-to-b from-black/60 to-transparent" />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-32 bg-linear-to-t from-black/70 to-transparent" />
    </section>
  );
}