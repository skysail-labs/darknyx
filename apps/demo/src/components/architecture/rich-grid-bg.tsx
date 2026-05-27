"use client";

type Props = {
  rings?: number;
  ringScale?: number;
  innerInset?: number;
  linesPerHorizontalSide?: number;
  linesPerVerticalSide?: number;
  stroke?: string;
  opacity?: number;
  className?: string;
};

export default function RichGridBackground({
  rings = 3,
  ringScale = 0.8,
  innerInset = 0.17,
  linesPerHorizontalSide = 15,
  linesPerVerticalSide = 9,
  stroke = "currentColor",
  opacity = 0.5,
  className,
}: Props) {
  const W = 2000;
  const H = 1200;
  const cx = W / 2;
  const cy = H / 2;

  const outer = { x1: 0, y1: 0, x2: W, y2: H };

  const innerW = W * (1 - innerInset * 2);
  const innerH = H * (1 - innerInset * 2);
  const inner = {
    x1: cx - innerW / 2,
    y1: cy - innerH / 2,
    x2: cx + innerW / 2,
    y2: cy + innerH / 2,
  };

  const rects: Array<{ x1: number; y1: number; x2: number; y2: number }> = [];
  // Outward rings (inner → outer)
  for (let i = 0; i < rings; i++) {
    const s = Math.pow(1 / ringScale, i);
    const w = Math.min(innerW * s, W);
    const h = Math.min(innerH * s, H);
    rects.push({
      x1: cx - w / 2,
      y1: cy - h / 2,
      x2: cx + w / 2,
      y2: cy + h / 2,
    });
  }

  const cornerLines = [
    { x1: inner.x1, y1: inner.y1, x2: outer.x1, y2: outer.y1 },
    { x1: inner.x2, y1: inner.y1, x2: outer.x2, y2: outer.y1 },
    { x1: inner.x2, y1: inner.y2, x2: outer.x2, y2: outer.y2 },
    { x1: inner.x1, y1: inner.y2, x2: outer.x1, y2: outer.y2 },
  ];

  function sideRays(side: "top" | "bottom" | "left" | "right", count: number) {
    const lines: Array<{ x1: number; y1: number; x2: number; y2: number }> = [];
    for (let i = 1; i <= count; i++) {
      const t = (i / (count + 1)) * 2 - 1;
      let ox = 0, oy = 0, ex = 0, ey = 0;
      switch (side) {
        case "top":
          ox = cx + (innerW / 2) * t; oy = inner.y1;
          ex = cx + (W / 2) * t;     ey = outer.y1;
          break;
        case "bottom":
          ox = cx + (innerW / 2) * t; oy = inner.y2;
          ex = cx + (W / 2) * t;     ey = outer.y2;
          break;
        case "left":
          ox = inner.x1; oy = cy + (innerH / 2) * t;
          ex = outer.x1; ey = cy + (H / 2) * t;
          break;
        case "right":
          ox = inner.x2; oy = cy + (innerH / 2) * t;
          ex = outer.x2; ey = cy + (H / 2) * t;
          break;
      }
      lines.push({ x1: ox, y1: oy, x2: ex, y2: ey });
    }
    return lines;
  }

  const rays = [
    ...sideRays("top",    linesPerHorizontalSide),
    ...sideRays("bottom", linesPerHorizontalSide),
    ...sideRays("left",   linesPerVerticalSide),
    ...sideRays("right",  linesPerVerticalSide),
  ];

  // ── INNER GRID ───────────────────────────────────────
  // Vertical: connect each top-edge ray origin to its matching bottom-edge origin
  const innerGrid: Array<{ x1: number; y1: number; x2: number; y2: number }> = [];
  for (let i = 1; i <= linesPerHorizontalSide; i++) {
    const t = (i / (linesPerHorizontalSide + 1)) * 2 - 1;
    const x = cx + (innerW / 2) * t;
    innerGrid.push({ x1: x, y1: inner.y1, x2: x, y2: inner.y2 });
  }
  // Horizontal: connect each left-edge ray origin to its matching right-edge origin
  for (let i = 1; i <= linesPerVerticalSide; i++) {
    const t = (i / (linesPerVerticalSide + 1)) * 2 - 1;
    const y = cy + (innerH / 2) * t;
    innerGrid.push({ x1: inner.x1, y1: y, x2: inner.x2, y2: y });
  }

  return (
    <svg
      className={className}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      style={{ width: "100%", height: "100%", display: "block", color: stroke }}
    >
      <defs>
        <filter id="grid-blur">
          <feGaussianBlur stdDeviation="0.2" />
        </filter>
        {/* Fade mask: white inside 2nd rect, black at screen edges, blurred transition */}
        <mask id="fade-mask">
          <rect x={0} y={0} width={W} height={H} fill="black" />
          <rect
            x={rects[1]?.x1 ?? 0}
            y={rects[1]?.y1 ?? 0}
            width={(rects[1]?.x2 ?? W) - (rects[1]?.x1 ?? 0)}
            height={(rects[1]?.y2 ?? H) - (rects[1]?.y1 ?? 0)}
            fill="white"
            filter="url(#mask-blur)"
          />
        </mask>
        <filter id="mask-blur" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation={`${W * 0.07} ${H * 0.07}`} />
        </filter>
      </defs>
      <g
        stroke="currentColor"
        strokeWidth={1}
        fill="none"
        vectorEffect="non-scaling-stroke"
        strokeLinecap="round"
        opacity={opacity}
        filter="url(#grid-blur)"
        mask="url(#fade-mask)"
      >
        {rects.map((r, i) => (
          <rect key={`r-${i}`} x={r.x1} y={r.y1} width={r.x2 - r.x1} height={r.y2 - r.y1} />
        ))}
        {cornerLines.map((l, i) => (
          <line key={`c-${i}`} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
        ))}
        {rays.map((l, i) => (
          <line key={`p-${i}`} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
        ))}
        {innerGrid.map((l, i) => (
          <line key={`g-${i}`} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
        ))}
      </g>
    </svg>
  );
}
