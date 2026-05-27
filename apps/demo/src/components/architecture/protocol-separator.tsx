"use client";

export function ProtocolSeparator() {
  return (
    <div className="relative overflow-hidden" style={{ height: "2px", background: "transparent" }}>
      <div className="absolute inset-0" style={{ background: "rgba(255,255,255,0.06)" }} />
      <div className="absolute left-[18%] top-1/2 -translate-y-1/2 h-2 w-2 rounded-full" style={{ background: "rgba(217,104,32,0.5)" }} />
      <div className="absolute right-[18%] top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full" style={{ background: "rgba(255,255,255,0.15)" }} />
    </div>
  );
}
