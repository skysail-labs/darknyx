import { getAssociatedTokenAddress } from "@solana/spl-token";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";

export const runtime = "nodejs";

async function readAtaBalance(
  conn: import("@solana/web3.js").Connection,
  mint: PublicKey,
  owner: PublicKey,
) {
  const ata = await getAssociatedTokenAddress(mint, owner);
  const info = await conn.getAccountInfo(ata, "confirmed");
  if (!info)
    return { ata: ata.toBase58(), exists: false, amount: "0" } as const;
  // SPL Token account layout: amount is u64 LE at offset 64.
  const amount = new DataView(
    info.data.buffer,
    info.data.byteOffset + 64,
    8,
  ).getBigUint64(0, true);
  return {
    ata: ata.toBase58(),
    exists: true,
    amount: amount.toString(),
  } as const;
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { ownerPubkeyBase58?: string };
    if (!body.ownerPubkeyBase58) {
      return NextResponse.json(
        { ok: false, error: "missing ownerPubkeyBase58" },
        { status: 400 },
      );
    }
    const owner = new PublicKey(body.ownerPubkeyBase58);

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1 } = getDemoConnections(cfg);
    const { baseMint, quoteMint } = parseDemoPrograms(cfg);

    const [base, quote] = await Promise.all([
      readAtaBalance(l1, baseMint, owner),
      readAtaBalance(l1, quoteMint, owner),
    ]);

    return NextResponse.json({
      ok: true,
      base: {
        ...base,
        mintBase58: baseMint.toBase58(),
        decimals: cfg.baseMint.decimals,
      },
      quote: {
        ...quote,
        mintBase58: quoteMint.toBase58(),
        decimals: cfg.quoteMint.decimals,
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
