import { PublicKey, TransactionInstruction } from "@solana/web3.js";

/** JSON-safe wire format for a single `TransactionInstruction`. */
export interface InstructionJson {
  programId: string;
  keys: { pubkey: string; isSigner: boolean; isWritable: boolean }[];
  data: string;
}

export function instructionToJson(ix: TransactionInstruction): InstructionJson {
  return {
    programId: ix.programId.toBase58(),
    keys: ix.keys.map((m) => ({
      pubkey: m.pubkey.toBase58(),
      isSigner: m.isSigner,
      isWritable: m.isWritable,
    })),
    data: Buffer.from(ix.data).toString("hex"),
  };
}

export function instructionFromJson(
  j: InstructionJson,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(j.programId),
    keys: j.keys.map((k) => ({
      pubkey: new PublicKey(k.pubkey),
      isSigner: k.isSigner,
      isWritable: k.isWritable,
    })),
    data: Buffer.from(j.data, "hex"),
  });
}
