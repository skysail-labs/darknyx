import { describe, expect, it } from "vitest";

import { noteCommitmentV2, poseidonHashBytesBE } from "../src/utxo/note.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { noteCommitmentFromBytes } from "../src/utxo/note-identity.js";
import {
  deriveLegacyMergeInner,
  searchLegacyFeeDictionary,
} from "./helpers/privacy-observer.js";

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value, "hex"));

describe("retired public-data lineage constructions", () => {
  it("recovers a planted PA-01 legacy fee from public data", async () => {
    const inputCommitment = fromHex("11".repeat(32));
    const tokenMint = new Uint8Array(32).fill(0x31);
    const protocolOwnerCommitment = 17n;
    const role = 0xfcn;
    const plantedAmount = 37n;
    const legacyInner = await poseidonHashBytesBE([
      25n,
      BigInt(`0x${Buffer.from(inputCommitment).toString("hex")}`),
      role,
    ]);
    const target = await noteCommitmentV2({
      tokenMint,
      amount: plantedAmount,
      ownerCommitment: protocolOwnerCommitment,
      innerHash: BigInt(`0x${Buffer.from(legacyInner).toString("hex")}`),
    });
    const amount = await searchLegacyFeeDictionary({
      inputCommitment,
      targetFeeCommitment: target,
      tokenMint,
      protocolOwnerCommitment,
      role: Number(role),
      maxFee: 50n,
    });
    expect(amount).toBe(plantedAmount);
  });

  it("derives only the retired PA-02 tag from public merge leaves", async () => {
    const commitments = [
      fromHex(
        "13f52d5049005ab83a3a3d13581b9fb7ca473ad74f813857d0a4f3b95cf4d8d5",
      ),
      fromHex(
        "00894a1e3a73fe423b9b72cd1f1308ca438ea18971555d049631b9428f7e81b2",
      ),
    ];
    const legacyInner = await deriveLegacyMergeInner(commitments);
    expect(Buffer.from(legacyInner).toString("hex")).toBe(
      "20fc95a5b0babac413d46e7a9a1411766ff7eaf8464369c475ae9ddd3b81a000",
    );
    const commitment = fromHex(
      "0788ebc14e987a36c69a4874e1f98c27a0711faf55114d3e0760f0603ef5bf02",
    );
    const tag = await deriveNoteUseTag(
      noteCommitmentFromBytes(commitment),
      legacyInner,
    );
    expect(Buffer.from(tag).toString("hex")).toBe(
      "2def4d9f4f0eb961d0cea78c987aeb348c6024418ba39ac3b0b114b4755f9cfd",
    );
  });
});
