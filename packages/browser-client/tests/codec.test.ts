import { describe, expect, it } from "vitest";

import {
  aadForHeader,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  validateRecord,
  vaultHeader,
} from "../src/custody/codec.js";

describe("browser vault record codec", () => {
  it("round-trips canonical base64url", () => {
    const bytes = Uint8Array.from([0, 1, 2, 127, 128, 255]);
    const encoded = toBase64Url(bytes);
    expect(encoded).toBe("AAECf4D_");
    expect(fromBase64Url(encoded)).toEqual(bytes);
    expect(() => fromBase64Url(`${encoded}=`)).toThrow(/invalid base64url/);
    expect(() => fromBase64Url("AR")).toThrow(/non-canonical base64url/);
  });

  it("pins the vault-record authenticated-data domain and field order", () => {
    const header = vaultHeader("AQ", new Uint8Array(32), new Uint8Array(32));
    expect(new TextDecoder().decode(aadForHeader(header))).toBe(
      [
        "darknyx/browser-vault/v1",
        "darknyx-browser-vault",
        "1",
        "webauthn-prf-v1",
        "AQ",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ].join("\n"),
    );
  });

  it("rejects malformed nested backup parameters", async () => {
    const { validateBackup } = await import("../src/custody/codec.js");
    expect(() =>
      validateBackup({
        format: "darknyx-master-seed-backup",
        version: 2,
        kdf: null,
        cipher: [],
      }),
    ).toThrow(/unsupported encrypted seed-backup format/);
  });

  it("accepts only exact versioned ciphertext records", () => {
    const header = vaultHeader("AQ", randomBytes(32), randomBytes(32));
    const record = {
      ...header,
      cipher: {
        name: "AES-256-GCM" as const,
        iv: toBase64Url(randomBytes(12)),
        ciphertext: toBase64Url(randomBytes(80)),
      },
    };
    expect(validateRecord(record).record).toEqual(record);
    expect(() => validateRecord({ ...record, version: 2 })).toThrow(
      /unsupported or malformed/,
    );
    expect(() =>
      validateRecord({
        ...record,
        cipher: { ...record.cipher, ciphertext: toBase64Url(randomBytes(79)) },
      }),
    ).toThrow(/lengths/);
  });
});
