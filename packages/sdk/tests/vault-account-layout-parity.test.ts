/**
 * A-3 — pin the SDK's hand-written vault account offsets to the fixture
 * GENERATED from the real on-chain structs.
 *
 * `packages/sdk/src/tee/vault-config.ts` carries `1258`, `1259`, and `1264` as
 * bare literals. Nothing checked them. The neighbouring test
 * (`tee-vault-config.test.ts`) builds its synthetic account *using those same
 * constants*, so it is self-consistent by construction and passes for any
 * values at all — including wrong ones.
 *
 * That is the exact failure A-3 describes: the SDK can agree with itself while
 * disagreeing with `VaultConfig`, and the first symptom is a client reading the
 * wrong `num_trees` off a real account and mis-routing a shard, or reading a
 * garbage TEE pubkey set and refusing every attestation.
 *
 * `programs/vault/account-layout.json` is emitted from the structs themselves
 * (`offset_of!` for zero-copy accounts, probe-verified Borsh accumulation for
 * the rest), so it is the one artifact Rust, the TEE, and this package can all
 * be held to. Regenerate it in the same commit as any struct change:
 *
 *   UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  NUM_TEE_KEYS_OFFSET,
  NUM_TREES_OFFSET,
  TEE_PUBKEYS_OFFSET,
  VAULT_CONFIG_ACCOUNT_LEN,
} from "../src/index.js";

interface LayoutField {
  offset: number;
  size: number;
}
interface LayoutAccount {
  account_len: number;
  [field: string]: number | LayoutField;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const fixturePath = join(repoRoot, "programs", "vault", "account-layout.json");

function loadAccount(name: string): LayoutAccount {
  let raw: string;
  try {
    raw = readFileSync(fixturePath, "utf8");
  } catch (e) {
    throw new Error(
      `cannot read the generated vault layout fixture at ${fixturePath}: ${String(e)}\n` +
        "Regenerate with: UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture",
    );
  }
  const parsed = JSON.parse(raw) as { accounts: Record<string, LayoutAccount> };
  const account = parsed.accounts?.[name];
  if (!account) throw new Error(`account-layout.json has no entry for ${name}`);
  return account;
}

function offsetOf(account: LayoutAccount, field: string): number {
  const entry = account[field];
  if (typeof entry !== "object" || typeof entry.offset !== "number") {
    throw new Error(`account-layout.json: missing offset for field ${field}`);
  }
  return entry.offset;
}

describe("vault account layout parity (A-3)", () => {
  const vaultConfig = loadAccount("VaultConfig");

  it("SDK VaultConfig offsets match the generated struct layout", () => {
    expect(TEE_PUBKEYS_OFFSET).toBe(offsetOf(vaultConfig, "tee_pubkeys"));
    expect(NUM_TEE_KEYS_OFFSET).toBe(offsetOf(vaultConfig, "num_tee_keys"));
    expect(NUM_TREES_OFFSET).toBe(offsetOf(vaultConfig, "num_trees"));
  });

  it("SDK VaultConfig account length matches the generated struct size", () => {
    expect(VAULT_CONFIG_ACCOUNT_LEN).toBe(vaultConfig.account_len);
  });

  it("the tee_pubkeys array fits inside the account it is read from", () => {
    // Guards the read the SDK actually performs: 16 pubkeys starting at
    // TEE_PUBKEYS_OFFSET must not run past the end of the account. A field
    // inserted before the array would push it over the edge, and the resulting
    // subarray would silently be short rather than throwing.
    const teePubkeys = vaultConfig.tee_pubkeys;
    if (typeof teePubkeys !== "object") throw new Error("tee_pubkeys missing");
    expect(TEE_PUBKEYS_OFFSET + teePubkeys.size).toBeLessThanOrEqual(
      vaultConfig.account_len,
    );
  });
});
