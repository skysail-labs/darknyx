import type { ChainScan, RawSettleTx } from "@darknyx/sdk/browser-recovery";

import {
  requestVaultInternal,
  type BrowserVault,
} from "../custody/browser-vault.js";
import { EncryptedIndexedDbInventoryStore } from "./inventory-store.js";
import type { InventoryCiphertext } from "./inventory-store.js";
import type { RecoveryReport } from "./types.js";

const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

export interface BrowserRecoveryOptions {
  vault: BrowserVault;
  programId: string;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  scan: ChainScan;
  sinceSlot?: number;
}

/**
 * Scan public finalized chain data outside custody, then perform all seed-bound
 * filtering/decryption inside the serialized custody Worker.
 */
export async function recoverBrowserInventory(
  options: BrowserRecoveryOptions,
): Promise<RecoveryReport> {
  const transactions: RawSettleTx[] = await options.scan({
    sinceSlot: options.sinceSlot,
  });
  return requestVaultInternal<RecoveryReport>(options.vault, "recoverNotes", {
    programId: options.programId,
    baseMint: hex(options.baseMint),
    quoteMint: hex(options.quoteMint),
    transactions,
    sinceSlot: options.sinceSlot,
  });
}

/** Build the durable encrypted store from a key that never becomes extractable. */
export async function inventoryStoreForVault(
  vault: BrowserVault,
  databaseName?: string,
): Promise<EncryptedIndexedDbInventoryStore> {
  return new EncryptedIndexedDbInventoryStore(
    {
      seal: (plaintext) =>
        requestVaultInternal<InventoryCiphertext>(vault, "inventorySeal", {
          plaintext,
        }),
      open: (ciphertext) =>
        requestVaultInternal<Uint8Array>(vault, "inventoryOpen", {
          iv: ciphertext.iv,
          ciphertext: ciphertext.ciphertext,
        }),
    },
    databaseName,
  );
}
