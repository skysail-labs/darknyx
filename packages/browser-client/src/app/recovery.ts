import { Connection, PublicKey } from "@solana/web3.js";
import {
  makeConnectionScan,
  type RawSettleTx,
} from "@darknyx/sdk/browser-recovery";

import type { BrowserVault } from "../custody/browser-vault.js";
import { recoverBrowserInventory } from "../inventory/browser-recovery.js";
import type { RecoveryReport } from "../inventory/types.js";
import type {
  TrustedVenueSession,
  VenueReleaseConfig,
} from "../venue/types.js";

export type VenueRecovery = (
  vault: BrowserVault,
  venue: TrustedVenueSession,
) => Promise<RecoveryReport>;

/** Finalized, cursor-based multi-market recovery shared by the production app. */
export function createVenueRecovery(
  release: VenueReleaseConfig,
): VenueRecovery {
  const connection = new Connection(release.rpcUrl, "finalized");
  const programId = new PublicKey(release.vaultProgramId);
  const scan = makeConnectionScan(connection, programId);
  let sinceSlot = release.recoveryStartSlot;
  let queued = Promise.resolve();

  return (vault, venue) => {
    let resolve!: (value: RecoveryReport) => void;
    let reject!: (error: unknown) => void;
    const result = new Promise<RecoveryReport>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    queued = queued.then(async () => {
      try {
        const floor = sinceSlot;
        const transactions = await scan({ sinceSlot: floor });
        const cachedScan = async (): Promise<RawSettleTx[]> => transactions;
        const reports = await Promise.all(
          venue.instruments.map((market) =>
            recoverBrowserInventory({
              vault,
              programId: release.vaultProgramId,
              baseMint: new PublicKey(market.baseMint).toBytes(),
              quoteMint: new PublicKey(market.quoteMint).toBytes(),
              scan: cachedScan,
              sinceSlot: floor,
            }),
          ),
        );
        const notes = new Map(
          reports.flatMap((report) =>
            report.notes.map((note) => [note.commitment, note] as const),
          ),
        );
        const nextFloor =
          transactions.length > 0
            ? Math.max(...transactions.map((transaction) => transaction.slot)) +
              1
            : (await connection.getSlot("finalized")) + 1;
        sinceSlot = Math.max(sinceSlot, nextFloor);
        resolve({
          fullScan: floor === release.recoveryStartSlot,
          notes: [...notes.values()],
          recovered: {
            deposits: reports.reduce(
              (sum, report) => sum + report.recovered.deposits,
              0,
            ),
            trade: reports.reduce(
              (sum, report) => sum + report.recovered.trade,
              0,
            ),
            change: reports.reduce(
              (sum, report) => sum + report.recovered.change,
              0,
            ),
            merges: reports.reduce(
              (sum, report) => sum + report.recovered.merges,
              0,
            ),
          },
          unresolvedSettlements: reports.reduce(
            (sum, report) => sum + report.unresolvedSettlements,
            0,
          ),
          unresolvedMerges: reports.reduce(
            (sum, report) => sum + report.unresolvedMerges,
            0,
          ),
        });
      } catch (error) {
        reject(error);
      }
    });
    return result;
  };
}
