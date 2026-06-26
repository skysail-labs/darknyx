/**
 * Demo-only helper: read `vault_config.fee_rate_bps` from L1 and, if it is
 * non-zero, send `set_protocol_config(fee_rate_bps=0)` so subsequent
 * `run_batch` + `tee_forced_settle` rounds don't trip
 * `MatchingError::ConservationViolation` (the user's deposit equals the bid
 * notional in the demo, so any fee underflows the conservation check).
 *
 * The current demo's L1 settle path also asserts `buyer_fee == 0 &&
 * seller_fee == 0` because it builds a `MatchResultPayload` with a
 * `note_fee_commitment` of zero. So zeroing fees on devnet is the
 * end-to-end-correct thing for the demo. Production would obviously route
 * fees to a real protocol-owner shielded identity.
 *
 * The admin keypair (loaded from the demo keyring) is the only signer that
 * `set_protocol_config` accepts; this is why we run the auto-zero only on
 * the dapp demo's owned devnet.
 */
import { buildSetProtocolConfigInstruction, vaultConfigPda } from "@nyx/sdk";
import {
  Connection,
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";

/** VaultConfig field offsets (after the 8B anchor discriminator). */
const PROTOCOL_OWNER_COMMITMENT_OFFSET =
  8 + 32 + 32 + 32 + 8 + 32 + 32 * 32 + 20 * 32 + 20 * 32 + 1 + 1;
const FEE_RATE_BPS_OFFSET = PROTOCOL_OWNER_COMMITMENT_OFFSET + 32;

export interface EnsureZeroFeeOutcome {
  /** Fee rate observed on the live vault before any fix-up. */
  observedFeeBps: number;
  /** True if we sent an `set_protocol_config(0)` ix to fix it up. */
  zeroed: boolean;
  /** L1 signature of the fix-up tx, when `zeroed === true`. */
  signature?: string;
}

/**
 * Read the live vault's protocol fee rate. If non-zero, send
 * `set_protocol_config(fee_rate_bps=0)` (preserving the existing
 * `protocol_owner_commitment`).
 */
export async function ensureZeroProtocolFee(
  l1: Connection,
  vaultProgramId: PublicKey,
  admin: Keypair,
): Promise<EnsureZeroFeeOutcome> {
  const [vaultPda] = vaultConfigPda(vaultProgramId);
  const acct = await l1.getAccountInfo(vaultPda, "confirmed");
  if (!acct?.data) {
    throw new Error(`vault_config account not found at ${vaultPda.toBase58()}`);
  }
  const data = acct.data;
  if (data.length < FEE_RATE_BPS_OFFSET + 2) {
    throw new Error(
      `vault_config account too small (got ${data.length} bytes, need ≥ ${FEE_RATE_BPS_OFFSET + 2}). ` +
        "VaultConfig zero-copy layout may have drifted from this helper's offsets.",
    );
  }
  const observedFeeBps = data.readUInt16LE(FEE_RATE_BPS_OFFSET);
  if (observedFeeBps === 0) {
    return { observedFeeBps: 0, zeroed: false };
  }
  const protocolOwnerCommitment = new Uint8Array(
    data.subarray(
      PROTOCOL_OWNER_COMMITMENT_OFFSET,
      PROTOCOL_OWNER_COMMITMENT_OFFSET + 32,
    ),
  );
  const ix = buildSetProtocolConfigInstruction({
    programId: vaultProgramId,
    admin: admin.publicKey,
    protocolOwnerCommitment,
    feeRateBps: 0,
  });
  const sig = await sendAndConfirmTransaction(
    l1,
    new Transaction().add(ix),
    [admin],
    {
      commitment: "confirmed",
    },
  );
  return { observedFeeBps, zeroed: true, signature: sig };
}
