/**
 * Attribute Anchor event logs to the program that emitted them.
 *
 * `Program data: <base64>` is the output of `sol_log_data`, which **any**
 * Solana program can call — Anchor's `emit!` is only a wrapper around it. A
 * transaction's `meta.logMessages` interleaves the logs of every program it
 * invokes, so a decoder that scans for the prefix and dispatches on an event
 * discriminator is reading an open channel, not the vault's.
 *
 * Solana brackets every invocation: `Program <id> invoke [n]` opens a frame and
 * `Program <id> success` / `failed` closes it, at any CPI depth. Replaying those
 * lines reconstructs which program emitted each event.
 *
 * ## Why the SDK bothers
 *
 * The enclave's Merkle-mirror sync had this same unscoped decode, where it was a
 * Critical: anyone could forge a leaf into the shared mirror and halt the venue.
 * Client-side the blast radius is far smaller and structurally so — the SDK
 * reads logs of its **own just-submitted transaction**, so the realistic
 * attacker is a hostile RPC returning fabricated `logMessages`, and a forged
 * `leaf_index` only makes the client's own note look unspendable (the Merkle
 * path will not fold to a root containing the commitment, so VALID_SPEND fails
 * to prove). It fails closed, is self-inflicted, and is recoverable by pointing
 * at an honest RPC.
 *
 * It is fixed anyway for one reason: closing an unscoped decoder in Rust while
 * leaving the identical construction in TypeScript is how a defect survives its
 * own remediation. `chain-history.ts` already scopes *instruction* data by
 * `programId` one function away from where the log decode did not.
 */

const PROGRAM_DATA_PREFIX = "Program data: ";

/**
 * The `Program data:` payloads emitted by `programId` in this transaction, in
 * log order, base64-decoded. Events from any other program — top-level or
 * nested under `programId` via CPI — are dropped.
 *
 * Fails closed: an event with no enclosing frame (truncated or malformed logs)
 * is not returned. Missing a leaf index is a recoverable error the caller
 * already handles; acting on a forged one is not.
 *
 * `programId` is the base58 address, matching how it appears in the log lines.
 */
export function programEventPayloads(
  logs: readonly string[],
  programId: string,
): Buffer[] {
  const stack: string[] = [];
  const out: Buffer[] = [];

  for (const line of logs) {
    if (line.startsWith(PROGRAM_DATA_PREFIX)) {
      if (stack[stack.length - 1] !== programId) continue;
      try {
        out.push(
          Buffer.from(line.slice(PROGRAM_DATA_PREFIX.length).trim(), "base64"),
        );
      } catch {
        // Undecodable payload — skip, same as any unrecognised line.
      }
      continue;
    }
    // `Program log:` / `Program return:` carry program-controlled TEXT. They are
    // discarded before the scope patterns so a `msg!("Program <vault> invoke
    // [1]")` cannot open a frame it does not own.
    if (line.startsWith("Program log:") || line.startsWith("Program return:")) {
      continue;
    }
    if (!line.startsWith("Program ")) continue;
    const rest = line.slice("Program ".length);
    // `Program failed to complete: …` aborts the innermost program and is the
    // one exit line carrying no program id.
    if (rest.startsWith("failed to complete")) {
      stack.pop();
      continue;
    }
    const sep = rest.indexOf(" ");
    if (sep < 0) continue;
    const id = rest.slice(0, sep);
    const tail = rest.slice(sep + 1);
    if (tail.startsWith("invoke [")) {
      stack.push(id);
    } else if (tail === "success" || tail.startsWith("failed")) {
      stack.pop();
    }
    // Anything else (`consumed N of M compute units`, `Log truncated`) leaves
    // the stack alone.
  }

  return out;
}
