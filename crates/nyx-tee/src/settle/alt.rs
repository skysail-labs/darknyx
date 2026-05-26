//! Per-batch Address Lookup Table. Holds the 5 derivable PDAs
//! (note_lock_a/b/e/f + batch_validity_marker) so the settle tx
//! stays under 1232 B. See CRYPTOGRAPHY.md §9 + the gotcha about
//! `getLatestBlockhashAndContext().context.slot` vs `getSlot()`.
