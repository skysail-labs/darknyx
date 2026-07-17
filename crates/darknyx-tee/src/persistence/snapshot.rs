//! Periodic bincode snapshots to the LUKS-mounted disk volume.
//! Atomic write-rename pattern. On boot: load latest snapshot then
//! replay deltas since `snapshot.timestamp`.
