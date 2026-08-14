const MERKLE_DEPTH = 20;
const ROOT_HISTORY_SIZE = 64;
export const MERKLE_TREE_ACCOUNT_LEN = 2_744;
const CURRENT_ROOT_OFFSET = 16;
const ROOTS_RING_OFFSET = CURRENT_ROOT_OFFSET + 32;
const ROOTS_HEAD_OFFSET =
  ROOTS_RING_OFFSET + ROOT_HISTORY_SIZE * 32 + MERKLE_DEPTH * 32;
const TREE_ID_OFFSET = ROOTS_HEAD_OFFSET + 1;
const MERKLE_TREE_DISCRIMINATOR = Uint8Array.from([
  98, 51, 51, 226, 162, 20, 73, 212,
]);

export interface MerkleRootRingSnapshot {
  treeId: number;
  leafCount: bigint;
  /** Current root followed by retained historical roots, newest first. */
  acceptedRoots: Uint8Array[];
}

const isAllZero = (value: Uint8Array): boolean =>
  value.every((byte) => byte === 0);

/** Parse and validate the exact zero-copy `MerkleTree` account layout. */
export function parseMerkleRootRing(
  data: Uint8Array,
  treeId: number,
): MerkleRootRingSnapshot {
  if (!Number.isInteger(treeId) || treeId < 0 || treeId > 255) {
    throw new Error(`tree id must be a u8, got ${treeId}`);
  }
  if (data.length !== MERKLE_TREE_ACCOUNT_LEN) {
    throw new Error(
      `merkle tree shard ${treeId} account length must be ${MERKLE_TREE_ACCOUNT_LEN}, got ${data.length}`,
    );
  }
  if (
    !data
      .subarray(0, 8)
      .every((value, index) => value === MERKLE_TREE_DISCRIMINATOR[index])
  ) {
    throw new Error(`invalid MerkleTree discriminator for shard ${treeId}`);
  }
  if (data[TREE_ID_OFFSET] !== treeId) {
    throw new Error(
      `merkle tree PDA shard ${treeId} contains tree_id ${data[TREE_ID_OFFSET]}`,
    );
  }
  const currentRoot = Uint8Array.from(
    data.subarray(CURRENT_ROOT_OFFSET, CURRENT_ROOT_OFFSET + 32),
  );
  if (isAllZero(currentRoot)) {
    throw new Error(`merkle tree shard ${treeId} has an all-zero current root`);
  }
  const rootsHead = data[ROOTS_HEAD_OFFSET];
  if (rootsHead >= ROOT_HISTORY_SIZE) {
    throw new Error(
      `merkle tree shard ${treeId} roots_head out of range: ${rootsHead}`,
    );
  }
  const acceptedRoots = [currentRoot];
  for (let age = 0; age < ROOT_HISTORY_SIZE; age += 1) {
    const index =
      (rootsHead - 1 - age + ROOT_HISTORY_SIZE * 2) % ROOT_HISTORY_SIZE;
    const offset = ROOTS_RING_OFFSET + index * 32;
    const root = Uint8Array.from(data.subarray(offset, offset + 32));
    if (!isAllZero(root)) acceptedRoots.push(root);
  }
  return {
    treeId,
    leafCount: new DataView(
      data.buffer,
      data.byteOffset,
      data.byteLength,
    ).getBigUint64(8, true),
    acceptedRoots,
  };
}
