import * as circomlibjs from "circomlibjs";

const DEPTH = 20;

const strings = (values) => values.map(String);

async function merkleFixtures(hash, leaves) {
  const zeroRoots = [];
  let zero = 0n;
  for (let depth = 0; depth < DEPTH; depth += 1) {
    zeroRoots.push(zero);
    zero = hash(zero, zero);
  }

  const paddedSize = 1 << Math.max(1, Math.ceil(Math.log2(leaves.length)));
  let level = [...leaves];
  while (level.length < paddedSize) level.push(0n);

  const paths = leaves.map(() => ({ elements: [], indices: [] }));
  let indices = leaves.map((_, index) => index);
  let depth = 0;
  while (level.length > 1) {
    for (let leaf = 0; leaf < leaves.length; leaf += 1) {
      const index = indices[leaf];
      paths[leaf].elements.push(level[index ^ 1]);
      paths[leaf].indices.push(index & 1);
      indices[leaf] >>= 1;
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hash(level[i], level[i + 1]));
    }
    level = next;
    depth += 1;
  }

  let root = level[0];
  while (depth < DEPTH) {
    for (const path of paths) {
      path.elements.push(zeroRoots[depth]);
      path.indices.push(0);
    }
    root = hash(root, zeroRoots[depth]);
    depth += 1;
  }
  return { root, paths };
}

/** One deterministic corpus shared byte-for-byte by every benchmark backend. */
export async function buildFixtures() {
  const poseidon = await circomlibjs.buildPoseidon();
  const fr = (value) => BigInt(poseidon.F.toObject(value));
  const hash = (...values) => fr(poseidon(values));

  const spendingKey = 12345678901234567890n;
  const mint = [
    0x00112233445566778899aabbccddeeffn,
    0xffeeddccbbaa99887766554433221100n,
  ];
  const amounts = [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n];
  const innerHashes = [701n, 702n, 703n, 704n];
  const owner = hash(32n, spendingKey);
  const commitments = amounts.map((amount, index) =>
    hash(2n, mint[0], mint[1], amount, owner, innerHashes[index]),
  );
  const useTags = commitments.map((commitment, index) =>
    hash(29n, commitment, innerHashes[index]),
  );
  const tree = await merkleFixtures(hash, commitments);

  const recoveryNonce = 112233445566778899n;
  const noteSecret = 998877665544332211n;
  const depositInner = hash(33n, recoveryNonce, noteSecret);
  const depositAmount = 5_015_000n;
  const depositCommitment = hash(
    2n,
    mint[0],
    mint[1],
    depositAmount,
    owner,
    depositInner,
  );

  const path = (index) => ({
    merklePath: strings(tree.paths[index].elements),
    merkleIndices: strings(tree.paths[index].indices),
  });
  const commonNote = (index) => ({
    merkleRoot: String(tree.root),
    tokenMint: strings(mint),
    amount: String(amounts[index]),
    spendingKey: String(spendingKey),
    innerHash: String(innerHashes[index]),
    ...path(index),
  });

  const merge = (k) => {
    const active = Array.from({ length: k }, (_, index) => index < k);
    const masked = innerHashes.slice(0, k);
    while (masked.length < 4) masked.push(0n);
    const bitmap = (1n << BigInt(k)) - 1n;
    const outputAmount = amounts.slice(0, k).reduce((sum, x) => sum + x, 0n);
    const outputInner = hash(34n, ...masked, bitmap);
    const outputCommitment = hash(
      2n,
      mint[0],
      mint[1],
      outputAmount,
      owner,
      outputInner,
    );
    return {
      input: {
        merkleRoot: String(tree.root),
        tokenMint: strings(mint),
        spendingKey: String(spendingKey),
        isActive: active.map((value) => (value ? "1" : "0")),
        amount: strings(amounts.slice(0, k)),
        innerHash: strings(innerHashes.slice(0, k)),
        merklePath: tree.paths
          .slice(0, k)
          .map((entry) => strings(entry.elements)),
        merkleIndices: tree.paths
          .slice(0, k)
          .map((entry) => strings(entry.indices)),
      },
      expectedPublic: strings([
        outputCommitment,
        ...useTags.slice(0, k),
        tree.root,
        ...mint,
      ]),
    };
  };

  const recipient = [
    0x1234567890abcdef1234567890abcdefn,
    0xfedcba0987654321fedcba0987654321n,
  ];

  return {
    deposit: {
      input: {
        noteCommitment: String(depositCommitment),
        tokenMint: strings(mint),
        amount: String(depositAmount),
        recoveryNonce: String(recoveryNonce),
        spendingKey: String(spendingKey),
        noteSecret: String(noteSecret),
      },
      expectedPublic: strings([
        depositCommitment,
        ...mint,
        depositAmount,
        recoveryNonce,
      ]),
    },
    input: {
      input: { ...commonNote(0), noteUseTag: String(useTags[0]) },
      expectedPublic: strings([tree.root, useTags[0], ...mint]),
    },
    spend: {
      input: {
        ...commonNote(0),
        recipient: strings(recipient),
      },
      expectedPublic: strings([
        useTags[0],
        tree.root,
        ...mint,
        amounts[0],
        ...recipient,
      ]),
    },
    merge_k2: merge(2),
    merge_k4: merge(4),
  };
}
