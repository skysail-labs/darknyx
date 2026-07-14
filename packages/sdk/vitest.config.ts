import { defineConfig } from "vitest/config";
import {
  DEVNET_GLOBS,
  CVM_GLOBS,
  LOCAL_INCLUDE,
  LOCAL_EXCLUDE,
} from "./tests/buckets";

// Three named projects (`--project local|devnet|cvm`) keyed off the
// `tests/buckets.ts` manifest. Bare `vitest run` runs all three; the
// devnet/cvm files self-skip (`describe.skip`) when their RUN_* env flag is
// absent, so running everything is still safe with no infra. `setup-env.ts`
// loads the .env secrets for every project. See tests/TESTS.md for the index.
const shared = {
  globals: false,
  testTimeout: 30_000,
  setupFiles: ["./tests/setup-env.ts"],
};

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          ...shared,
          name: "local",
          include: LOCAL_INCLUDE,
          exclude: LOCAL_EXCLUDE,
        },
      },
      {
        test: {
          ...shared,
          name: "devnet",
          include: DEVNET_GLOBS,
        },
      },
      {
        test: {
          ...shared,
          name: "cvm",
          include: CVM_GLOBS,
          // cvm tests drive ONE live CVM + share ONE on-chain Merkle tree, so
          // they must NOT race: run the files one at a time (within a file,
          // `it` is already serial). This makes a `--project cvm` bucket run
          // deterministic. It does NOT let the leaf-count tests share a tree —
          // each of those needs its OWN freshly-reset tree + a CVM cold-boot
          // (the mirror is append-only and can't rewind), so run them
          // individually. See docs/cvm-run-runbook.md §5 + CLAUDE.md §3.4.
          fileParallelism: false,
        },
      },
    ],
  },
});
