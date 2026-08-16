import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Resolve `@darknyx/sdk` to its TypeScript source (not the built `dist`) so daemon
// tests always run against the current SDK, no build step required. Vite
// rewrites the SDK's `.js` ESM imports to the matching `.ts` files.
export default defineConfig({
  resolve: {
    alias: {
      // Subpath aliases must precede the bare specifier: Vite matches these in
      // order, and a bare "@darknyx/sdk" entry would otherwise swallow
      // "@darknyx/sdk/transport-node" and resolve it as a path *under* index.ts.
      "@darknyx/sdk/transport-node": fileURLToPath(
        new URL("../sdk/src/transport-node.ts", import.meta.url),
      ),
      "@darknyx/sdk": fileURLToPath(
        new URL("../sdk/src/index.ts", import.meta.url),
      ),
    },
  },
  test: {
    globals: false,
    testTimeout: 30_000,
  },
});
