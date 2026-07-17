import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Resolve `@darknyx/sdk` to its TypeScript source (not the built `dist`) so daemon
// tests always run against the current SDK, no build step required. Vite
// rewrites the SDK's `.js` ESM imports to the matching `.ts` files.
export default defineConfig({
  resolve: {
    alias: {
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
