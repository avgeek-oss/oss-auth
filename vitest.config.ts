import { defineConfig } from "vitest/config";

// The "@avgeek-oss/source" export condition points this repository's
// packages at src, so tests run against current code without a build step.
// It is scoped so that no dependency's own "source" export is picked up.
export default defineConfig({
  resolve: { conditions: ["@avgeek-oss/source"] },
  ssr: { resolve: { conditions: ["@avgeek-oss/source"] } },
  test: {
    include: ["packages/*/test/**/*.test.ts", "examples/*/test/**/*.test.ts"],
  },
});
