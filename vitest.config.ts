import { defineConfig } from "vitest/config";

// The "source" export condition points workspace packages at src, so tests
// run against current code without a build step.
export default defineConfig({
  resolve: { conditions: ["source"] },
  ssr: { resolve: { conditions: ["source"] } },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
  },
});
