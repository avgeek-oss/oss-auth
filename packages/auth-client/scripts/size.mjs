// The bundle-size budget, run by `pnpm verify` after the build: each entry
// point of dist, bundled and minified as an app's bundler would, then
// gzipped. `react` is the app's own; `./react` is measured without the core
// entry it shares with the app.
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { build } from "rolldown";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));

const entries = [
  { name: "@avgeek-oss/auth-client", input: "index.js", budget: 5 * 1024 },
  {
    name: "@avgeek-oss/auth-client/react",
    input: "react/index.js",
    budget: 3 * 1024,
    external: [/^react(\/|$)/, /\/index\.js$/],
  },
];

let failed = false;
for (const entry of entries) {
  const result = await build({
    input: `${dist}${entry.input}`,
    external: entry.external ?? [],
    write: false,
    logLevel: "silent",
    output: { format: "esm", minify: true },
  });
  const code = result.output
    .filter((chunk) => chunk.type === "chunk")
    .map((chunk) => chunk.code)
    .join("");
  if (/\bfrom\s*["']node:|import\(\s*["']node:/.test(code)) {
    process.stderr.write(`${entry.name} imports a node: module.\n`);
    failed = true;
  }
  const gzipped = gzipSync(code, { level: 9 }).length;
  const ok = gzipped <= entry.budget;
  if (!ok) failed = true;
  process.stdout.write(
    `${ok ? "ok  " : "FAIL"} ${entry.name}: ${code.length} B minified, ${gzipped} B gzipped (budget ${entry.budget} B)\n`,
  );
}
if (failed) process.exit(1);
