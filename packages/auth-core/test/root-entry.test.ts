import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const src = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

/**
 * Every module specifier `file` imports or re-exports, type-only ones
 * included, since those decide what the published declarations load.
 */
function specifiers(file: string): string[] {
  const text = readFileSync(file, "utf8");
  const found: string[] = [];
  for (const match of text.matchAll(
    /^\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"|^\s*import\s+"([^"]+)"/gm,
  ))
    found.push(match[1] ?? match[2] ?? "");
  return found;
}

/** The bare (package) specifiers reachable from `entry` through relative imports. */
function packagesReachable(entry: string): Map<string, string> {
  const seen = new Set<string>();
  const packages = new Map<string, string>();
  const queue = [entry];
  for (let file = queue.pop(); file !== undefined; file = queue.pop()) {
    if (seen.has(file)) continue;
    seen.add(file);
    for (const specifier of specifiers(file)) {
      if (specifier.startsWith(".")) {
        queue.push(resolve(dirname(file), specifier.replace(/\.js$/, ".ts")));
      } else if (!packages.has(specifier)) {
        packages.set(specifier, file.slice(src.length + 1));
      }
    }
  }
  return packages;
}

describe("the root entry point", () => {
  it("loads no web framework, so its types check without Hono installed", () => {
    const packages = packagesReachable(resolve(src, "index.ts"));
    const framework = [...packages].filter(
      ([name]) =>
        name === "hono" ||
        name.startsWith("hono/") ||
        name.startsWith("@hono/"),
    );
    expect(framework).toEqual([]);
    // The walk itself works: config.ts's own dependency is found.
    expect(packages.has("zod")).toBe(true);
  });
});
