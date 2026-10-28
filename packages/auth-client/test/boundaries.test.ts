import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src");

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(dir, entry.name))
      : entry.name.endsWith(".ts")
        ? [join(dir, entry.name)]
        : [],
  );
}

/** Every module specifier a file imports or re-exports, type-only included. */
function specifiers(file: string): string[] {
  const text = readFileSync(file, "utf8");
  return [
    ...text.matchAll(
      /^\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"|^\s*import\s+"([^"]+)"|\bimport\(\s*"([^"]+)"\s*\)/gm,
    ),
  ].map((match) => match[1] ?? match[2] ?? match[3] ?? "");
}

describe("auth-client stays browser-safe", () => {
  it("imports nothing but its own files and, from ./react only, react", () => {
    const outside = files(src).flatMap((file) =>
      specifiers(file)
        .filter((specifier) => !specifier.startsWith("."))
        .map((specifier) => `${relative(src, file)}: ${specifier}`),
    );
    expect(outside).toEqual(["react/index.ts: react"]);
    // The walk itself works.
    expect(specifiers(join(src, "index.ts"))).toContain("./client.js");
  });

  it("uses no Node globals", () => {
    for (const file of files(src))
      expect(readFileSync(file, "utf8"), relative(src, file)).not.toMatch(
        /\b(process|Buffer|require|__dirname|global)\b[.(]/,
      );
  });

  it("has no runtime dependencies, and react only as an optional peer", () => {
    const manifest = JSON.parse(
      readFileSync(join(root, "package.json"), "utf8"),
    ) as {
      dependencies?: unknown;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
      version: string;
    };
    expect(manifest.dependencies).toBeUndefined();
    expect(Object.keys(manifest.peerDependencies ?? {})).toEqual(["react"]);
    expect(manifest.peerDependenciesMeta?.react?.optional).toBe(true);
    const core = JSON.parse(
      readFileSync(join(root, "../auth-core/package.json"), "utf8"),
    ) as { version: string };
    // Versioned together with auth-core.
    expect(manifest.version).toBe(core.version);
  });
});
