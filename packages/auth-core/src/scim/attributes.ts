import { normaliseAttribute } from "./filter.js";

/** Parsed `attributes` and `excludedAttributes` query parameters. */
export interface Projection {
  readonly attributes: readonly string[] | null;
  readonly excluded: readonly string[];
}

const ALWAYS = new Set(["schemas", "id"]);

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => normaliseAttribute(entry.trim()))
    .filter((entry) => entry !== "");
}

/** Reads `attributes` and `excludedAttributes`, as in RFC 7644 §3.9. */
export function projection(query: {
  attributes?: string | undefined;
  excludedAttributes?: string | undefined;
}): Projection {
  const attributes = list(query.attributes);
  return {
    attributes: attributes.length > 0 ? attributes : null,
    excluded: list(query.excludedAttributes),
  };
}

function pick(value: unknown, sub: readonly string[]): unknown {
  if (sub.length === 0 || typeof value !== "object" || value === null)
    return value;
  const keep = (item: unknown) => {
    if (typeof item !== "object" || item === null) return item;
    return Object.fromEntries(
      Object.entries(item).filter(([key]) => sub.includes(key.toLowerCase())),
    );
  };
  return Array.isArray(value) ? value.map(keep) : keep(value);
}

/**
 * Applies a projection to a resource. `schemas` and `id` are always kept.
 * With `attributes`, only the named attributes (and named sub-attributes,
 * such as `name.givenName`) remain; `excludedAttributes` then removes
 * attributes, such as `members` on a group.
 */
export function applyProjection(
  resource: Record<string, unknown>,
  { attributes, excluded }: Projection,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(resource)) {
    const name = key.toLowerCase();
    if (ALWAYS.has(name)) {
      out[key] = value;
      continue;
    }
    if (excluded.includes(name)) continue;
    if (attributes === null) {
      out[key] = value;
      continue;
    }
    const wanted = attributes.filter(
      (a) => a === name || a.startsWith(`${name}.`),
    );
    if (wanted.length === 0) continue;
    const whole = wanted.includes(name);
    out[key] = whole
      ? value
      : pick(
          value,
          wanted.map((a) => a.slice(name.length + 1)),
        );
  }
  return out;
}
