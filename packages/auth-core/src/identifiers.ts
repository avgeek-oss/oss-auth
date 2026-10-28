/**
 * True when `name` can be the auth schema: 1 to 63 bytes (Postgres truncates
 * longer names), no control characters, no surrounding spaces, and not in
 * the reserved `pg_` namespace. Any other character is allowed, because the
 * name is always quoted with {@link quoteIdent}.
 */
export function isValidSchemaName(name: string): boolean {
  return (
    name !== "" &&
    Buffer.byteLength(name) <= 63 &&
    name.trim() === name &&
    !/\p{Cc}/u.test(name) &&
    !name.toLowerCase().startsWith("pg_")
  );
}

/** Quotes a Postgres identifier: `my "schema"` becomes `"my ""schema"""`. */
export function quoteIdent(name: string): string {
  if (name === "" || name.includes("\u0000"))
    throw new TypeError("Identifiers must be non-empty and contain no NUL.");
  return `"${name.replaceAll('"', '""')}"`;
}
