import { badRequest } from "./errors.js";

/** One `attribute eq "value"` comparison. */
export interface FilterCondition {
  /**
   * The attribute path, lowercased and without the core schema URN:
   * `username`, `emails.value`, `emails[type eq "work"].value`.
   */
  readonly path: string;
  readonly value: string;
}

type Token =
  | { kind: "word"; text: string }
  | { kind: "string"; text: string }
  | { kind: "lbracket" | "rbracket" | "lparen" | "rparen" };

const UNSUPPORTED_OPERATORS = new Set([
  "ne",
  "co",
  "sw",
  "ew",
  "pr",
  "gt",
  "ge",
  "lt",
  "le",
]);

function invalid(detail: string): never {
  throw badRequest(detail, "invalidFilter");
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i] ?? "";
    if (ch === " " || ch === "\t") {
      i++;
    } else if (ch === "[") {
      tokens.push({ kind: "lbracket" });
      i++;
    } else if (ch === "]") {
      tokens.push({ kind: "rbracket" });
      i++;
    } else if (ch === "(") {
      tokens.push({ kind: "lparen" });
      i++;
    } else if (ch === ")") {
      tokens.push({ kind: "rparen" });
      i++;
    } else if (ch === '"') {
      let j = i + 1;
      while (j < input.length && input[j] !== '"')
        j += input[j] === "\\" ? 2 : 1;
      if (j >= input.length) invalid("The filter has an unterminated string.");
      let text: unknown;
      try {
        text = JSON.parse(input.slice(i, j + 1));
      } catch {
        invalid("The filter has an invalid string.");
      }
      tokens.push({ kind: "string", text: text as string });
      i = j + 1;
    } else {
      let j = i;
      while (j < input.length && !' \t[]()"'.includes(input[j] ?? "")) j++;
      tokens.push({ kind: "word", text: input.slice(i, j) });
      i = j;
    }
  }
  return tokens;
}

const CORE_PREFIX = /^urn:ietf:params:scim:schemas:core:2\.0:(user|group):/i;

/** Lowercases an attribute name and strips the core schema URN. */
export function normaliseAttribute(name: string): string {
  return name.replace(CORE_PREFIX, "").toLowerCase();
}

/**
 * Parses the filters SCIM clients send for lookups: one or more
 * `attribute eq "value"` comparisons joined with `and`. The attribute may
 * have a sub-attribute (`emails.value`) or a value filter with an `eq`
 * inside (`emails[type eq "work"].value`).
 *
 * Every other operator, `or`, `not`, grouping and non-string values answer
 * 400 `invalidFilter`. Which attributes may be filtered on is up to the
 * resource.
 */
export function parseFilter(input: string): FilterCondition[] {
  if (input.length > 1024) invalid("The filter is too long.");
  const tokens = tokenize(input);
  let pos = 0;
  const next = () => tokens[pos++];
  const conditions: FilterCondition[] = [];

  const attributePath = (): string => {
    const head = next();
    if (head?.kind !== "word") invalid("Expected an attribute name.");
    if (head.text.toLowerCase() === "not") invalid("not is not supported.");
    let path = normaliseAttribute(head.text);
    if (!/^[a-z$][a-z0-9_$-]*(\.[a-z$][a-z0-9_$-]*)?$/.test(path))
      invalid(`"${head.text}" is not an attribute path.`);
    if (tokens[pos]?.kind === "lbracket") {
      pos++;
      const sub = next();
      const op = next();
      const value = next();
      const close = next();
      if (
        sub?.kind !== "word" ||
        op?.kind !== "word" ||
        op.text.toLowerCase() !== "eq" ||
        value?.kind !== "string" ||
        close?.kind !== "rbracket"
      )
        invalid('Value filters must look like emails[type eq "work"].');
      path += `[${normaliseAttribute(sub.text)} eq ${JSON.stringify(value.text)}]`;
      const after = tokens[pos];
      if (after?.kind === "word" && after.text.startsWith(".")) {
        pos++;
        path += after.text.toLowerCase();
      }
    }
    return path;
  };

  for (;;) {
    if (tokens[pos]?.kind === "lparen") invalid("Grouping is not supported.");
    const path = attributePath();
    const op = next();
    if (op?.kind !== "word") invalid("Expected an operator.");
    const operator = op.text.toLowerCase();
    if (UNSUPPORTED_OPERATORS.has(operator))
      invalid(`The ${operator} operator is not supported; use eq.`);
    if (operator !== "eq") invalid(`"${op.text}" is not an operator.`);
    const value = next();
    if (value?.kind !== "string")
      invalid("Filter values must be quoted strings.");
    conditions.push({ path, value: value.text });
    const joiner = next();
    if (joiner === undefined) return conditions;
    if (joiner.kind !== "word") invalid("Unexpected token in the filter.");
    const word = joiner.text.toLowerCase();
    if (word === "or") invalid("or is not supported; use and.");
    if (word !== "and") invalid(`Unexpected "${joiner.text}" in the filter.`);
    if (conditions.length >= 10) invalid("The filter has too many conditions.");
  }
}
