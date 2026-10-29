/**
 * The browser family and operating system a `User-Agent` header names,
 * without versions, such as `{ browser: "Firefox", os: "macOS" }`. Each is
 * `null` when not recognised.
 */
export interface UserAgentSummary {
  readonly browser: string | null;
  readonly os: string | null;
}

// Most specific first: Edge and Opera also say Chrome, Chrome says Safari,
// and an iPad may say Macintosh.
const BROWSERS: readonly (readonly [string, readonly string[]])[] = [
  ["Edge", ["Edg/", "EdgA/", "EdgiOS/"]],
  ["Opera", ["OPR/", "OPT/", "Opera"]],
  ["Samsung Internet", ["SamsungBrowser/"]],
  ["Vivaldi", ["Vivaldi/"]],
  ["Firefox", ["Firefox/", "FxiOS/"]],
  ["Chrome", ["CriOS/", "Chrome/", "Chromium/"]],
  ["Safari", ["Safari/"]],
];

const SYSTEMS: readonly (readonly [string, readonly string[]])[] = [
  ["iPadOS", ["iPad"]],
  ["iOS", ["iPhone", "iPod"]],
  ["Android", ["Android"]],
  ["ChromeOS", ["CrOS"]],
  ["Windows", ["Windows"]],
  ["macOS", ["Macintosh", "Mac OS X"]],
  ["Linux", ["Linux", "X11"]],
];

function first(
  header: string,
  table: readonly (readonly [string, readonly string[]])[],
): string | null {
  for (const [name, needles] of table)
    if (needles.some((needle) => header.includes(needle))) return name;
  return null;
}

/**
 * Summarises a `User-Agent` header as a browser family and an operating
 * system, for the sessions list. Only this summary is stored, never the
 * header. Plain substring checks on the first 512 characters, so a
 * client-written header costs linear time; anything unrecognised is
 * `null`.
 */
export function summarizeUserAgent(
  header: string | null | undefined,
): UserAgentSummary {
  if (typeof header !== "string") return { browser: null, os: null };
  const text = header.slice(0, 512);
  // Safari is only Safari when no other browser claimed the string and it
  // carries Safari's Version/ token.
  let browser = first(text, BROWSERS);
  if (browser === "Safari" && !text.includes("Version/")) browser = null;
  return { browser, os: first(text, SYSTEMS) };
}
