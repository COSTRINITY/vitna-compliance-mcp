/**
 * The claim link never reaches the agent (0.5.2).
 *
 * Founder decision, 2026-10-05: "The claim link must never reach the agent.
 * Take it out of anything returned as a tool result, including the
 * trial-limit stop message, and show it only where a person looks."
 *
 * A claim link turns a trial into an account a person owns. Whoever opens it
 * first and finishes with GitHub or a passkey owns the account, its records
 * and its limits. If the agent being overseen holds the link, it can hand it
 * to anyone, paste it into a transcript, or try to claim its own oversight.
 * So 0.5.0 and 0.5.1, which put the link in tool results on purpose (the
 * CONNECTED notice, the reminder, vitna_claim, vitna_help and the guard's
 * trial-limit refusal), are reversed here.
 *
 * WHERE THE LINK GOES INSTEAD
 *   stderr, the channel an MCP server logs to. It is not part of the protocol,
 *   so it is never a tool result: a client shows or keeps it as the server's
 *   log (the MCP spec also lets a client ignore it, which is one reason for
 *   VITNA_OPEN_CLAIM). The link is
 *   written there when the trial is created and whenever a VITNA response
 *   carries one (an older server, or the setup link 0.5.1 kept in
 *   ~/.vitna/credentials.json, which 0.5.2 moves to the log and deletes).
 *   With VITNA_OPEN_CLAIM=1 the setup link is also opened in the default
 *   browser (see openCommand).
 *
 * WHAT THIS FILE DOES
 *   scrubValue / scrubText take every claim link and claim token out of what
 *   goes to the model, and return what they took so the caller can write it
 *   to stderr. A field named for the link (claim_url and its spellings) is
 *   set to null rather than deleted, so a client that reads the field still
 *   finds it. scrubForwardedLine does the same, more narrowly, for the output
 *   of a server the guard wraps.
 *
 * FIELD NAMES AS WELL AS VALUES
 *   A link or token can be the name of a field in JSON ({"<token>": 1}), and
 *   a name reaches the model as surely as a value does. So scrubValue and
 *   scrubForwardedLine scrub each field name the way they scrub a string
 *   value (scrubFieldNames). A name that loses a link or token can then read
 *   the same as another field's name; it gets " (2)", " (3)" and so on, so
 *   both values are kept and nothing is dropped. Until this was added, a
 *   name passed unchanged in guard mode and through the hosted /api/mcp
 *   route, and in normal mode two names that became the same were written
 *   twice into the result's text, where a client reading it keeps only one.
 *
 * PERCENT-ENCODED FORMS
 *   A link can arrive inside another value, percent-encoded: as the next= of
 *   a dashboard address, say, where /claim?owner= reads %2Fclaim%3Fowner%3D,
 *   or encoded twice (%252Fclaim%253Fowner%253D, the % itself becoming %25).
 *   Every pattern here reads each separator (: / ? =) as written or
 *   percent-encoded up to MAX_ENCODINGS times, and a token may start straight
 *   after an encoded byte (t%3Dv2...). The log gets the link decoded until it
 *   reads as a plain link.
 *
 * THE CURRENT TOKEN, WHEREVER IT STARTS
 *   A token of the shape VITNA mints today (v2.<13-digit ms>.<43-character
 *   mac>) is replaced wherever it starts: straight after a letter, a digit,
 *   - . or _, after quoted-printable (t=3Dv2...), and with its dots written
 *   as . or percent-encoded (v2%2E...%2E...). The older shapes keep a left
 *   boundary (TOKEN_START), and none is replaced when its mac runs straight
 *   on into another mac character, since it is then a longer string, not a
 *   token. The README's honest limits list what still passes.
 *
 *   Every scan here is linear in the length of the text: a link is found
 *   address by address (a run of characters an address can hold), never by a
 *   pattern that rescans the rest of the text from each https it meets, and
 *   a token pattern does a bounded amount of work at each place it is tried.
 */

/** What the model is told instead of the link, in every message that mentions claiming. */
export const CLAIM_LINK_IN_LOG = 'A person can claim this VITNA account with the claim link printed in the MCP server log when the trial started.';

/** What replaces a link or token found inside a string. */
export const WITHHELD = '[claim link withheld: it is in the MCP server log]';

/** Field names that carry a claim link or token. */
const CLAIM_FIELDS = new Set(['claim_url', 'claimurl', 'claim_link', 'claimlink', 'claim_token', 'claimtoken']);

/**
 * How many times over a percent-encoded separator is still read as one:
 * "/" is %2F encoded once, %252F twice, %25252F three times, and so on.
 */
export const MAX_ENCODINGS = 8;
const ENCODED = `%(?:25){0,${MAX_ENCODINGS - 1}}`;

/** One separator of a web address, as written or percent-encoded (see MAX_ENCODINGS). */
const sep = (literal: string, hex: string) => `(?:${literal}|${ENCODED}${hex})`;
const COLON = sep(':', '3A');
const SLASH = sep('\\/', '2F');
const QUESTION = sep('\\?', '3F');
const EQUALS = sep('=', '3D');

/** http:// or https://, each separator as written or encoded. */
const SCHEME = new RegExp(`https?${COLON}${SLASH}${SLASH}`, 'i');
/** The /claim? path of any claim link. */
const CLAIM_PATH = new RegExp(`${SLASH}claim${QUESTION}`, 'gi');
/** The /claim?owner= path of the link VITNA mints. */
const VITNA_CLAIM_PATH = new RegExp(`${SLASH}claim${QUESTION}owner${EQUALS}`, 'gi');

/**
 * A run of the characters a web address can hold, in text or JSON: anything
 * but space, quotes, angle brackets and backslash. A link ends where its run
 * ends.
 */
const ADDRESS_RUN = /[^\s"'<>\\]+/g;

/**
 * `text` with each claim link on `path` replaced by WITHHELD, and `onLink`
 * told each one. A claim link is the address that holds the claim path: from
 * the first http:// or https:// before the path in its run, or from the start
 * of the run when no scheme comes before it (a relative /claim?... or a host
 * written without one), to the end of the run. So a link inside another
 * address takes that whole address with it.
 */
function replaceLinks(text: string, path: RegExp, onLink: (link: string) => void): string {
  if (!/claim/i.test(text)) return text;
  return text.replace(ADDRESS_RUN, (run) => {
    if (!/claim/i.test(run)) return run;
    path.lastIndex = 0;
    const found = path.exec(run);
    if (!found) return run;
    const scheme = SCHEME.exec(run);
    const from = scheme && scheme.index + scheme[0].length <= found.index ? scheme.index : 0;
    onLink(run.slice(from));
    return run.slice(0, from) + WITHHELD;
  });
}

/**
 * Where an older-shape token can start: not inside a longer run of token
 * characters, or straight after a percent-encoded byte (t%3D17...,
 * t%253D17...). The current shape (VITNA_TOKEN) has no such boundary.
 */
const TOKEN_START = `(?:(?<![A-Za-z0-9_.-])|(?<=${ENCODED}[0-9A-Fa-f]{2}))`;

/**
 * A claim token on its own: v2 `v2.<issued ms>.<mac>` and v1 `<expiry ms>.<mac>`,
 * the mac being base64url SHA-256 (43 characters). See lib/claimToken.ts.
 * Used, with VITNA_TOKEN, for what goes to the model in normal mode and for
 * the guard's own messages.
 */
const TOKEN = new RegExp(`${TOKEN_START}(?:v2\\.)?\\d{12,14}\\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`, 'g');

/** A dot of the current token, as written or percent-encoded (see MAX_ENCODINGS). */
const DOT = sep('\\.', '2[Ee]');

/**
 * The token shape VITNA mints today, exactly: v2, a 13-digit time in
 * milliseconds and a 43-character mac, each dot as written or
 * percent-encoded. It is replaced wherever it starts, with no left boundary:
 * after a letter or digit (x...v2..., quoted-printable t=3Dv2...), after
 * - . or _, and after an encoded byte. It ends where its mac does: a mac
 * that runs on into another mac character is a longer string, not this
 * token. Linear: the pattern can only start at "v2", and the work at each
 * start is bounded (MAX_ENCODINGS per dot, 13 digits, 43 mac characters).
 *
 * Used alone, with VITNA_CLAIM_PATH, for a wrapped server's output, where
 * nothing else is ours to change. Not the v1 shape (<ms>.<mac>, without
 * v2.): that is too plain to tell apart from other identifiers a server may
 * print.
 */
const VITNA_TOKEN = new RegExp(`v2${DOT}\\d{13}${DOT}[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`, 'g');

/**
 * The first plain claim link in `s` (nothing encoded): from the nearest
 * http:// or https:// before a /claim? path, with no ? or # between them, to
 * the end of its run. Null when there is none. Linear: each backward scan
 * stops at the ? of the path before it.
 */
function plainLinkIn(s: string): string | null {
  for (const m of s.matchAll(/\/claim\?/gi)) {
    const at = m.index ?? 0;
    let from = at;
    while (from > 0 && !/[\s"'<>\\?#]/.test(s[from - 1]!)) from--;
    const scheme = s.slice(from, at).search(/https?:\/\//i);
    if (scheme < 0) continue;
    let to = at + m[0].length;
    while (to < s.length && !/[\s"'<>\\]/.test(s[to]!)) to++;
    return s.slice(from + scheme, to);
  }
  return null;
}

/**
 * The claim link a match holds, for the log: decoded (%XX to its character)
 * until a plain link appears, at most MAX_ENCODINGS times, so a person gets a
 * link they can open rather than the address it was encoded in. Null when
 * none appears (a relative path, which nobody can open as it is).
 */
function linkForLog(match: string): string | null {
  let s = match;
  for (let i = 0; i <= MAX_ENCODINGS; i++) {
    const plain = plainLinkIn(s);
    if (plain) return plain;
    const decoded = s.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
    if (decoded === s) break;
    s = decoded;
  }
  return null;
}

/**
 * The fields of one object with each name passed through `scrub`, which
 * returns a name unchanged when it holds no claim link or token. Returns
 * `entries` itself when no name changed.
 *
 * A name that changed and now reads the same as another field's name gets
 * " (2)", " (3)" and so on, the first number not already a field name, so
 * both values are kept. A name that did not change is never renamed, wherever
 * it comes in the object: the data it labels is not ours to rename.
 *
 * Linear: each changed name keeps its own next number, so no name that is
 * already taken is tried twice, and the work is at most one try per changed
 * field plus one per taken name.
 */
function scrubFieldNames(entries: Array<[string, unknown]>, scrub: (name: string) => string): Array<[string, unknown]> {
  const names = entries.map(([k]) => scrub(k));
  if (names.every((n, i) => n === entries[i]![0])) return entries;
  const taken = new Set<string>();
  names.forEach((n, i) => { if (n === entries[i]![0]) taken.add(n); });
  const next = new Map<string, number>();
  return entries.map(([k, v], i): [string, unknown] => {
    let name = names[i]!;
    if (name !== k && taken.has(name)) {
      let c = next.get(name) ?? 2;
      while (taken.has(`${name} (${c})`)) c++;
      next.set(name, c + 1);
      name = `${name} (${c})`;
    }
    taken.add(name);
    return [name, v];
  });
}

export interface Scrubbed<T> {
  value: T;
  /** Every claim link taken out, in order, without repeats. */
  links: string[];
  /** True when anything was taken out (a link, a token, or a claim field). */
  changed: boolean;
}

/** One string, with every claim link and token replaced by WITHHELD. */
export function scrubText(text: string): Scrubbed<string> {
  const links: string[] = [];
  let changed = false;
  const value = replaceLinks(text, CLAIM_PATH, (m) => {
    changed = true;
    const l = linkForLog(m);
    if (l && !links.includes(l)) links.push(l);
  }).replace(VITNA_TOKEN, () => { changed = true; return WITHHELD; })
    .replace(TOKEN, () => { changed = true; return WITHHELD; });
  return { value, links, changed };
}

/**
 * A copy of `input` with every claim link and token taken out, at any depth:
 * a claim field is set to null, a string has each link or token replaced, and
 * so does the name of a field (scrubFieldNames). Returns the input itself
 * when nothing was found.
 */
export function scrubValue<T>(input: T): Scrubbed<T> {
  const links: string[] = [];
  const note = (l: string) => { if (!links.includes(l)) links.push(l); };
  let changed = false;
  const scrubString = (s: string): string => {
    const r = scrubText(s);
    if (!r.changed) return s;
    changed = true;
    r.links.forEach(note);
    return r.value;
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return scrubString(v);
    if (Array.isArray(v)) {
      let any = false;
      const out = v.map((x) => { const y = walk(x); if (y !== x) any = true; return y; });
      return any ? out : v;
    }
    if (v && typeof v === 'object') {
      let any = false;
      const entries: Array<[string, unknown]> = [];
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (CLAIM_FIELDS.has(k.toLowerCase()) && x !== null && x !== undefined) {
          any = true;
          changed = true;
          if (typeof x === 'string') { const s = scrubText(x); s.links.forEach(note); if (!s.links.length && /^https?:\/\//i.test(x)) note(x); }
          entries.push([k, null]);
          continue;
        }
        const y = walk(x);
        if (y !== x) any = true;
        entries.push([k, y]);
      }
      const named = scrubFieldNames(entries, scrubString);
      // fromEntries, not out[k] = ...: a field named __proto__ stays a field.
      return any || named !== entries ? Object.fromEntries(named) : v;
    }
    return v;
  };
  const value = walk(input) as T;
  return { value, links, changed };
}

/**
 * A line that might hold a VITNA claim link or token: "claim" in any case
 * (percent-encoding leaves the letters as they are), "v2." or "v2%" (a token
 * with its dots written or encoded), or a JSON \u escape, which could spell
 * any of them. Any other line is passed on as it is, without being parsed.
 */
const MAYBE_CLAIM = /claim|v2[.%]|\\u/i;

/**
 * One line of a wrapped server's output, as the guard passes it to the
 * client: unchanged unless it holds a VITNA claim link (/claim?owner=, as
 * written or percent-encoded) or a token of the shape VITNA mints today
 * (v2.<13-digit ms>.<mac>, wherever it starts, dots written or encoded),
 * each replaced by WITHHELD, in a string value or in the name of a field
 * (scrubFieldNames). Nothing else in a wrapped server's output is touched:
 * another address on a /claim? path and a v1-shaped token (<ms>.<mac>) are
 * left alone.
 */
export function scrubForwardedLine(line: string): { line: string; withheld: number } {
  if (!MAYBE_CLAIM.test(line)) return { line, withheld: 0 };
  let n = 0;
  const scrub = (s: string) => replaceLinks(s, VITNA_CLAIM_PATH, () => { n++; })
    .replace(VITNA_TOKEN, () => { n++; return WITHHELD; });
  let msg: unknown;
  try { msg = JSON.parse(line); } catch {
    const out = scrub(line);
    return n ? { line: out, withheld: n } : { line, withheld: 0 };
  }
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return scrub(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const entries = Object.entries(v as Record<string, unknown>).map(([k, x]): [string, unknown] => [k, walk(x)]);
      return Object.fromEntries(scrubFieldNames(entries, scrub));
    }
    return v;
  };
  const out = walk(msg);
  return n ? { line: JSON.stringify(out), withheld: n } : { line, withheld: 0 };
}

/**
 * A link this process may hand to the operating system to open: https, a
 * /claim path, and only the characters VITNA's links use (an owner id and an
 * encoded token), so nothing in it can be read as a second argument or a
 * command. Everything else stays in the log only.
 */
export function isOpenableClaimLink(url: string): boolean {
  return /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/claim\?[A-Za-z0-9._~%&=-]{1,600}$/.test(url);
}

/**
 * How to open `url` in the default browser on `platform`, with no shell:
 * rundll32's URL handler on Windows (cmd's `start` would read the & in the
 * link as a second command), `open` on macOS, `xdg-open` elsewhere. Null when
 * the link is not one isOpenableClaimLink accepts.
 */
export function openCommand(platform: string, url: string): { command: string; args: string[] } | null {
  if (!isOpenableClaimLink(url)) return null;
  if (platform === 'win32') return { command: 'rundll32.exe', args: ['url.dll,FileProtocolHandler', url] };
  if (platform === 'darwin') return { command: 'open', args: [url] };
  return { command: 'xdg-open', args: [url] };
}

/**
 * What the guard writes to its log when a policy session on a trial key ends
 * (0.5.3). Trial keys get no signed bundle: closing a session needs a claimed
 * account. Until 0.5.3 the guard logged only "could not close session".
 * The claim link is the one this run received when it created the trial,
 * kept in memory only; without one, the person is pointed to the link the
 * log shows from when the trial started. Never sent to the agent.
 */
export function trialSessionEnd(sessionId: string, link: string | null): string[] {
  return [
    `[vitna-guard] Session ${sessionId} ended. Trial keys don't get a signed bundle: signed evidence is kept for claimed accounts only, so no bundle was saved.`,
    ...(link
      ? claimLinkForPerson(link, 'the session ended on a trial key')
      : [`[vitna-guard] ${CLAIM_LINK_IN_LOG} If it has expired, open it anyway: within 72 hours of the trial starting, the page offers a fresh link, once.`]),
  ];
}

/** The lines written to stderr for a person, around one claim link. */
export function claimLinkForPerson(url: string, why: string): string[] {
  return [
    '[vitna-compliance-mcp] ---------------------------------------------------------------',
    `[vitna-compliance-mcp] For the person who set up VITNA, not for the agent (${why}):`,
    '[vitna-compliance-mcp] open this link to claim the trial account. Claiming keeps signed evidence and lifts the trial limits.',
    `[vitna-compliance-mcp]   ${url}`,
    '[vitna-compliance-mcp] It works once, for 24 hours from when it was made. The agent is never sent this link.',
    '[vitna-compliance-mcp] If it has expired, open it anyway: within 72 hours of the trial starting, the page offers a fresh link, once.',
    '[vitna-compliance-mcp] ---------------------------------------------------------------',
  ];
}
