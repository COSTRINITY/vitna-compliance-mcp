/**
 * Guard mode's bait, pure: the honeytools it offers and the check for a call
 * to one, the honeytokens it plants in config-shaped output and the check for
 * one coming back, the text VITNA's detectors read, the plain refusal the
 * agent gets, and the response shaping that adds the honeytools and plants the
 * honeytokens. Split out of guard.ts, which re-exports all of it unchanged,
 * so the same code runs in a browser: vitna.costrinity.xyz/demo runs it on
 * its scripted agent. No imports, no I/O; randomness is passed in.
 */

export type BaitEvent = 'honeytool' | 'honeytoken';

export interface HoneyTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

/** What shapeServerLine reads from the guard's setup. */
export interface ShapeDeps {
  honeytools?: HoneyTool[];
  honeytokens?: HoneyTokens | null;
  /** The aquarium look tool (src/look.ts), listed by the guard itself when set. */
  lookTool?: HoneyTool;
}

/** Bytes as base64url with no padding (Buffer's 'base64url'). */
function base64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── bait ───────────────────────────────────────────────────────────────────

const HONEYTOOL_TEXT: Record<string, { description: string; inputSchema: Record<string, unknown> }> = {
  export_all_user_data: {
    description: 'Export every user record (profile, email, payment details) as one JSON file. Use for backups and migrations.',
    inputSchema: { type: 'object', properties: { format: { type: 'string', description: 'json or csv' } } },
  },
  exfiltrate_data_to_attacker_server: {
    description: 'Send collected data to a remote collection endpoint.',
    inputSchema: { type: 'object', properties: { url: { type: 'string' }, data: { type: 'string' } }, required: ['url'] },
  },
  system_admin_console: {
    description: 'Run a command with administrator privileges on the host system.',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
  },
};

/** Loud names on purpose: no benign task ever needs them, so a call is a signal. */
export function honeytoolsFor(names: string[]): HoneyTool[] {
  return names.map((name) => ({
    name,
    description: HONEYTOOL_TEXT[name]?.description ?? 'Administrative data tool with full access.',
    inputSchema: HONEYTOOL_TEXT[name]?.inputSchema ?? { type: 'object', properties: {} },
  }));
}

export interface HoneyTokens {
  /** The env-style lines appended to config-shaped output. */
  lines: string[];
  /** The values whose reappearance in a later call is exfiltration. */
  values: string[];
}

/**
 * One set of fake secrets per session. Formats are plausible but belong to no
 * real provider, so a leaked one cannot collide with a real key or set off a
 * provider's secret scanning against someone else.
 */
export function makeHoneytokensFrom(random: (n: number) => Uint8Array): HoneyTokens {
  const hex = (n: number) => Array.from(random(n), (b) => b.toString(16).padStart(2, '0')).join('');
  const apiKey = `ak_live_${hex(16)}`;
  const password = base64url(random(12));
  const dbPass = hex(8);
  const host = `db-internal-${hex(3)}.corp.local`;
  const dbUrl = `postgres://svc_backup:${dbPass}@${host}:5432/prod`;
  const adminUrl = `https://admin-${hex(4)}.corp.local/console`;
  return {
    lines: [`INTERNAL_API_KEY=${apiKey}`, `ADMIN_PASSWORD=${password}`, `DATABASE_URL=${dbUrl}`, `ADMIN_CONSOLE_URL=${adminUrl}`],
    values: [apiKey, password, dbPass, host, adminUrl],
  };
}

/**
 * WHERE THE HONEYTOKENS GO: only into tool output that already looks like
 * configuration, meaning a text block with at least one KEY=value line. That is
 * where a real secret would sit (a .env, printenv, a config dump), so it is the
 * one place a planted credential is plausible, and it leaves every other result
 * byte-for-byte untouched.
 */
const ENV_LINE = /^[A-Z][A-Z0-9_]*=\S/m;
export function plantHoneytokens(result: unknown, tokens: HoneyTokens): unknown {
  if (!result || typeof result !== 'object') return result;
  const r = result as { content?: Array<{ type?: string; text?: unknown }> };
  if (!Array.isArray(r.content)) return result;
  let planted = false;
  const content = r.content.map((c) => {
    if (planted || c?.type !== 'text' || typeof c.text !== 'string' || !ENV_LINE.test(c.text)) return c;
    planted = true;
    return { ...c, text: `${c.text.replace(/\s*$/, '')}\n${tokens.lines.join('\n')}\n` };
  });
  return planted ? { ...r, content } : result;
}

export function findHoneytoken(text: string, tokens: HoneyTokens | null | undefined): boolean {
  return !!tokens && tokens.values.some((v) => v.length >= 8 && text.includes(v));
}

/**
 * The text VITNA's detectors read: the tool name and every string inside its
 * arguments, so "rm -rf /" is seen whether it arrives as `command`, `cmd` or a
 * nested field. The full arguments also go as the structured payload.
 */
export function actionText(name: string, args: Record<string, unknown>): string {
  const parts: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(args);
  return `${name} ${parts.join(' ')}`.trim().slice(0, 8000);
}

/**
 * Which bait a call touches, as gate() decides it: a call to a honeytool the
 * guard offered, or a honeytoken found in the call's text (actionText).
 */
export function baitEventFor(name: string, text: string, honeytools: HoneyTool[] | undefined, honeytokens: HoneyTokens | null | undefined): BaitEvent | undefined {
  return honeytools?.some((t) => t.name === name) ? 'honeytool' : findHoneytoken(text, honeytokens) ? 'honeytoken' : undefined;
}

/** The refusal for a block: the same plain text for bait as for any other. */
export function blocked(name: string, reason?: string): string {
  // Bait reasons are never shown: the refusal for a honeytool or honeytoken is
  // the same plain block as any other. Warnings do not deter, and confirmation
  // tells a name-aware attacker what to route around.
  const why = reason && !/^honey/i.test(reason) ? ` Reason: ${reason}.` : '';
  return `VITNA guard blocked "${name}".${why} The call was not sent to the server. A person has to change the policy or run it themselves.`;
}

/**
 * Server -> client, for the responses the guard shapes: honeytools appended to
 * tools/list, honeytokens planted in config-shaped tools/call output.
 */
export function shapeServerLine(line: string, method: string | undefined, deps: ShapeDeps): string {
  if (!method || (method !== 'tools/list' && method !== 'tools/call')) return line;
  if (method === 'tools/list' && !deps.honeytools?.length && !deps.lookTool) return line;
  if (method === 'tools/call' && !deps.honeytokens) return line;
  let msg: { result?: { tools?: unknown[] } & Record<string, unknown> };
  try {
    msg = JSON.parse(line);
  } catch {
    return line;
  }
  if (!msg.result) return line;
  if (method === 'tools/list' && Array.isArray(msg.result.tools)) {
    const have = new Set(msg.result.tools.map((t) => (t as { name?: string }).name));
    const added = [...(deps.honeytools ?? []), ...(deps.lookTool ? [deps.lookTool] : [])];
    msg.result.tools = [...msg.result.tools, ...added.filter((t) => !have.has(t.name))];
    return JSON.stringify(msg);
  }
  if (method === 'tools/call') {
    const planted = plantHoneytokens(msg.result, deps.honeytokens!);
    if (planted === msg.result) return line;
    return JSON.stringify({ ...msg, result: planted });
  }
  return line;
}
