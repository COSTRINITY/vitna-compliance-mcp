/**
 * Guard mode: VITNA in the execution path.
 *
 *   npx @costrinity/vitna-compliance-mcp guard -- <command that starts an MCP server>
 *   e.g. ... guard -- npx -y @modelcontextprotocol/server-filesystem /data
 *
 * WHY THIS EXISTS
 *   Every other way of using VITNA is cooperative: the agent asks, VITNA
 *   answers, and the agent decides whether to listen. An agent that is wrong,
 *   or that skips the question, is not stopped by an answer it never read.
 *
 *   Guard mode is not cooperative. The MCP client talks to THIS process, and
 *   this process is the only route to the wrapped server. Every tools/call is
 *   sent to VITNA first and forwarded only when the decision is `allowed`.
 *   Everything else is answered with a tool error and never reaches the
 *   server. The model cannot skip the check, because the check is not a tool it
 *   chooses to call.
 *
 * TWO MODES
 *   Without a policy (as shipped in 0.4.0): each call goes to the preflight.
 *   With VITNA_GUARD_POLICY=<file.json> (0.5.0): the guard opens an engagement
 *   session with that scope policy and each call goes through it. That adds:
 *     - HOLD. A held call waits for a person, up to the policy's deadline, then
 *       forwards (approved) or is refused (denied or expired). While it waits
 *       the agent is told, in plain words, that it is held and until when; a
 *       silent deny makes an agent route around, a stated hold makes it wait.
 *     - BAIT, opt-in per policy. Honeytools are added to tools/list; a call to
 *       one is blocked, recorded and alerted. Honeytokens are added to
 *       config-shaped tool output; one coming back in any later call is
 *       blocked, recorded and alerted. The agent gets the same plain refusal
 *       as any other block: nothing tells it that it touched bait.
 *     - COVERAGE. The session records which surfaces were wrapped, which were
 *       declared unwrapped, and whether built-in tools were declared.
 *
 * FAIL CLOSED
 *   If VITNA cannot evaluate a call (unreachable, slow, key refused), or a hold
 *   cannot be read, the call is not forwarded. VITNA_GUARD_FAIL_OPEN=1 forwards
 *   instead when VITNA cannot be reached; every such call is logged to stderr.
 *   It never forwards a call VITNA answered with a block or a hold.
 *
 * WHAT IT DOES NOT COVER
 *   Containment is exactly as wide as the servers you wrap. A tool the agent
 *   reaches some other way (a built-in shell, an unwrapped server) is outside
 *   it. The checks are heuristic and policy-based: a call that stays inside the
 *   policy with plausible arguments is allowed, whatever its intent.
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';

export type GuardDecision = {
  decision: 'allowed' | 'blocked' | 'flagged' | 'held' | 'error';
  reason?: string;
  hold?: { hold_id: string; deadline: string };
};

export type BaitEvent = 'honeytool' | 'honeytoken';
export type HoldOutcome = 'approved' | 'denied' | 'expired' | 'error';

export interface HoneyTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface GuardDeps {
  /** Ask VITNA about one tool call. Must resolve, never reject. */
  preflight(action: string, payload: Record<string, unknown>, call: { name: string; meta?: unknown; bait?: BaitEvent }): Promise<GuardDecision>;
  /** Wait for a person to decide a hold (engagement mode). Must resolve. */
  waitForHold?(hold: { hold_id: string; deadline: string }, progress: (message: string) => void): Promise<HoldOutcome>;
  honeytools?: HoneyTool[];
  honeytokens?: HoneyTokens | null;
  failOpen: boolean;
  log(message: string): void;
  /** Runs once when the wrapped server exits (engagement mode closes its session). */
  onExit?(): Promise<void>;
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
export function makeHoneytokens(): HoneyTokens {
  const hex = (n: number) => randomBytes(n).toString('hex');
  const apiKey = `ak_live_${hex(16)}`;
  const password = randomBytes(12).toString('base64url');
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

// ── the gate ───────────────────────────────────────────────────────────────

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

function refusal(id: unknown, text: string): string {
  return JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } });
}

function blocked(name: string, reason?: string): string {
  // Bait reasons are never shown: the refusal for a honeytool or honeytoken is
  // the same plain block as any other. Warnings do not deter, and confirmation
  // tells a name-aware attacker what to route around.
  const why = reason && !/^honey/i.test(reason) ? ` Reason: ${reason}.` : '';
  return `VITNA guard blocked "${name}".${why} The call was not sent to the server. A person has to change the policy or run it themselves.`;
}

/**
 * Decide what happens to one line from the client. Returns the line to send to
 * the wrapped server, or the reply to send straight back to the client.
 * `notify` writes a message to the client while a call waits (progress).
 */
export async function gate(
  line: string,
  deps: GuardDeps,
  notify: (line: string) => void = () => {},
): Promise<{ forward: string } | { reply: string }> {
  let msg: { id?: unknown; method?: unknown; params?: { name?: unknown; arguments?: unknown; _meta?: { progressToken?: unknown } } };
  try {
    msg = JSON.parse(line);
  } catch {
    return { forward: line }; // not ours to judge; the server will reject it
  }
  if (msg.method !== 'tools/call' || msg.id === undefined) return { forward: line };

  const name = typeof msg.params?.name === 'string' ? msg.params.name : '';
  const args = msg.params?.arguments && typeof msg.params.arguments === 'object'
    ? (msg.params.arguments as Record<string, unknown>) : {};
  const text = actionText(name, args);

  // Bait: recorded and alerted by VITNA, refused here whatever VITNA says, and
  // never forwarded (the wrapped server does not have these tools anyway).
  const bait: BaitEvent | undefined = deps.honeytools?.some((t) => t.name === name) ? 'honeytool'
    : findHoneytoken(text, deps.honeytokens) ? 'honeytoken' : undefined;
  const d = await deps.preflight(text, args, { name, meta: msg.params?._meta, bait });
  if (bait) {
    deps.log(`${bait} triggered by "${name}"; refused and reported`);
    return { reply: refusal(msg.id, blocked(name)) };
  }

  if (d.decision === 'allowed') return { forward: line };

  if (d.decision === 'held' && d.hold && deps.waitForHold) {
    const until = d.hold.deadline;
    const token = msg.params?._meta?.progressToken;
    let step = 0;
    const progress = (message: string) => {
      if (token === undefined) return;
      notify(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: token, progress: ++step, message } }));
    };
    progress(`Held for human review until ${until}. A person decides; if nobody does, it is blocked.`);
    const outcome = await deps.waitForHold(d.hold, progress);
    if (outcome === 'approved') return { forward: line };
    const why = outcome === 'denied' ? 'A person denied it.'
      : outcome === 'expired' ? 'Nobody decided before the deadline, so it was blocked.'
        : 'The hold could not be read, so it was blocked.';
    return { reply: refusal(msg.id, `VITNA guard held "${name}" for human review until ${until}. ${why} The call was not sent to the server.`) };
  }

  if (d.decision === 'error' || d.decision === 'held') {
    if (d.decision === 'error' && deps.failOpen) {
      deps.log(`FAIL-OPEN: forwarded ${name} without a VITNA decision (${d.reason ?? 'no reason'})`);
      return { forward: line };
    }
    return {
      reply: refusal(msg.id, `VITNA guard did not run "${name}": VITNA could not evaluate it (${d.reason ?? 'unknown error'}), and an unchecked call is never forwarded. Nothing was sent to the server. Retry once VITNA is reachable.`),
    };
  }
  if (d.decision === 'flagged') {
    const why = d.reason ? ` Reason: ${d.reason}.` : '';
    return { reply: refusal(msg.id, `VITNA guard held "${name}": it was flagged for human review.${why} Held calls are not forwarded. A person has to approve and run it themselves.`) };
  }
  return { reply: refusal(msg.id, blocked(name, d.reason)) };
}

/**
 * Server -> client, for the responses the guard shapes: honeytools appended to
 * tools/list, honeytokens planted in config-shaped tools/call output.
 */
export function shapeServerLine(line: string, method: string | undefined, deps: Pick<GuardDeps, 'honeytools' | 'honeytokens'>): string {
  if (!method || (method !== 'tools/list' && method !== 'tools/call')) return line;
  if (method === 'tools/list' && !deps.honeytools?.length) return line;
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
    msg.result.tools = [...msg.result.tools, ...deps.honeytools!.filter((t) => !have.has(t.name))];
    return JSON.stringify(msg);
  }
  if (method === 'tools/call') {
    const planted = plantHoneytokens(msg.result, deps.honeytokens!);
    if (planted === msg.result) return line;
    return JSON.stringify({ ...msg, result: planted });
  }
  return line;
}

/** Wrap an MCP server. Resolves never; exits with the wrapped server. */
export function runGuard(command: string, commandArgs: string[], deps: GuardDeps): void {
  // No shell, except on Windows, where `npx` is npx.cmd and cannot be started
  // without one. There each argument is quoted here, because Node's shell mode
  // joins arguments unescaped (DEP0190).
  const stdio: ['pipe', 'pipe', 'inherit'] = ['pipe', 'pipe', 'inherit'];
  const quote = (a: string): string => (/^[\w@+=:,./\\-]+$/.test(a) ? a : `"${a.replace(/"/g, '""')}"`);
  const child = process.platform === 'win32'
    ? spawn([command, ...commandArgs].map(quote).join(' '), { stdio, shell: true })
    : spawn(command, commandArgs, { stdio });

  // Which method each request id was, so a response can be shaped by method.
  const methodById = new Map<string, string>();
  const out = (l: string) => process.stdout.write(l + '\n');

  // Server -> client, whole lines only, so a guard reply written in between can
  // never land in the middle of a server message.
  createInterface({ input: child.stdout! }).on('line', (l) => {
    let id: string | undefined;
    try { const m = JSON.parse(l); if (m && m.id !== undefined && m.method === undefined) id = JSON.stringify(m.id); } catch { /* pass through */ }
    const method = id ? methodById.get(id) : undefined;
    if (id) methodById.delete(id);
    out(shapeServerLine(l, method, deps));
  });

  // Client -> server. Each line is handled on its own: a call waiting minutes
  // on a hold must not stall every other call behind it. Lines that are not
  // tools/call resolve without awaiting anything, so they keep their order. A
  // cancellation that overtakes a call still being checked is harmless: the
  // server ignores an id it has not seen, and the client drops the late reply.
  const pending = new Set<Promise<void>>();
  createInterface({ input: process.stdin }).on('line', (line) => {
    if (!line.trim()) return;
    const p = gate(line, deps, out).then((res) => {
      if ('forward' in res) {
        try { const m = JSON.parse(res.forward); if (m && m.id !== undefined && typeof m.method === 'string') methodById.set(JSON.stringify(m.id), m.method); } catch { /* not JSON */ }
        child.stdin!.write(res.forward + '\n');
      } else out(res.reply);
    }).catch((e) => deps.log(`guard error: ${e instanceof Error ? e.message : String(e)}`))
      .finally(() => pending.delete(p));
    pending.add(p);
  }).on('close', () => { void Promise.allSettled([...pending]).then(() => child.stdin!.end()); });

  child.on('exit', (code) => {
    void Promise.resolve(deps.onExit?.()).catch(() => {}).finally(() => process.exit(code ?? 0));
  });
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => child.kill(sig));
}
