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
 * TRIAL LIMITS (0.5.1)
 *   A restricted trial key that hits a limit (daily, lifetime, its 72 hours,
 *   checks at the same time, the shared daily capacity, or a pause) gets a
 *   refusal from VITNA that names the limit and carries a fresh claim link.
 *   That is VITNA answering, not VITNA unreachable, so the call is refused
 *   (fail-open or not) and the agent is told which limit, that the call was
 *   not sent, and the claim link, so a person can claim the account. 0.5.0
 *   reported it as "could not evaluate ... Retry once VITNA is reachable" and
 *   dropped the link.
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
  /**
   * `closed`: the engagement session is closed and takes no new actions.
   * `limited`: a free trial limit refused the check (see `limit`).
   */
  decision: 'allowed' | 'blocked' | 'flagged' | 'held' | 'closed' | 'limited' | 'error';
  reason?: string;
  hold?: { hold_id: string; deadline: string };
  limit?: TrialLimit;
};

/** A check refused by a free trial limit, as VITNA reported it. */
export interface TrialLimit {
  /** The server's code, e.g. daily_cap_reached. */
  code: string;
  /** The server's own sentence about the limit, when it sent one. */
  message?: string;
  /** Where a person claims the account and lifts the limits. */
  claim_url?: string;
}

/**
 * The limits a restricted trial key can hit (lib/restrictedKey on the server),
 * each with the short name the refusal uses. metering_unavailable is not here:
 * that is VITNA failing, not a limit, and stays an error.
 */
export const TRIAL_LIMITS: Readonly<Record<string, string>> = {
  daily_cap_reached: 'daily check limit',
  lifetime_cap_reached: 'lifetime check limit',
  key_expired: 'the trial key has expired',
  too_many_concurrent: 'limit on checks at the same time',
  global_capacity_reached: "today's free trial capacity for all trial accounts",
  service_paused: 'free trial checks are paused',
};

/**
 * The trial limit in a VITNA refusal body, or null when the refusal is
 * something else. The server's message and claim link are kept only when
 * they are plain: a sentence of at most 300 characters, an http(s) URL.
 */
export function trialLimitFrom(body: unknown): TrialLimit | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  if (typeof b.error !== 'string' || !Object.prototype.hasOwnProperty.call(TRIAL_LIMITS, b.error)) return null;
  const limit: TrialLimit = { code: b.error };
  if (typeof b.message === 'string') {
    const m = b.message.replace(/\s+/g, ' ').trim();
    if (m) limit.message = m.length > 300 ? `${m.slice(0, 297)}...` : m;
  }
  if (typeof b.claim_url === 'string' && /^https?:\/\/[^\s"'<>]{1,500}$/i.test(b.claim_url)) limit.claim_url = b.claim_url;
  return limit;
}

/** What the agent is told when a trial limit refused the check. */
export function trialLimitRefusal(name: string, limit: TrialLimit): string {
  const which = TRIAL_LIMITS[limit.code] ?? 'a trial limit';
  const said = limit.message ? ` VITNA says: ${/[.!?]$/.test(limit.message) ? limit.message : `${limit.message}.`}` : '';
  // The link goes last, so no punctuation can be read as part of it.
  const claim = limit.claim_url
    ? ` To lift the trial limits, a person can claim this VITNA account. Give the user this claim link: ${limit.claim_url}`
    : ' To lift the trial limits, a person can claim this VITNA account with the claim link VITNA gave when the trial started.';
  return `VITNA guard did not run "${name}": the free VITNA trial limit was reached (${which}).${said} The call was not sent to the server.${claim}`;
}

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

// ── coverage ───────────────────────────────────────────────────────────────

/**
 * The name the session's coverage list gives the wrapped server. The name set
 * with VITNA_GUARD_NAME when there is one, else the file name of the command
 * that starts the server, without its folders or a .exe, .cmd, .bat or .js
 * extension: `npx`, `node`, `uvx`, `my-server`.
 *
 * Never a path and never an argument (0.5.1). 0.5.0 sent the first argument
 * that looked like a package, or the full command, either of which could be a
 * folder on the user's machine. A configured name keeps an npm scope
 * (`@scope/name`); any other folder part is dropped from it too.
 */
export function coverageLabel(configured: string | undefined, command: string | undefined): string {
  const fileName = (s: string): string => s.split(/[\\/]/).pop() ?? '';
  const name = (configured ?? '').trim();
  if (name) {
    const label = /^@[\w.-]+\/[\w.-]+$/.test(name) ? name : fileName(name).replace(/[^\w@.+-]/g, '_');
    if (label.replace(/[_.]/g, '')) return label.slice(0, 80);
  }
  const bare = fileName((command ?? '').trim())
    .replace(/\.(exe|cmd|bat|com|js|mjs|cjs)$/i, '')
    .replace(/[^\w.+-]/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 80);
  return bare.replace(/[_.]/g, '') ? bare : 'wrapped-server';
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
 * One VITNA call's result as index.ts's vitnaWithin reports it. A refusal by
 * a free trial limit carries `limit`.
 */
export type VitnaResult = { ok: true; value: Record<string, unknown> } | { ok: false; reason: string; limit?: TrialLimit };

/**
 * One POST /api/engagement/action answer as a GuardDecision (engagement mode).
 *
 * `session_closed` (409) is an answer, not an outage: the session was closed,
 * by this guard's exit or by a person through the API, and a closed session
 * takes no new actions. So it becomes `closed`, which gate() refuses like a
 * block and which fail-open never forwards. A trial limit is an answer too and
 * becomes `limited`. Every other refusal (unreachable, timed out, key refused)
 * stays `error`.
 */
export function engagementDecision(r: VitnaResult): GuardDecision {
  if (!r.ok) {
    if (r.limit) return { decision: 'limited', reason: r.limit.code, limit: r.limit };
    return r.reason === 'session_closed' ? { decision: 'closed', reason: 'session_closed' } : { decision: 'error', reason: r.reason };
  }
  const o = r.value;
  const reason = typeof o.reason === 'string' ? o.reason : undefined;
  if (o.decision === 'allow') return { decision: 'allowed', reason };
  if (o.decision === 'deny') return { decision: 'blocked', reason };
  const h = o.hold as { hold_id?: string; deadline?: string } | undefined;
  if (o.decision === 'hold' && h?.hold_id && h.deadline) return { decision: 'held', reason, hold: { hold_id: h.hold_id, deadline: h.deadline } };
  return { decision: 'error', reason: 'no decision in the response' };
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

  // Before the error branch on purpose: fail-open is for an unreachable
  // VITNA, and a trial limit or a closed session is VITNA answering.
  if (d.decision === 'limited') {
    const limit = d.limit ?? { code: d.reason ?? 'trial_limit' };
    deps.log(`free trial limit reached (${limit.code}): refused "${name}"; the refusal carries the claim link`);
    return { reply: refusal(msg.id, trialLimitRefusal(name, limit)) };
  }

  if (d.decision === 'closed') {
    return {
      reply: refusal(msg.id, `VITNA guard did not run "${name}": its engagement session is closed, and a closed session takes no new actions. Nothing was sent to the server. Restart the guard (restart your MCP client) to open a new session.`),
    };
  }

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

/** The id (as a map key) and method of a JSON-RPC request line, or null for anything else. */
function requestOf(line: string): { id: string; method: string } | null {
  try {
    const m = JSON.parse(line);
    if (m && m.id !== undefined && typeof m.method === 'string') return { id: JSON.stringify(m.id), method: m.method };
  } catch { /* not JSON */ }
  return null;
}

/**
 * How long a guard whose wrapped server failed waits for the client's first
 * request, so the client gets the error as an answer rather than a closed
 * pipe. MCP clients send initialize as soon as the process starts.
 */
export const FAILURE_GRACE_MS = 2000;

/** The JSON-RPC error a request gets once the wrapped server has failed. */
export function wrappedServerFailure(why: string): string {
  return `VITNA guard: the MCP server it wraps is not running (${why}), so this request was not answered. Check the command after "guard --".`;
}

/**
 * Wrap an MCP server. Resolves never; exits with the wrapped server.
 *
 * IF THE WRAPPED SERVER FAILS (0.5.1)
 *   A command that does not exist, or a server that exits or stops reading
 *   while the client is still talking to it. 0.5.0 could crash here: neither
 *   a spawn error nor the EPIPE from writing the client's initialize to a
 *   dead process had a handler.
 *   Now nothing more is forwarded. Every request the server had not answered,
 *   every request still being checked and every request that arrives later
 *   gets one JSON-RPC error saying so, and the guard exits non-zero, once it
 *   has answered a request, once the client closes its side, or after
 *   FAILURE_GRACE_MS. A request that arrives after the failure is never sent
 *   to VITNA either.
 */
export function runGuard(command: string, commandArgs: string[], deps: GuardDeps): void {
  // No shell, except on Windows, where `npx` is npx.cmd and cannot be started
  // without one. There each argument is quoted here, because Node's shell mode
  // joins arguments unescaped (DEP0190). Through the shell a missing command
  // is not a spawn error: the shell says so on stderr and exits non-zero.
  const stdio: ['pipe', 'pipe', 'inherit'] = ['pipe', 'pipe', 'inherit'];
  const quote = (a: string): string => (/^[\w@+=:,./\\-]+$/.test(a) ? a : `"${a.replace(/"/g, '""')}"`);
  const child = process.platform === 'win32'
    ? spawn([command, ...commandArgs].map(quote).join(' '), { stdio, shell: true })
    : spawn(command, commandArgs, { stdio });

  // Which method each request id was, so a response can be shaped by method.
  // An id stays here until the server answers it.
  const methodById = new Map<string, string>();
  const out = (l: string) => process.stdout.write(l + '\n');

  // ── the wrapped server failed (see the comment above) ──────────────────
  let failure: string | null = null;
  let failCode = 1;
  let clientClosed = false;
  let stopping = false; // a signal passed on to the server: its exit is expected
  let leaving = false;
  /** The requests being checked by gate(), one entry per line, so a failure can answer them too. */
  const checking = new Set<{ id: string }>();
  const replies: Promise<void>[] = [];
  const refuse = (id: string) => {
    const line = JSON.stringify({ jsonrpc: '2.0', id: JSON.parse(id), error: { code: -32603, message: failure } });
    replies.push(new Promise<void>((done) => { process.stdout.write(line + '\n', () => done()); }));
  };
  let graceTimer: ReturnType<typeof setTimeout> | undefined;
  /**
   * The one way out: flush the replies, run onExit (policy mode closes its
   * session), then exit with `code` by letting the event loop drain, with
   * process.exit as the fallback a second later. Not process.exit straight
   * after onExit: on Windows, Node 24 aborts with a libuv assertion (async.c,
   * UV_HANDLE_CLOSING) when process.exit runs just after a second fetch on a
   * kept-alive connection, which closing a policy session is, and the guard
   * then ended with 0xC0000409 instead of its exit code.
   */
  const leave = (code: number) => {
    if (leaving) return;
    leaving = true;
    clearTimeout(graceTimer);
    void Promise.allSettled(replies)
      .then(() => deps.onExit?.())
      .catch(() => {})
      .finally(() => {
        process.exitCode = code;
        process.stdin.destroy();
        child.stdin?.destroy();
        if (child.exitCode === null && child.signalCode === null) child.kill();
        setTimeout(() => process.exit(code), 1000).unref();
      });
  };
  const fail = (why: string, code = 1) => {
    if (failure !== null || leaving) return;
    failure = wrappedServerFailure(why);
    failCode = code > 0 ? code : 1;
    deps.log(`the wrapped server is not running (${why}); nothing more is forwarded, and each request is answered with an error`);
    for (const id of [...methodById.keys(), ...[...checking].map((c) => c.id)]) refuse(id);
    methodById.clear();
    checking.clear();
    if (replies.length || clientClosed) leave(failCode);
    else graceTimer = setTimeout(() => leave(failCode), FAILURE_GRACE_MS);
  };
  const named = JSON.stringify(command);
  child.on('error', (e: NodeJS.ErrnoException) => {
    fail(`could not start ${named}: ${e.code === 'ENOENT' ? 'command not found' : e.message}`);
  });
  child.stdin!.on('error', (e: NodeJS.ErrnoException) => {
    fail(`${named} stopped reading its input: ${e.code ?? e.message}`);
  });

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
    const req = requestOf(line);
    if (failure !== null) {
      // Nothing is forwarded or checked. A request is answered; anything else is dropped.
      if (req) { refuse(req.id); leave(failCode); }
      return;
    }
    const ticket = req ? { id: req.id } : null;
    if (ticket) checking.add(ticket);
    const p = gate(line, deps, out).then((res) => {
      // After a failure, fail() has already answered this request.
      if (ticket && !checking.delete(ticket)) return;
      if (failure !== null) return;
      if ('forward' in res) {
        if (req) methodById.set(req.id, req.method);
        child.stdin!.write(res.forward + '\n');
      } else out(res.reply);
    }).catch((e) => deps.log(`guard error: ${e instanceof Error ? e.message : String(e)}`))
      .finally(() => pending.delete(p));
    pending.add(p);
  }).on('close', () => {
    clientClosed = true;
    if (failure !== null) { leave(failCode); return; }
    void Promise.allSettled([...pending]).then(() => { if (failure === null) child.stdin!.end(); });
  });

  child.on('exit', (code, signal) => {
    // Gone while the client is still talking to it, owing an answer or with a
    // failing exit code: the client is told, not left waiting on a dead pipe.
    if (!clientClosed && !stopping && (methodById.size > 0 || checking.size > 0 || code !== 0)) {
      fail(`${named} exited ${signal ? `on ${signal}` : `with code ${code}`}`, code ?? 1);
      return;
    }
    if (failure === null) leave(code ?? 0);
  });
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { stopping = true; child.kill(sig); });
}
