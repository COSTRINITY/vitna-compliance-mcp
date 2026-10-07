/**
 * How long the guard may wait on a hold before the client may have given up
 * (0.5.4).
 *
 * A held call waits for a person for 30 to 3,600 seconds, but most MCP clients
 * give up on a tool call much sooner, and many send no cancel when they do.
 * If the guard forwarded a call after that, an approval would run an action
 * the agent no longer knows about. So the guard never forwards after the
 * client may have given up:
 *
 *   - It reads the client's name from its initialize request and waits at
 *     most that client's documented timeout, less a margin (waitBudgetMs).
 *     A client it does not know gets UNKNOWN_CLIENT_TIMEOUT_MS, below the
 *     shortest timeout in the table, so an unknown client is never waited on
 *     longer than any known one gives up after.
 *   - VITNA_GUARD_CLIENT_TIMEOUT_SECONDS overrides that for an operator who
 *     has raised the client's own timeout and knows the value.
 *   - A client that never times out is waited on at most GUARD_MAX_HOLD_MS
 *     (VITNA_GUARD_MAX_HOLD_SECONDS).
 *   - When the wait ends with the hold still open, the guard answers "held,
 *     not run" itself. The hold stays open in VITNA. If the owner approves,
 *     the same call (callHash: the tool and its canonical arguments) is
 *     forwarded once if the agent retries it within RETRY_AFTER_APPROVAL_MS of
 *     the approval. Expiry still blocks.
 *
 * The names in CLIENTS are UNPROVEN until a real client of that name is
 * tested: the guard logs the name and version each client sends, and the
 * setup table records which were tested. Timeouts are from each client's
 * documentation as read on 7 October 2026 (VITNA_everywhere_build_prompt.md).
 */
import { createHash } from 'node:crypto';

export interface ClientEntry {
  /** What the client calls itself in initialize's clientInfo.name, compared lower case. */
  names: string[];
  label: string;
  /** Its default tool-call timeout, or null when it never times out. */
  timeoutMs: number | null;
  /** True once a real client of this name was tested with the guard. */
  verified: boolean;
}

/**
 * Only names specific to one client: a short-timeout client sending a name
 * listed with a long timeout would be waited on too long. The generic "mcp"
 * (the Python SDK's default, used by several frameworks with different
 * timeouts) maps to the shortest of them.
 */
export const CLIENTS: readonly ClientEntry[] = [
  { names: ['mcp'], label: 'a client on the Python MCP SDK (OpenAI Agents, ADK, AutoGen, LlamaIndex, CrewAI, LangChain)', timeoutMs: 5_000, verified: false },
  { names: ['claude-ai'], label: 'Claude Desktop', timeoutMs: 240_000, verified: false },
  { names: ['visual studio code', 'visual studio code - insiders'], label: 'VS Code', timeoutMs: null, verified: false },
  { names: ['cursor-vscode'], label: 'Cursor', timeoutMs: 60_000, verified: false },
  { names: ['zed'], label: 'Zed', timeoutMs: 60_000, verified: false },
  { names: ['cline'], label: 'Cline', timeoutMs: 60_000, verified: false },
  { names: ['continue', 'continue-client'], label: 'Continue', timeoutMs: 60_000, verified: false },
  { names: ['mastra'], label: 'Mastra', timeoutMs: 60_000, verified: false },
  { names: ['n8n'], label: 'n8n', timeoutMs: 60_000, verified: false },
  { names: ['openclaw'], label: 'OpenClaw', timeoutMs: 60_000, verified: false },
];

/** The shortest timeout in CLIENTS: an unknown client is treated like the fastest known one (waited on 4 s, after the margin). */
export const UNKNOWN_CLIENT_TIMEOUT_MS = 5_000;
/** The longest a hold is waited on in place, for a client that never times out. */
export const GUARD_MAX_HOLD_MS = 600_000;
/** How long after an approval a retry of the same call is forwarded, once. */
export const RETRY_AFTER_APPROVAL_MS = 10 * 60_000;

export interface ClientProfile {
  name: string | null;
  label: string;
  /** The client's timeout, or null when it never times out. */
  timeoutMs: number | null;
  /** Where the timeout came from. */
  source: 'table' | 'override' | 'unknown';
}

function seconds(v: string | undefined): number | null {
  if (v === undefined || v.trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n * 1000) : null;
}

/** The profile for the clientInfo a client sent, with the operator's override applied. */
export function clientProfile(clientInfo: unknown, env: Record<string, string | undefined> = process.env): ClientProfile {
  const raw = clientInfo && typeof clientInfo === 'object' ? (clientInfo as { name?: unknown }).name : undefined;
  const name = typeof raw === 'string' ? raw.slice(0, 120) : null;
  const override = seconds(env.VITNA_GUARD_CLIENT_TIMEOUT_SECONDS);
  const entry = name ? CLIENTS.find((c) => c.names.includes(name.trim().toLowerCase())) : undefined;
  if (override !== null) return { name, label: entry?.label ?? name ?? 'unknown client', timeoutMs: override, source: 'override' };
  if (entry) return { name, label: entry.label, timeoutMs: entry.timeoutMs, source: 'table' };
  return { name, label: name ?? 'unknown client', timeoutMs: UNKNOWN_CLIENT_TIMEOUT_MS, source: 'unknown' };
}

/** The guard's own cap on a hold waited in place (VITNA_GUARD_MAX_HOLD_SECONDS, default GUARD_MAX_HOLD_MS). */
export function maxHoldMs(env: Record<string, string | undefined> = process.env): number {
  return seconds(env.VITNA_GUARD_MAX_HOLD_SECONDS) ?? GUARD_MAX_HOLD_MS;
}

/**
 * How long the guard waits for the decision in place: the client's timeout
 * less a margin (a fifth of it, at most 5 s), or the guard's maximum for a
 * client that never times out.
 */
export function waitBudgetMs(profile: ClientProfile, maxHold: number): number {
  if (profile.timeoutMs === null) return maxHold;
  const margin = Math.min(5_000, Math.floor(profile.timeoutMs / 5));
  return Math.max(0, Math.min(profile.timeoutMs - margin, maxHold));
}

/** JSON with object keys sorted at every level, so equal arguments hash equally. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/** The exact call an approval is bound to: the tool and its canonical arguments. */
export function callHash(name: string, args: unknown): string {
  return createHash('sha256').update(canonical({ name, args })).digest('hex');
}

/** What the agent is told when the wait ends with the hold still open. */
export function heldNotRun(name: string, until: string): string {
  const minutes = Math.round(RETRY_AFTER_APPROVAL_MS / 60_000);
  return `VITNA guard held "${name}" for human review until ${until}. Held, not run: the call was not sent to the server. Your owner can approve it. If they do, this same call will be allowed once if you retry it within ${minutes} minutes of the approval.`;
}
