#!/usr/bin/env node
/**
 * VITNA Compliance MCP server.
 *
 * Exposes VITNA's compliance fabric as MCP tools so LLM agents can:
 *   - Check if processing is allowed under any active consent
 *   - Classify whether an incident is reportable per jurisdiction
 *   - Classify an AI system under the EU AI Act
 *   - Validate identifiers (Aadhaar / CPF / SIN / etc.) with masking
 *   - Generate cross-border transfer notices
 *   - Look up sub-processor disclosures, US state laws, breach deadlines
 *   - Run DPIA + ROPA + SCC Annex II + privacy notice generators
 *
 * Why this exists
 *   Compliance lives in the operator's runtime, not their planning stage.
 *   An agent that's about to send a user record cross-border should be
 *   able to ASK whether that's allowed — at request time, not in a
 *   yearly DPIA. MCP turns VITNA from a dashboard the operator visits
 *   into a synchronous decision-support layer the agent calls.
 *
 *   GUARD MODE (src/guard.ts, `... guard -- <server>`) puts VITNA in the
 *   execution path of a wrapped MCP server. Otherwise, pair with
 *   `@costrinity/vigil-mcp` (the proxy/observer, not yet on npm) for
 *   coverage: the observer captures what the agent does, this server
 *   gives the agent compliance superpowers before it acts.
 *
 * Transport
 *   stdio JSON-RPC 2.0 — same as every other MCP server. Add to your
 *   client config:
 *
 *     {
 *       "mcpServers": {
 *         "vigil-compliance": {
 *           "command": "npx",
 *           "args": ["@costrinity/vitna-compliance-mcp"],
 *           "env": {
 *             "VITNA_OWNER_ID": "<your-owner-uuid>",
 *             "VITNA_API_KEY": "vigil_<your-key>",
 *             "VITNA_BASE_URL": "https://vitna.costrinity.xyz"
 *           }
 *         }
 *       }
 *     }
 *
 * Tool catalogue
 *   The MCP `tools/list` response enumerates each tool with its input
 *   schema. Keep the catalogue stable across versions; add new tools
 *   rather than mutating signatures.
 */

import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

// THE tool catalogue -- shared with the remote streamable-HTTP transport in
// the Next.js app (app/api/mcp/route.ts). This file owns the stdio TRANSPORT
// and credential handling; it deliberately declares no tools of its own, so
// the two transports cannot drift apart.
import { listedTools, resolveTool, SERVER_VERSION } from './tools.js';
import { runGuard, honeytoolsFor, makeHoneytokens, engagementDecision, coverageLabel, trialLimitFrom, type GuardDecision, type GuardDeps, type VitnaResult } from './guard.js';
import { scrubValue, claimLinkForPerson, openCommand, CLAIM_LINK_IN_LOG } from './claimLink.js';

// Env vars: VITNA_* is canonical. The old VIGIL_* names are accepted forever
// as aliases, so existing user configs never break.
const env = (name: string): string | undefined =>
  process.env['VITNA_' + name] ?? process.env['VIGIL_' + name];

const VITNA_BASE_URL = env('BASE_URL') ?? 'https://vitna.costrinity.xyz';
// let, not const: when absent, these are populated on first use by
// self-provisioning (a restricted trial key) or from the local cache.
let VITNA_OWNER_ID = env('OWNER_ID') ?? '';
let VITNA_API_KEY = env('API_KEY') ?? '';
// justProvisioned is true only on the single tool call that triggered
// self-provisioning, so the very first tool response can carry a plain-language
// connection notice the agent relays to the user. The claim link is never in
// it (0.5.2, src/claimLink.ts): this process keeps no copy of the link at all,
// it writes it to stderr and forgets it.
let justProvisioned = false;

const SERVER_NAME = 'vitna-compliance';
// SERVER_VERSION now lives in the shared catalogue (src/tools.ts) so the
// stdio and remote transports cannot announce different versions.


// ─── Self-provisioning (restricted trial key on first use) ─────────
//
// When VITNA_OWNER_ID / VITNA_API_KEY are not set, the first tool call
// provisions a RESTRICTED trial key via /api/setup and caches it locally.
// The claim link that comes back (a person claims the account with it,
// lifting the limits and unlocking signed evidence) goes to stderr only,
// where a person reads it, never into anything the agent is sent, and it is
// not cached (0.5.2, src/claimLink.ts). Explicit env credentials always win.
// Set VITNA_EMAIL to own the trial account under a real address; otherwise a
// throwaway is used.

const CRED_FILE = join(homedir(), '.vitna', 'credentials.json');

/** Writes `lines` to stderr, the MCP server log a person reads. Never to stdout. */
function toLog(lines: string[]): void {
  for (const l of lines) console.error(l);
}

/**
 * 0.5.1 also kept the setup claim link in ~/.vitna/credentials.json, and an
 * agent can read files. So the first time this process looks at that file, a
 * claim_url found there is written to the log and removed from the file,
 * which keeps everything else in it as it was. Once per process, and in
 * effect once: the next process finds no link to move.
 *
 * It runs whichever credentials this process uses, the cached ones or
 * VITNA_OWNER_ID / VITNA_API_KEY from the environment: a person who moved to
 * env credentials after 0.5.1 still has the link in the file. It takes only
 * claim_url out and writes the rest of the file back as it was; it does not
 * use the key in the file, and never reads, writes or changes the env
 * credentials.
 */
let legacyLinkChecked = false;
function moveLegacyClaimLink(): void {
  if (legacyLinkChecked) return;
  legacyLinkChecked = true;
  let c: unknown;
  try {
    c = JSON.parse(readFileSync(CRED_FILE, 'utf8'));
  } catch {
    return; // no file, or not one this version wrote
  }
  if (!c || typeof c !== 'object' || Array.isArray(c) || !('claim_url' in c)) return;
  const { claim_url: link, ...rest } = c as Record<string, unknown>;
  if (typeof link === 'string' && link) {
    toLog(claimLinkForPerson(link, 'saved by an earlier version in ~/.vitna/credentials.json, now removed from that file'));
  }
  saveCachedCreds(rest);
}

/** The cached key, after any claim link 0.5.1 left beside it has been moved out (moveLegacyClaimLink). */
function loadCachedCreds(): { owner_id: string; api_key: string } | null {
  moveLegacyClaimLink();
  try {
    const c = JSON.parse(readFileSync(CRED_FILE, 'utf8'));
    if (c && typeof c.owner_id === 'string' && typeof c.api_key === 'string' && c.owner_id && c.api_key) {
      return { owner_id: c.owner_id, api_key: c.api_key };
    }
  } catch {
    /* no cache yet */
  }
  return null;
}

function saveCachedCreds(c: Record<string, unknown>): void {
  try {
    mkdirSync(join(homedir(), '.vitna'), { recursive: true });
    writeFileSync(CRED_FILE, JSON.stringify(c, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error('[vitna-compliance-mcp] could not cache credentials:', e instanceof Error ? e.message : String(e));
  }
}

/**
 * VITNA_OPEN_CLAIM=1: open the setup claim link in the default browser too.
 * Off unless the person sets it in the MCP config, because this process is
 * often started where nobody is at the screen (a container, CI, a remote
 * machine), the first tool call that creates the trial is the agent's, and an
 * agent that drives the browser could read the page it opened. Only a link
 * openCommand accepts is opened, with no shell.
 */
function offerToOpen(url: string): void {
  if (env('OPEN_CLAIM') !== '1') {
    toLog(["[vitna-compliance-mcp] Set VITNA_OPEN_CLAIM=1 in this server's MCP config to have the claim link opened in your browser when a trial starts."]);
    return;
  }
  const how = openCommand(process.platform, url);
  if (!how) {
    toLog(['[vitna-compliance-mcp] VITNA_OPEN_CLAIM=1, but this link is not one this server opens (https, a /claim path, plain characters only). Copy it from above.']);
    return;
  }
  try {
    const child = spawn(how.command, how.args, { stdio: 'ignore', detached: true, windowsHide: true, shell: false });
    child.on('error', (e) => toLog([`[vitna-compliance-mcp] could not open the browser (${e.message}). Copy the link from above.`]));
    child.unref();
    toLog(['[vitna-compliance-mcp] Opened the claim link in your default browser.']);
  } catch (e) {
    toLog([`[vitna-compliance-mcp] could not open the browser (${e instanceof Error ? e.message : String(e)}). Copy the link from above.`]);
  }
}

/**
 * A claim link a VITNA response carried. Every response passes through here
 * (callVitna), and before 0.5.2 the server sent one with each trial-limit
 * refusal and with claim-status. Logged once per process, then dropped:
 * scrubValue takes it out of anything the agent is sent.
 */
let serverLinkLogged = false;
function logServerLinks(links: string[]): void {
  if (!links.length || serverLinkLogged) return;
  serverLinkLogged = true;
  toLog(claimLinkForPerson(links[0]!, 'a newer link VITNA sent with a response'));
}

// The agent name a trial is created with. Fixed: 0.5.0 and earlier appended
// the machine's hostname, which is often a person's name ("Daniels-MacBook-
// Pro") and stayed on the account. Each trial is a new owner with one agent,
// so the name does not need to tell machines apart. VITNA_AGENT_NAME still
// overrides it.
const TRIAL_AGENT_NAME = 'vitna-compliance-mcp';

async function provision(): Promise<void> {
  const owner_email = env('EMAIL') || `agent-${randomBytes(6).toString('hex')}@mcp.vitna.local`;
  const agent_name = env('AGENT_NAME') || TRIAL_AGENT_NAME;
  try {
    const res = await fetch(`${VITNA_BASE_URL}/api/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': `vitna-compliance-mcp/${SERVER_VERSION}` },
      body: JSON.stringify({ owner_email, agent_name }),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || typeof data.api_key !== 'string' || typeof data.owner_id !== 'string') {
      console.error(
        `[vitna-compliance-mcp] self-provision did not return a key (HTTP ${res.status}). ` +
          `${typeof data.error === 'string' ? data.error + '. ' : ''}` +
          'Set VITNA_OWNER_ID + VITNA_API_KEY manually, or VITNA_EMAIL to a fresh address.',
      );
      return;
    }
    VITNA_OWNER_ID = data.owner_id;
    VITNA_API_KEY = data.api_key;
    justProvisioned = true;
    // No claim_url in the cache: an agent can read this file (see loadCachedCreds).
    saveCachedCreds({ owner_id: VITNA_OWNER_ID, api_key: VITNA_API_KEY, base_url: VITNA_BASE_URL });
    console.error(`[vitna-compliance-mcp] provisioned a restricted trial key (owner ${VITNA_OWNER_ID}).`);
    if (typeof data.claim_url === 'string' && data.claim_url) {
      toLog(claimLinkForPerson(data.claim_url, 'the trial was just created'));
      offerToOpen(data.claim_url);
    } else {
      console.error('[vitna-compliance-mcp] VITNA sent no claim link with this trial.');
    }
  } catch (e) {
    console.error('[vitna-compliance-mcp] self-provision failed:', e instanceof Error ? e.message : String(e));
  }
}

// Memoized so /api/setup is called at most once even under concurrent tools.
let credsReady: Promise<void> | null = null;
function ensureCredentials(): Promise<void> {
  if (!credsReady) {
    credsReady = (async () => {
      if (VITNA_OWNER_ID && VITNA_API_KEY) {
        // Explicit env credentials win. A claim link 0.5.1 left in the
        // cache file is still moved to the log, and the file's key is not read.
        moveLegacyClaimLink();
        return;
      }
      const cached = loadCachedCreds();
      if (cached) {
        VITNA_OWNER_ID = cached.owner_id;
        VITNA_API_KEY = cached.api_key;
        return;
      }
      await provision();
    })();
  }
  return credsReady;
}

// ─── HTTP transport ────────────────────────────────────────────────

async function callVitna(method: string, path: string, body?: unknown): Promise<unknown> {
  await ensureCredentials();
  const url = `${VITNA_BASE_URL}${path}${path.includes('?') ? '&' : '?'}owner_id=${encodeURIComponent(VITNA_OWNER_ID)}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': `vitna-compliance-mcp/${SERVER_VERSION}`,
  };
  if (VITNA_API_KEY) {
    headers['Authorization'] = `Bearer ${VITNA_API_KEY}`;
    // Send both header forms: x-vitna-key is current, x-vigil-key keeps this
    // client working against any older self-hosted server that predates the
    // rename. The server accepts either.
    headers['x-vitna-key'] = VITNA_API_KEY;
    headers['x-vigil-key'] = VITNA_API_KEY;
  }
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { _raw: text, _status: res.status };
  }
  // Every VITNA answer passes here, so this is where a claim link in one is
  // moved to the log and taken out (0.5.2): nothing after this point, in
  // either mode, holds a link the agent could be sent.
  const { value, links } = scrubValue(parsed);
  logServerLinks(links);
  return value;
}

/**
 * Did the server refuse to evaluate this call? Returns the error code plus the
 * original body when so, null when the call produced a real decision.
 * Recognises both the API's error envelope and the raw-text fallback.
 */
function isRefusal(result: unknown): { code: string; body: unknown } | null {
  if (!result || typeof result !== 'object') return null;
  const r = result as Record<string, unknown>;
  if (typeof r.error === 'string') return { code: r.error, body: r };
  if (typeof r._status === 'number' && r._status >= 400) {
    return { code: `http_${r._status}`, body: r };
  }
  return null;
}


/* ── Unclaimed-account reminder ──────────────────────────────────────
 *
 * Until the account is claimed, nothing is durably recorded. The reminder
 * rides on governed tool results as its OWN text block, so the agent can tell
 * its person. It is never merged into the JSON: the structured verdict an
 * agent branches on must be byte-identical whether or not the account is
 * claimed, or we would be changing a safety decision to advertise.
 *
 * It carries no claim link (0.5.2). 0.5.0 and 0.5.1 put the link here, and in
 * the CONNECTED notice, so the agent would pass it on; the founder decided on
 * 2026-10-05 that the link must never reach the agent. It says where a person
 * finds the link instead: the MCP server log (src/claimLink.ts).
 *
 * CADENCE: the first 3 governed calls, then every 10th. The first few are
 * where an agent is still narrating setup to its human, so that is when it
 * gets relayed; the every-10th tail catches long-running sessions without the
 * line ever becoming most of the output. Once the account is claimed it stops
 * for good -- claimConfirmed latches.
 */
let governedCalls = 0;
let claimConfirmed = false;

/** Cheap check, run only when we are about to remind, so a claim that happened
 *  in another window silences this one within at most 10 calls. Failure to
 *  reach the API leaves the reminder on, which is the harmless direction. */
async function stillUnclaimed(): Promise<boolean> {
  if (claimConfirmed) return false;
  try {
    const r = await callVitna('GET', '/api/owners/claim-status');
    if (r && typeof r === 'object' && (r as Record<string, unknown>).claimed === true) {
      claimConfirmed = true;
      return false;
    }
  } catch { /* keep reminding */ }
  return true;
}

function reminderLine(): string {
  return `Unclaimed trial - this evidence is not being durably recorded until a person claims the account. ${CLAIM_LINK_IN_LOG}`;
}

/** One-time notice, in language the agent can relay to the user, emitted on the
 *  first tool response after self-provisioning. No claim link (see above). */
function connectionNotice(): string {
  return [
    'CONNECTED TO VITNA, a safety and compliance oversight layer, in TRIAL mode.',
    'You can now check risky actions BEFORE you run them: call vitna_preflight for shell / file / DB / network actions, or the compliance checks for data handling. Each returns an allow / deny / hold decision. Treat deny or hold as a stop and get human approval before proceeding.',
    'This trial key is rate-limited and does NOT keep signed audit evidence. To keep the audit records and raise the limits, a person has to claim this account.',
    CLAIM_LINK_IN_LOG,
    'You are not given that link, so do not look for it. Relay this to the user in your own words: they will find the link in the log of this MCP server, in their MCP client.',
  ].join(' ');
}

// ─── MCP JSON-RPC plumbing ──────────────────────────────────────────

interface JsonRpcReq {
  jsonrpc: '2.0';
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}
interface JsonRpcResp {
  jsonrpc: '2.0';
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/**
 * The one writer to stdout in normal mode, so the one place every message to
 * the client is checked: a claim link or token anywhere in it is moved to the
 * log and taken out (0.5.2). callVitna has already done this for VITNA's
 * answers; this catches anything else.
 */
function send(resp: JsonRpcResp): void {
  const { value, links } = scrubValue(resp);
  logServerLinks(links);
  process.stdout.write(JSON.stringify(value) + '\n');
}

function ok(id: number | string | null, result: unknown): void {
  send({ jsonrpc: '2.0', id, result });
}
function err(id: number | string | null, code: number, message: string, data?: unknown): void {
  send({ jsonrpc: '2.0', id, error: { code, message, data } });
}

async function handle(req: JsonRpcReq): Promise<void> {
  const id = req.id ?? null;
  try {
    switch (req.method) {
      case 'initialize':
        ok(id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        });
        return;

      case 'tools/list':
        ok(id, { tools: listedTools() });
        return;

      case 'tools/call': {
        const params = (req.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        // Hidden aliases from the VIGIL era. They are deliberately NOT listed in
        // tools/list (the catalogue advertises the vitna_* names only), but they
        // keep working forever so an agent with a cached config does not break.
        const tool = resolveTool(params.name ?? '');
        if (!tool) {
          err(id, -32602, `unknown tool: ${params.name}`);
          return;
        }
        let result: unknown;
        if (tool.local) {
          result = tool.local(params.arguments ?? {});
        } else if (tool.call) {
          const { method, path, body } = tool.call(params.arguments ?? {});
          result = await callVitna(method, path, body);
        } else {
          err(id, -32603, `tool ${tool.name} has no handler`);
          return;
        }
        // FAIL CLOSED. When the server refuses the check (expired trial key,
        // cap reached, paused, bad credentials) the reply carries an `error`
        // and NO `decision`. Agents are told "decision=allowed means proceed;
        // blocked or flagged means STOP", so an error used to leave them with
        // neither value and they would fall through and act. A guardrail that
        // cannot evaluate must read as STOP, so we synthesise a
        // machine-readable stop and set isError for clients that branch on it.
        const failedCheck = isRefusal(result);
        if (failedCheck && !tool.local) {
          result = {
            decision: 'blocked',
            effect: 'block',
            flagged: true,
            reason: `VITNA could not evaluate this action: ${failedCheck.code}`,
            enforced_by: 'caller',
            stop: true,
            note: 'This is a fail-closed stop, not a threat verdict. VITNA did not evaluate the action, so it must not be treated as allowed. Resolve the error below, then re-check.',
            ...(failedCheck.body as Record<string, unknown>),
          };
        }

        const content: Array<{ type: 'text'; text: string }> = [];
        // On the tool call that triggered self-provisioning, lead with a
        // plain-language connection notice the agent can relay to the user.
        const noticeShownThisCall = justProvisioned;
        if (justProvisioned) {
          justProvisioned = false;
          content.push({ type: 'text', text: connectionNotice() });
        }
        content.push({ type: 'text', text: JSON.stringify(result, null, 2) });

        // Appended AFTER the verdict, as a separate block, and only for
        // governed calls -- vitna_claim and vitna_help already talk about
        // claiming, so reminding on those would be noise. justProvisioned
        // already carried the full notice on this same response, so skip it
        // there rather than saying it twice.
        if (!tool.local && !noticeShownThisCall && !claimConfirmed) {
          governedCalls++;
          if (governedCalls <= 3 || governedCalls % 10 === 0) {
            if (await stillUnclaimed()) {
              content.push({ type: 'text', text: reminderLine() });
            }
          }
        }

        ok(id, failedCheck ? { content, isError: true } : { content });
        return;
      }

      case 'notifications/initialized':
        // Spec-required notification; no response.
        return;

      default:
        err(id, -32601, `method not found: ${req.method}`);
        return;
    }
  } catch (e) {
    err(id, -32603, e instanceof Error ? e.message : 'internal error');
  }
}

// ─── Guard mode (VITNA in the execution path; see src/guard.ts) ────

const GUARD_TIMEOUT_MS = 10_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A VITNA call that resolves within 10s or reports why not. Never rejects:
 *  a hung check must fail closed, not hang the agent's tool call forever. */
async function vitnaWithin(method: string, path: string, body?: unknown): Promise<VitnaResult> {
  // Cleared once the call settles, so a finished call does not hold the guard
  // open for 10 seconds when it exits.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ ok: false; reason: string }>((r) => { timer = setTimeout(() => r({ ok: false, reason: 'timed out after 10s' }), GUARD_TIMEOUT_MS); });
  const call = (async () => {
    try {
      const r = await callVitna(method, path, body);
      const refused = isRefusal(r);
      if (refused) {
        // A free trial limit keeps the server's message, so the refusal the
        // agent gets can name the limit. Not a claim link: callVitna already
        // moved any link in the answer to the log (0.5.2).
        const limit = trialLimitFrom(refused.body);
        return { ok: false as const, reason: refused.code, ...(limit ? { limit } : {}) };
      }
      return { ok: true as const, value: (r ?? {}) as Record<string, unknown> };
    } catch (e) {
      return { ok: false as const, reason: e instanceof Error ? e.message : String(e) };
    }
  })();
  return Promise.race([call, timeout]).finally(() => clearTimeout(timer));
}

/**
 * ACTIVATION NOTE (0.5.1). The guard tells VITNA once per process that guard
 * mode is in use and which mode, so VITNA can note it on the account (owner
 * metadata guard_activation: first seen, mode, client version). Default mode
 * adds one fixed field to the preflight body it already sends, on one call at
 * a time until a call carrying it comes back with a decision: calls made while
 * that call is in flight do not carry it, so concurrent first calls send it
 * once. Policy mode marks the session it opens with metadata.via. Nothing else
 * is added: no hostname, no path, no tool name. VITNA_GUARD_NO_ACTIVATION=1
 * sends neither; checks are unchanged.
 */
const GUARD_NO_ACTIVATION = env('GUARD_NO_ACTIVATION') === '1';
const DEFAULT_MODE_ACTIVATION = { activation: true, mode: 'default' } as const;
/** pending: the next call carries the field; sending: one call carrying it is in flight; done: one was evaluated (or opt-out). */
let activation: 'pending' | 'sending' | 'done' = GUARD_NO_ACTIVATION ? 'done' : 'pending';

/** Preflight mode (no policy), as shipped in 0.4.0, plus the activation note. */
async function guardPreflight(action: string, payload: Record<string, unknown>): Promise<GuardDecision> {
  const body: Record<string, unknown> = { action, payload, action_type: 'mcp_tool' };
  const announcing = activation === 'pending';
  if (announcing) {
    body.guard = DEFAULT_MODE_ACTIVATION;
    activation = 'sending';
  }
  const r = await vitnaWithin('POST', '/api/preflight/action-check', body);
  const evaluated = r.ok && (r.value.decision === 'allowed' || r.value.decision === 'blocked' || r.value.decision === 'flagged');
  // Not evaluated (unreachable, a trial limit, no decision): the next call carries it.
  if (announcing) activation = evaluated ? 'done' : 'pending';
  if (!r.ok) return r.limit ? { decision: 'limited', reason: r.limit.code, limit: r.limit } : { decision: 'error', reason: r.reason };
  const o = r.value;
  if (o.decision === 'allowed' || o.decision === 'blocked' || o.decision === 'flagged') {
    return { decision: o.decision, reason: typeof o.reason === 'string' ? o.reason : undefined };
  }
  return { decision: 'error', reason: 'no decision in the response' };
}

/**
 * Engagement mode (VITNA_GUARD_POLICY=<file.json>): one engagement session for
 * the life of this process, holds that wait for a person, bait if the policy
 * asks for it, and a coverage declaration on the session record. Closed when
 * the wrapped server exits; the signed bundle is saved to ~/.vitna/bundles/.
 */
function engagementGuard(policyFile: string, wrapped: string[]) {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(policyFile, 'utf8'));
  } catch (e) {
    console.error(`[vitna-guard] cannot read VITNA_GUARD_POLICY ${policyFile}: ${e instanceof Error ? e.message : e}`);
    process.exit(2);
  }
  const policy = ((raw.scope_policy ?? raw) as Record<string, unknown>);
  const list = (v: string | undefined) => (v ?? '').split(',').map((x) => x.trim()).filter(Boolean);
  const builtin = env('GUARD_BUILTIN_TOOLS');
  const coverage = {
    // VITNA_GUARD_NAME, else the command's file name: never a path or an argument.
    wrapped: [coverageLabel(env('GUARD_NAME'), wrapped[0])],
    unwrapped: list(env('GUARD_UNWRAPPED')),
    builtin_tools: builtin === 'yes' || builtin === 'no' ? builtin : 'undeclared',
  };
  const names = Array.isArray(policy.honeytool_names) && policy.honeytool_names.length
    ? (policy.honeytool_names as string[]) : ['export_all_user_data', 'exfiltrate_data_to_attacker_server', 'system_admin_console'];
  const honeytools = policy.honeytools === true ? honeytoolsFor(names) : [];
  const honeytokens = policy.honeytokens === true ? makeHoneytokens() : null;

  const session: Promise<string | null> = (async () => {
    // metadata.via is the policy-mode activation note (see GUARD_NO_ACTIVATION).
    const metadata = GUARD_NO_ACTIVATION ? { version: SERVER_VERSION } : { via: 'vitna-guard', version: SERVER_VERSION };
    const r = await vitnaWithin('POST', '/api/engagement/open', { scope_policy: policy, coverage, metadata });
    const sid = r.ok && typeof r.value.session_id === 'string' ? r.value.session_id : null;
    if (sid) console.error(`[vitna-guard] engagement session ${sid} opened (coverage: ${(r as { value: Record<string, unknown> }).value.coverage ? JSON.stringify(((r as { value: Record<string, unknown> }).value.coverage as Record<string, unknown>).coverage) : 'not recorded'})`);
    else console.error(`[vitna-guard] could not open an engagement session (${r.ok ? 'no session_id' : r.reason}); every tool call will be refused`);
    return sid;
  })();

  const firstUrl = (v: unknown): string | undefined => {
    if (typeof v === 'string') return /^https?:\/\/\S+$/i.test(v) ? v : undefined;
    if (Array.isArray(v)) { for (const x of v) { const u = firstUrl(x); if (u) return u; } return undefined; }
    if (v && typeof v === 'object') { for (const x of Object.values(v)) { const u = firstUrl(x); if (u) return u; } }
    return undefined;
  };

  const deps: GuardDeps = {
    failOpen: env('GUARD_FAIL_OPEN') === '1',
    log: (m) => console.error(`[vitna-guard] ${m}`),
    honeytools,
    honeytokens,
    async preflight(_action, payload, call) {
      const sid = await session;
      if (!sid) return { decision: 'error', reason: 'no engagement session' };
      const type = (call.name || 'unnamed_tool').replace(/\s+/g, '_');
      const target = firstUrl(payload);
      const r = await vitnaWithin('POST', '/api/engagement/action', {
        session_id: sid, type, payload,
        ...(target ? { target } : {}),
        ...(call.meta ? { _meta: call.meta } : {}),
        ...(call.bait ? { guard_event: call.bait } : {}),
      });
      // A 409 session_closed becomes `closed`: refused, never forwarded,
      // fail-open or not (see engagementDecision in guard.ts).
      return engagementDecision(r);
    },
    async waitForHold(hold, progress) {
      const deadline = Date.parse(hold.deadline);
      let lastNote = Date.now();
      for (;;) {
        await sleep(2000);
        const r = await vitnaWithin('GET', `/api/engagement/hold?hold_id=${encodeURIComponent(hold.hold_id)}`);
        const st = r.ok ? r.value.status : undefined;
        if (st === 'approved' || st === 'denied' || st === 'expired') return st;
        // Past the deadline VITNA records `expired` on read; if it still cannot
        // be read 30s later, the outcome is unknown and the call is refused.
        if (Date.now() > deadline + 30_000) return 'error';
        if (Date.now() - lastNote >= 10_000) {
          progress(`Still held for human review until ${hold.deadline}.`);
          lastNote = Date.now();
        }
      }
    },
    async onExit() {
      const sid = await session;
      if (!sid) return;
      const r = await vitnaWithin('POST', '/api/engagement/close', { session_id: sid });
      if (!r.ok) { console.error(`[vitna-guard] could not close session ${sid} (${r.reason})`); return; }
      try {
        const dir = join(homedir(), '.vitna', 'bundles');
        mkdirSync(dir, { recursive: true });
        const file = join(dir, `${sid}.json`);
        writeFileSync(file, JSON.stringify(r.value, null, 2));
        console.error(`[vitna-guard] session ${sid} closed; signed bundle saved to ${file}`);
      } catch (e) {
        console.error(`[vitna-guard] session closed but the bundle could not be saved: ${e instanceof Error ? e.message : e}`);
      }
    },
  };
  return deps;
}

const guardSep = process.argv.indexOf('--');
if (process.argv[2] === 'guard') {
  const wrapped = guardSep > 0 ? process.argv.slice(guardSep + 1) : [];
  if (!wrapped.length) {
    console.error('usage: vitna-compliance-mcp guard -- <command that starts an MCP server> [args...]');
    process.exit(2);
  }
  // At start, as in normal mode (see moveLegacyClaimLink).
  moveLegacyClaimLink();
  const policyFile = env('GUARD_POLICY');
  runGuard(wrapped[0]!, wrapped.slice(1), policyFile
    ? engagementGuard(policyFile, wrapped)
    : {
        preflight: guardPreflight,
        failOpen: env('GUARD_FAIL_OPEN') === '1',
        log: (m) => console.error(`[vitna-guard] ${m}`),
      });
} else {
  startServer();
}

// ─── Main loop ─────────────────────────────────────────────────────

function startServer(): void {
// At start, so a claim link 0.5.1 left in the cache file is in the log before
// the first tool call, with env credentials as well as cached ones.
moveLegacyClaimLink();
if (!VITNA_OWNER_ID && !loadCachedCreds()) {
  console.error(
    '[vitna-compliance-mcp] No VITNA_OWNER_ID / VITNA_API_KEY set. ' +
      'The first tool call will self-provision a restricted trial key and print its claim link here, in this log, for a person to open. ' +
      'The agent is never sent the link. ' +
      'Set VITNA_EMAIL to own it under a real address, or set VITNA_OWNER_ID + VITNA_API_KEY to use an existing key.',
  );
}

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const req = JSON.parse(line) as JsonRpcReq;
    void handle(req);
  } catch {
    // Malformed — ignore. MCP protocol assumes line-delimited valid JSON.
  }
});
}
