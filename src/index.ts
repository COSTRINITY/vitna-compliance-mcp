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
 *   Pair with `@costrinity/vitna-mcp` (the proxy/observer) for full
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
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

// THE tool catalogue -- shared with the remote streamable-HTTP transport in
// the Next.js app (app/api/mcp/route.ts). This file owns the stdio TRANSPORT
// and credential handling; it deliberately declares no tools of its own, so
// the two transports cannot drift apart.
import { listedTools, resolveTool, SERVER_VERSION } from './tools.js';

// Env vars: VITNA_* is canonical. The old VIGIL_* names are accepted forever
// as aliases, so existing user configs never break.
const env = (name: string): string | undefined =>
  process.env['VITNA_' + name] ?? process.env['VIGIL_' + name];

const VITNA_BASE_URL = env('BASE_URL') ?? 'https://vitna.costrinity.xyz';
// let, not const: when absent, these are populated on first use by
// self-provisioning (a restricted trial key) or from the local cache.
let VITNA_OWNER_ID = env('OWNER_ID') ?? '';
let VITNA_API_KEY = env('API_KEY') ?? '';
// Claim URL for the current (trial) account, learned on provision or from the
// cache. justProvisioned is true only on the single tool call that triggered
// self-provisioning, so the very first tool response can carry a plain-language
// connection notice the agent relays to the user.
let VITNA_CLAIM_URL = '';
let justProvisioned = false;

const SERVER_NAME = 'vitna-compliance';
// SERVER_VERSION now lives in the shared catalogue (src/tools.ts) so the
// stdio and remote transports cannot announce different versions.


// ─── Self-provisioning (restricted trial key on first use) ─────────
//
// When VITNA_OWNER_ID / VITNA_API_KEY are not set, the first tool call
// provisions a RESTRICTED trial key via /api/setup, caches it locally, and
// surfaces the claim URL so a human can claim the account (lifting the limits
// and unlocking signed evidence). Explicit env credentials always win. Set
// VITNA_EMAIL to own the trial account under a real address; otherwise a
// throwaway is used and the human can bind a real email later by claiming.

const CRED_FILE = join(homedir(), '.vitna', 'credentials.json');

function loadCachedCreds(): { owner_id: string; api_key: string; claim_url?: string } | null {
  try {
    const c = JSON.parse(readFileSync(CRED_FILE, 'utf8'));
    if (c && typeof c.owner_id === 'string' && typeof c.api_key === 'string' && c.owner_id && c.api_key) {
      return { owner_id: c.owner_id, api_key: c.api_key, claim_url: typeof c.claim_url === 'string' ? c.claim_url : undefined };
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

async function provision(): Promise<void> {
  const owner_email = env('EMAIL') || `agent-${randomBytes(6).toString('hex')}@mcp.vitna.local`;
  const agent_name = env('AGENT_NAME') || `vitna-compliance-mcp-${hostname()}`;
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
    if (typeof data.claim_url === 'string') VITNA_CLAIM_URL = data.claim_url;
    justProvisioned = true;
    saveCachedCreds({ owner_id: VITNA_OWNER_ID, api_key: VITNA_API_KEY, base_url: VITNA_BASE_URL, claim_url: data.claim_url ?? null });
    console.error(
      `[vitna-compliance-mcp] provisioned a restricted trial key (owner ${VITNA_OWNER_ID}). ` +
        (typeof data.claim_url === 'string'
          ? `Claim it for full access + signed evidence: ${data.claim_url}`
          : 'Claim it from your VITNA dashboard for full access.'),
    );
  } catch (e) {
    console.error('[vitna-compliance-mcp] self-provision failed:', e instanceof Error ? e.message : String(e));
  }
}

// Memoized so /api/setup is called at most once even under concurrent tools.
let credsReady: Promise<void> | null = null;
function ensureCredentials(): Promise<void> {
  if (!credsReady) {
    credsReady = (async () => {
      if (VITNA_OWNER_ID && VITNA_API_KEY) return; // explicit env credentials win
      const cached = loadCachedCreds();
      if (cached) {
        VITNA_OWNER_ID = cached.owner_id;
        VITNA_API_KEY = cached.api_key;
        if (cached.claim_url) VITNA_CLAIM_URL = cached.claim_url;
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
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text, _status: res.status };
  }
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


/** One-time notice, in language the agent can relay to the user, emitted on the
 *  first tool response after self-provisioning. */
function connectionNotice(): string {
  return [
    'CONNECTED TO VITNA, a safety and compliance oversight layer, in TRIAL mode.',
    'You can now check risky actions BEFORE you run them: call action_preflight for shell / file / DB / network actions, or the compliance checks for data handling. Each returns an allow / deny / hold decision. Treat deny or hold as a stop and get human approval before proceeding.',
    'This trial key is rate-limited and does NOT keep signed audit evidence.',
    VITNA_CLAIM_URL
      ? `To keep your audit records and raise the limits, tell the user to claim this account: ${VITNA_CLAIM_URL}`
      : 'To keep your audit records and raise the limits, ask the user to claim this account from the VITNA dashboard.',
    'Relay this to the user in your own words, including the claim link.',
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

function send(resp: JsonRpcResp): void {
  process.stdout.write(JSON.stringify(resp) + '\n');
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
          result = tool.local(params.arguments ?? {}, { claimUrl: VITNA_CLAIM_URL || null });
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
        if (justProvisioned) {
          justProvisioned = false;
          content.push({ type: 'text', text: connectionNotice() });
        }
        content.push({ type: 'text', text: JSON.stringify(result, null, 2) });
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

// ─── Main loop ─────────────────────────────────────────────────────

if (!VITNA_OWNER_ID && !loadCachedCreds()) {
  console.error(
    '[vitna-compliance-mcp] No VITNA_OWNER_ID / VITNA_API_KEY set. ' +
      'The first tool call will self-provision a restricted trial key and print a claim URL. ' +
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
