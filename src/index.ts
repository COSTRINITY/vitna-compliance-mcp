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
// Keep in lockstep with package.json "version" — this string is what every
// client sees in the MCP initialize handshake and in our outbound User-Agent.
// It silently said 0.3.0 across the 0.3.1 and 0.3.2 releases, which made
// version telemetry unreliable; tests/claims-gate.test.ts now fails the build
// if the two ever disagree again.
const SERVER_VERSION = '0.3.3';

/**
 * Tool names from the VIGIL era, mapped to their VITNA names. Resolved in
 * tools/call but intentionally absent from tools/list, so the advertised
 * catalogue is VITNA-only while cached agent configs keep working forever.
 */
const TOOL_ALIASES: Record<string, string> = {
  vigil_help: 'vitna_help',
  action_preflight: 'vitna_preflight',
};

// ─── Tool catalogue ────────────────────────────────────────────────

interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** Maps the MCP call to a VITNA HTTP request. Omitted for local tools. */
  call?: (input: Record<string, unknown>) => { method: string; path: string; body?: unknown };
  /** Local tool: returns a value directly with no VITNA HTTP call (no auth, no
   *  metering). Used for the self-describe / onboarding tool. */
  local?: (input: Record<string, unknown>) => unknown;
}

const TOOLS: ToolDef[] = [
  // ─── Onboarding / self-describe (call this first) ────────────────
  {
    name: 'vitna_help',
    description:
      "What is VITNA and how do I use it to keep myself in check? Call this FIRST after connecting to learn the safety and oversight checks available: how to check risky actions BEFORE running them, what a deny / hold decision means, trial vs claimed mode, and how the user can monitor and audit what you do. Runs entirely locally: no account, no API call, and no dashboard timeline trace.",
    inputSchema: { type: 'object', properties: {} },
    local: () => vigilHelp(),
  },

  // ─── Consent + processing gate ───────────────────────────────────
  {
    name: 'consent_check',
    description:
      "Before you process someone's personal data, ask VITNA whether an active consent actually permits it for this purpose. Give the data principal + purpose (and optional category); returns { allowed, reason, matching_consent_id, principal_id }, a determination you must honour yourself since VITNA evaluates and records but does not enforce. Use this for personal-data processing legality; for a dangerous technical action (shell / file / DB / network) use action_preflight instead.",
    inputSchema: {
      type: 'object',
      required: ['purpose'],
      properties: {
        principal_id: { type: 'string', description: 'UUID of the data principal (if known).' },
        principal_ref: { type: 'string', description: 'Operator-side identifier; will be SHA-256-hashed.' },
        purpose: { type: 'string', description: "Purpose code (e.g. 'operational_observability')." },
        category: { type: 'string', description: 'Optional permitted-category check.' },
      },
    },
    call: (input) => ({
      method: 'POST',
      path: '/api/consent/check',
      body: input,
    }),
  },

  // ─── Breach + incident classification ────────────────────────────
  {
    name: 'breach_classify',
    description:
      "After a security incident, check whether it is legally reportable before you decide how to respond. Give the incident facts (affected count, data categories, sensitivity, recovery state) and VITNA returns reportability + reasoning + the notification deadline + who to notify, across DPDP §8, GDPR Art 33, CPRA §1798.82, LGPD Art 48, PDPA §26B, and US-FED sectoral. This makes the full incident decision from the facts; for a quick per-US-state deadline/recipient/threshold table without incident facts, use us_state_breach_deadline. VITNA evaluates and records; acting on the result is up to you.",
    inputSchema: {
      type: 'object',
      required: ['affected_count', 'data_categories', 'sensitivity', 'recovery_state'],
      properties: {
        affected_count: { type: 'integer' },
        data_categories: { type: 'array', items: { type: 'string' } },
        processing_purpose: { type: 'string' },
        sensitivity: { type: 'string', enum: ['low', 'medium', 'high', 'special'] },
        recovery_state: { type: 'string', enum: ['lost', 'exposed', 'altered', 'destroyed', 'contained'] },
        jurisdiction: { type: 'string' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/breach-classify', body: input }),
  },

  // ─── EU AI Act risk classifier ────────────────────────────────────
  {
    name: 'ai_act_classify',
    description:
      "Before you build or ship an AI feature, check where it lands under the EU AI Act (Regulation 2024/1689). Describe the use case (with biometric / remote-identification / automated-decision / social-scoring / GPAI flags) and VITNA returns the risk tier (prohibited / high-risk / limited-risk / minimal-risk), GPAI obligations, and the per-tier obligations you would have to meet. A classification for you to act on: VITNA evaluates and records, it does not gate the build.",
    inputSchema: {
      type: 'object',
      required: ['use_case'],
      properties: {
        use_case: { type: 'string' },
        data_categories: { type: 'array', items: { type: 'string' } },
        sectors: { type: 'array', items: { type: 'string' } },
        automated_decisions: { type: 'boolean' },
        biometric: { type: 'boolean' },
        remote_identification: { type: 'boolean' },
        social_scoring: { type: 'boolean' },
        general_purpose_ai: { type: 'boolean' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/ai-act-classify', body: input }),
  },

  // ─── DPIA threshold check ─────────────────────────────────────────
  {
    name: 'dpia_threshold_check',
    description:
      "Before you start a new processing activity, check whether the law requires a DPIA first (GDPR Art 35 / DPDP §10 / LGPD Art 38). Give the purpose + data categories (and scale / systematic-monitoring / automated-decision / cross-border / vulnerable-subjects flags); returns dpia_required + the 9-criterion WP29 analysis + jurisdiction guidance, so you know whether to pause and assess before proceeding.",
    inputSchema: {
      type: 'object',
      required: ['processing_purpose', 'data_categories'],
      properties: {
        processing_purpose: { type: 'string' },
        data_categories: { type: 'array', items: { type: 'string' } },
        scale: { type: 'string', enum: ['small', 'medium', 'large', 'mass'] },
        automated_decision: { type: 'boolean' },
        systematic_monitoring: { type: 'boolean' },
        cross_border: { type: 'boolean' },
        vulnerable_subjects: { type: 'boolean' },
        jurisdiction: { type: 'string' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/dpia-threshold-check', body: input }),
  },

  // ─── US sectoral analysis ─────────────────────────────────────────
  {
    name: 'us_sectoral_check',
    description:
      "Before you process personal data under US law, find out which US federal sectoral regimes bind you (HIPAA, GLBA, COPPA, FERPA, FCRA, SOX) for a given processing profile, so you can factor them in before you act. US-scoped; for Indian sectoral regulators use india_sectoral_check.",
    inputSchema: {
      type: 'object',
      required: ['processing_purpose', 'data_categories'],
      properties: {
        processing_purpose: { type: 'string' },
        data_categories: { type: 'array', items: { type: 'string' } },
        counterparty_types: { type: 'array', items: { type: 'string' } },
        ai_decisions: { type: 'boolean' },
        has_revenue_threshold: { type: 'boolean' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/sectoral-check', body: input }),
  },

  // ─── Indian sectoral analysis ─────────────────────────────────────
  {
    name: 'india_sectoral_check',
    description:
      "Before you process personal data under Indian law, find out which sectoral regulators actually bind your specific activity (RBI / SEBI / IRDAI / TRAI / DoT / PFRDA) from its processing profile, so you know whose rules apply before you act. This analyses your processing to say what applies; for a plain directory of every Indian regulator regardless of your activity, use india_regulators_directory.",
    inputSchema: {
      type: 'object',
      required: ['processing_purpose', 'data_categories'],
      properties: {
        processing_purpose: { type: 'string' },
        data_categories: { type: 'array', items: { type: 'string' } },
        counterparty_types: { type: 'array', items: { type: 'string' } },
        sector_hint: { type: 'string' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/india-sectoral-check', body: input }),
  },

  // ─── Cross-border lookups ─────────────────────────────────────────
  {
    name: 'india_cross_border_status',
    description:
      "Before you transfer personal data out of India, check the destination country's DPDP §16 status (permitted / restricted / sectoral_restricted) plus any RBI / SEBI / IRDAI caveats. Pass the ISO-3166 alpha-2 country code (e.g. US). Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      required: ['country'],
      properties: { country: { type: 'string', description: 'ISO-3166 alpha-2 (e.g. US).' } },
    },
    call: (input) => ({
      method: 'GET',
      path: `/api/compliance/india-cross-border-countries?country=${encodeURIComponent(String(input.country ?? ''))}`,
    }),
  },
  {
    name: 'japan_cross_border_status',
    description:
      "Before you transfer personal data out of Japan, check the destination country's APPI Art 28 status (adequacy / standard basis / high scrutiny). Pass the ISO-3166 alpha-2 country code. Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      required: ['country'],
      properties: { country: { type: 'string', description: 'ISO-3166 alpha-2.' } },
    },
    call: (input) => ({
      method: 'GET',
      path: `/api/compliance/japan-cross-border?country=${encodeURIComponent(String(input.country ?? ''))}`,
    }),
  },

  // ─── US state breach deadlines ────────────────────────────────────
  {
    name: 'us_state_breach_deadline',
    description:
      "Quick reference lookup of a single US state's breach-notification window, AG recipient and resident threshold (e.g. 'CA' gives 500 residents, CA AG, without unreasonable delay). This is a static table, not an incident ruling. When you have the actual incident facts and need a reportable / not-reportable decision with reasoning, use breach_classify instead. Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      required: ['state'],
      properties: { state: { type: 'string', description: 'US 2-letter state code (CA, NY, TX, ...).' } },
    },
    call: (input) => ({
      method: 'GET',
      path: `/api/compliance/state-breach-deadlines?state=${encodeURIComponent(String(input.state ?? ''))}`,
    }),
  },

  // ─── Identifier validators (all auth-gated; pass owner_id) ───────
  {
    name: 'aadhaar_mask',
    description:
      "Mask + Verhoeff-validate an Aadhaar number. Returns masked form, validity, and an owner-scoped reference token. No persistence of the raw value. Stateless validator: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      required: ['aadhaar'],
      properties: { aadhaar: { type: 'string' } },
    },
    call: (input) => ({ method: 'POST', path: '/api/india/aadhaar-mask', body: input }),
  },
  {
    name: 'pan_classify',
    description: 'Classify a PAN entity type from the 4th character (P=Person, C=Company, H=HUF, F=Firm, ...). Stateless validator: records no decision and leaves no dashboard timeline trace.',
    inputSchema: { type: 'object', required: ['pan'], properties: { pan: { type: 'string' } } },
    call: (input) => ({ method: 'POST', path: '/api/india/pan-classify', body: input }),
  },
  {
    name: 'gstin_validate',
    description: 'Validate a GSTIN format + mod-36 check digit; returns state code lookup. Stateless validator: records no decision and leaves no dashboard timeline trace.',
    inputSchema: { type: 'object', required: ['gstin'], properties: { gstin: { type: 'string' } } },
    call: (input) => ({ method: 'POST', path: '/api/india/gstn-validate', body: input }),
  },
  {
    name: 'cpf_validate',
    description: 'Validate a Brazilian CPF (mod-11 check digits, rejects all-same). Stateless validator: records no decision and leaves no dashboard timeline trace.',
    inputSchema: { type: 'object', required: ['cpf'], properties: { cpf: { type: 'string' } } },
    call: (input) => ({ method: 'POST', path: '/api/brazil/cpf-validate', body: input }),
  },
  {
    name: 'sin_validate',
    description: 'Validate a Canadian SIN (Luhn checksum); returns series region + masked form. Stateless validator: records no decision and leaves no dashboard timeline trace.',
    inputSchema: { type: 'object', required: ['sin'], properties: { sin: { type: 'string' } } },
    call: (input) => ({ method: 'POST', path: '/api/canada/sin-validate', body: input }),
  },
  {
    name: 'iban_validate',
    description: 'Validate an IBAN format + ISO 7064 mod-97 check digit; supports 71 countries. Stateless validator: records no decision and leaves no dashboard timeline trace.',
    inputSchema: { type: 'object', required: ['iban'], properties: { iban: { type: 'string' } } },
    call: (input) => ({ method: 'POST', path: '/api/eu/iban-validate', body: input }),
  },
  {
    name: 'pii_test',
    description:
      "Dry-run VITNA's PII / threat detection on a sample event before you send real data, to preview what would be tagged, how it would be redacted, and whether severity would escalate. Nothing is persisted and nothing is filtered: a safe rehearsal you act on, not an enforced gate — it records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      required: ['sample_event'],
      properties: {
        sample_event: { type: 'object', description: 'event_type / message / payload fields.' },
        jurisdiction: { type: 'string' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/compliance/pii-test', body: input }),
  },

  // ─── Read-only generators ─────────────────────────────────────────
  {
    name: 'privacy_notice_get',
    description:
      "Generate the operator's jurisdiction-templated privacy notice. Returns markdown or JSON. Stateless generator: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      properties: { format: { type: 'string', enum: ['md', 'json'] } },
    },
    call: (input) => ({
      method: 'GET',
      path: `/api/compliance/privacy-notice?format=${input.format ?? 'md'}`,
    }),
  },
  {
    name: 'sub_processors_register',
    description: "Return the public sub-processor register (Supabase, Vercel, Resend, etc.). Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: { type: 'object', properties: {} },
    call: () => ({ method: 'GET', path: '/api/compliance/sub-processors?format=json' }),
  },
  {
    name: 'global_compliance_map',
    description: "Master catalogue of every privacy/security/sectoral regime VITNA has fabric for (28 entries covering 24 named statutes). Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: { type: 'object', properties: {} },
    call: () => ({ method: 'GET', path: '/api/compliance/global-status' }),
  },
  {
    name: 'india_regulators_directory',
    description: "Static reference directory of Indian data and sector regulators (DPB, RBI, SEBI, IRDAI, TRAI, DoT, PFRDA, MeitY, MCA), optionally filtered by sector: a lookup of who exists and what they cover. To instead work out which of them apply to a specific processing activity, use india_sectoral_check. Stateless lookup: records no decision and leaves no dashboard timeline trace.",
    inputSchema: {
      type: 'object',
      properties: { sector: { type: 'string' } },
    },
    call: (input) => ({
      method: 'GET',
      path: input.sector
        ? `/api/india/regulators?sector=${encodeURIComponent(String(input.sector))}`
        : '/api/india/regulators',
    }),
  },

  // ─── Destructive-action pre-flight gate ──────────────────────────
  {
    name: 'vitna_preflight',
    description:
      "SAFETY / OVERSIGHT CHECK before a dangerous or destructive action (shell command, file deletion, DB statement, network call). Call this to have VITNA check the action BEFORE you run it: it flags dangerous shell / SQL / secret-exfil / prompt-injection / suspicious-network patterns and returns { decision: allowed|blocked|flagged, threat_category, reason } plus (in claimed mode) a signed audit record the user can review. VITNA evaluates and records; it does NOT enforce, so treat blocked / flagged as a stop and get human approval. This is how a user keeps you in check. Heuristic pattern match, not a sandbox: novel or obfuscated payloads can pass.",
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'The proposed action / command text, e.g. "rm -rf /" or "DROP TABLE users".' },
        payload: { type: 'object', description: 'Optional structured payload to scan alongside the action text.' },
        action_type: { type: 'string', description: 'Optional short label for the action kind (shell, file_delete, db_query, network).' },
      },
    },
    call: (input) => ({ method: 'POST', path: '/api/preflight/action-check', body: input }),
  },
];

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

// ─── Onboarding + connection notice ────────────────────────────────

/** Plain-language guide the agent gets from vigil_help. No network / auth. */
function vigilHelp(): Record<string, unknown> {
  return {
    what_is_vigil:
      'VITNA is a safety and compliance oversight layer for AI agents. Before you take a risky action you ask VITNA; it returns an allow / deny / hold decision and, in claimed mode, keeps a signed, tamper-evident record a human can audit. It is how a user keeps you in check and monitors what you do.',
    how_to_use: [
      'Before a dangerous action (shell command, file delete, DB statement, network call), call action_preflight with the action text. decision=allowed means proceed; blocked or flagged means STOP and get human approval.',
      'Before handling personal data, call consent_check / breach_classify / dpia_threshold_check / ai_act_classify as relevant.',
      'VITNA evaluates and records; it does NOT enforce for you. YOU must honor a deny or hold: stop, get approval, then proceed.',
    ],
    safety_checks: [
      'action_preflight - flag dangerous shell / SQL / secret-exfil / prompt-injection / suspicious-network actions before they run',
      'consent_check - is processing allowed for this person + purpose',
      'breach_classify - is an incident reportable, by when, to whom',
      'dpia_threshold_check / ai_act_classify - risk classification before you build or ship',
    ],
    trial_vs_claimed:
      'On first use with no credentials you connect in TRIAL mode: decision checks work but are rate-limited, return label-only results, and do not persist signed evidence. Claiming the account (claim_url) unlocks full detail, higher limits, and signed audit records.',
    claim_url: VITNA_CLAIM_URL || null,
    tell_the_user:
      'Explain to the user that you are connected to a safety oversight layer, that you will check risky actions before running them, and share the claim link so they can keep the audit records and monitor you.',
  };
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
        ok(id, {
          tools: TOOLS.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });
        return;

      case 'tools/call': {
        const params = (req.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        // Hidden aliases from the VIGIL era. They are deliberately NOT listed in
        // tools/list (the catalogue advertises the vitna_* names only), but they
        // keep working forever so an agent with a cached config does not break.
        const requested = params.name ?? '';
        const resolved = TOOL_ALIASES[requested] ?? requested;
        const tool = TOOLS.find((t) => t.name === resolved);
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
