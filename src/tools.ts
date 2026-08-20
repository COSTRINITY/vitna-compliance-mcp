/**
 * THE tool catalogue. One definition, both transports.
 *
 * WHY THIS FILE EXISTS SEPARATELY
 *   VITNA speaks MCP over two transports: this package's stdio server
 *   (src/index.ts) and the remote streamable-HTTP endpoint in the Next.js
 *   app (app/api/mcp/route.ts). If each declared its own tool list, the two
 *   would drift the first time someone added a tool to one of them -- the
 *   same one-thing-recorded-two-ways failure that produced the compliance
 *   timeline bug. So neither declares tools; both import this.
 *
 *   tests/mcp-transport-parity.test.ts fails the build if the transports
 *   ever expose different tool sets.
 *
 * STATE-FREE ON PURPOSE
 *   Nothing here reads process.env or module-level mutable state, because
 *   the remote transport runs per-request in a shared server process where
 *    module state would leak between callers. The one tool that needs
 *   context (vitna_help, which surfaces a claim URL) receives it as an
 *   argument.
 */

/**
 * Tool names from the VIGIL era, mapped to their VITNA names. Resolved in
 * tools/call but intentionally absent from tools/list, so the advertised
 * catalogue is VITNA-only while cached agent configs keep working forever.
 */
export const TOOL_ALIASES: Record<string, string> = {
  vigil_help: 'vitna_help',
  action_preflight: 'vitna_preflight',
};



/**
 * The version both transports announce in the MCP initialize handshake.
 *
 * Lives here, with the catalogue, because it is the version of the TOOL
 * SURFACE and both transports must report the same thing. It said '0.3.0'
 * through two releases when it lived in the stdio server alone, and the
 * remote endpoint briefly reported the Next app's version (0.1.0) when it
 * read npm_package_version. tests/claims-gate.test.ts pins it to
 * package.json so neither can happen again.
 */
export const SERVER_VERSION = '0.3.7';

/** Per-call context for local (no-HTTP) tools. */
export interface LocalToolContext {
  /** Claim URL for the current trial account, when one is known. */
  claimUrl: string | null;
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** Maps the MCP call to a VITNA HTTP request. Omitted for local tools. */
  call?: (input: Record<string, unknown>) => { method: string; path: string; body?: unknown };
  /** Local tool: returns a value directly with no VITNA HTTP call (no auth, no
   *  metering). Used for the self-describe / onboarding tool. */
  local?: (input: Record<string, unknown>, ctx: LocalToolContext) => unknown;
}

export const TOOLS: ToolDef[] = [
  // ─── Onboarding / self-describe (call this first) ────────────────
  {
    name: 'vitna_help',
    description:
      "What is VITNA and how do I use it to keep myself in check? Call this FIRST after connecting to learn the safety and oversight checks available: how to check risky actions BEFORE running them, what a deny / hold decision means, trial vs claimed mode, and how the user can monitor and audit what you do. Runs entirely locally: no account, no API call, and no dashboard timeline trace.",
    inputSchema: { type: 'object', properties: {} },
    local: (_input, ctx) => vitnaHelp(ctx.claimUrl),
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

// ─── Onboarding ────────────────────────────────────────────────────

/**
 * Plain-language guide the agent gets from vitna_help. No network, no auth.
 * Takes the claim URL as an argument rather than reading module state, so it
 * is safe to call from the shared remote transport (see the header note).
 */
export function vitnaHelp(claimUrl: string | null): Record<string, unknown> {
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
    claim_url: claimUrl,
    tell_the_user:
      'Explain to the user that you are connected to a safety oversight layer, that you will check risky actions before running them, and share the claim link so they can keep the audit records and monitor you.',
  };
}

/**
 * The advertised catalogue: what tools/list returns, in catalogue order.
 * Aliases are deliberately absent (see TOOL_ALIASES) so the advertised
 * surface stays exactly the 22 supported names on both transports.
 */
export function listedTools(): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  return TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
}

/** Resolve a requested tool name, honouring the hidden legacy aliases. */
export function resolveTool(requested: string): ToolDef | undefined {
  return TOOLS.find((t) => t.name === (TOOL_ALIASES[requested] ?? requested));
}
