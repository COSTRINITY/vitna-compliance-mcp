# @costrinity/vitna-compliance-mcp

> **Renamed from VIGIL.** This package was formerly published as
> `@costrinity/vigil-compliance-mcp` and this repo was formerly
> `COSTRINITY/vigil-compliance-mcp`. **The old package name does not exist on
> npm** — anything still pointing at it will fail to install. Directory
> listings that show the VIGIL name are stale snapshots of this repo.
>
> Current package: **`@costrinity/vitna-compliance-mcp`**
> Registry entry: **`xyz.costrinity/vitna-compliance-preflight`**
> Site: **https://vitna.costrinity.xyz**

**Pre-action compliance for AI agents: allow, block or hold — before your agent acts.**

Most compliance servers answer questions *about* regulations. This one answers one question *about the action your agent is holding right now*: may it run? Your agent calls a check, gets `allowed` / `blocked` / `flagged` back synchronously, and decides. VITNA evaluates and records; your system enforces.

## The package

One package to install. This is the server your agent calls before it acts.

| Package | What it does | When you want it | Install |
|---|---|---|---|
| **`@costrinity/vitna-compliance-mcp`** (this one) | Your agent **asks before it acts**. Returns allow / block / flag on a proposed action, and records a signed evidence record of the decision. | You want a guardrail your agent calls, and provable receipts that it did. | `npx @costrinity/vitna-compliance-mcp` — no credentials needed to start |

A passive observer that records existing MCP traffic without deciding anything
is built in this repo but is **not published to npm**, so it is not documented
here yet. Nothing above depends on it.


## Coverage

| | |
|---|---|
| **24 named statutes** | across **13 jurisdictions** |
| **EU AI Act** (Reg 2024/1689) | risk-tier classification before you build or ship |
| **GDPR** + **UK GDPR** | DPIA thresholds, breach reportability, ROPA |
| **DPDP** (India, 2023) | §16 cross-border status, §8 breach path |
| **LGPD · PDPA-SG · APPI · PIPEDA + Law 25 · PIPL · PIPA-KR · NDPA · APP-AU · CPRA** | jurisdiction packs |
| **HIPAA · GLBA · COPPA · FERPA · FCRA · SOX** | US federal sectoral applicability |
| **RBI · SEBI · IRDAI · TRAI/DoT · PFRDA** | Indian sectoral regulators |
| **16 US state privacy laws** | plus breach deadlines for 21 states |
| **23 MCP tools** | 6 identifier validators, 15 stateless helpers |

Readiness scorecards (pre-audit, not certifications) additionally cover NIST Privacy Framework, SOC 2, ISO/IEC 27001 and PCI DSS v4.0.

Every count above is derived from the code and enforced by a build gate — if an implementation is removed, the build fails before the number can go stale. See "Honest limits" below for what these numbers do *not* mean.

VITNA's detection is heuristic, and those limits are documented publicly. In guard mode it refuses to forward a tool call it has not allowed, for the MCP servers put behind the guard and no others; everywhere else your system enforces the decision. Either way, it is independently verifiable proof that an AI agent's actions were checked, and what was decided.

## Free checkers — no install, no account

Two questions people usually have to answer *before* they need any of this. Both
run entirely in the browser, take a few questions, and store nothing.

| | |
|---|---|
| **[Does the 2 December 2026 deadline apply to you?](https://vitna.costrinity.xyz/ai-act-december-2026)** | Article 50(2) machine-readable marking for generative systems placed on the EU market before 2 August 2026, plus the two prohibited practices added by the Digital Omnibus. Works out which of the two dates you are actually on. |
| **[Article 50 transparency self-check](https://vitna.costrinity.xyz/article-50)** | Which Article 50 disclosure duties reach you as provider or deployer. |

Both are scoping tools, not legal advice, and neither issues a score or a
pass/fail. They cite the article and the Official Journal text behind every
date they state.

## Verify VITNA evidence yourself

Every decision also produces an Ed25519-signed evidence record that anyone can verify offline — **no account, and no trust in VITNA's servers required**. The public key is published, the verifier is open source, and the three commands below prove it in about a minute.

One minute, no account, no trust in VITNA's servers required. Download the open-source verifier and a real signed sample bundle, then check the signature offline with Node 18+:

```bash
curl -sO https://raw.githubusercontent.com/COSTRINITY/vitna-compliance-mcp/main/verify-evidence.mjs
curl -sO https://vitna.costrinity.xyz/sample-evidence.json
node verify-evidence.mjs sample-evidence.json
```

The verifier checks the Ed25519 signature over the whole package, then recomputes the sha256 of each individual decision record and confirms it matches the hash committed inside the signed package, printing PASS or FAIL per record, then an overall verdict.

Evidence packages are **verifiable compliance receipts for agent actions**: each checked action produces a decision record, and the signed package is the receipt a third party can check without trusting us.

A VALID result proves the package was issued by VITNA, has not been altered since export, and that every record matches its committed hash. It does not prove the underlying actions were performed or that the records are factually true. Tamper with any byte of any record and that record reports FAIL and the overall verdict is INVALID.

**Bundles from VITNA Desktop are signed differently.** VITNA Desktop signs on your own machine, with a key it generated there, not with VITNA's key. The signed package says so (`issuer: "vitna-desktop-local"`, `signer_key_id`, `signer_public_key`), and the verifier reports such a bundle as "signed by a local VITNA Desktop key, not by VITNA". By default it checks the key the bundle carries and prints its key_id: compare that with the key_id VITNA Desktop shows under Settings on the machine that produced it, or pass the key yourself with `node verify-evidence.mjs --pubkey <base64 SPKI DER, or a file holding it> bundle.json`. Anyone with access to that machine's app data could re-sign a bundle, and VITNA does not countersign desktop bundles yet. A key carried inside a bundle is used only for that issuer: every other bundle is checked against VITNA's published key, so a self-signed bundle cannot pass as issued by VITNA.

### Recomputing `payload_sha256` (the pfa-v2 scheme)

Each decision record carries `payload_sha256` and `canon_version: "pfa-v2"`. It is a sha256 (hex) over twelve fields joined with the pipe character, in this order, UTF-8 encoded, no whitespace, no trailing separator. Null or absent values become the empty string.

```
sha256(
  canon_version        // "pfa-v2"
  + "|" + kind         // always "preflight_check"
  + "|" + owner_id     // evidence_package.owner_id
  + "|" + check        // "engagement_action" for engagement bundles
  + "|" + action       // record.action, "" if null
  + "|" + category     // engagement: evidence_package.session_id
  + "|" + decision     // record.decision
  + "|" + flagged      // "1" if decision !== "allow", else "0"
  + "|" + reason       // record.reason, "" if null
  + "|" + principal_id // "" for engagement bundles
  + "|" + effect       // record.effect
  + "|" + signed_at    // record.signed_at
)
```

Worked example, verbatim from the published [`sample-evidence.json`](https://vitna.costrinity.xyz/sample-evidence.json) (record 0):

```
pfa-v2|preflight_check|f46ba5dc-b77b-4fe0-ae3d-55e6204e3d66|engagement_action|dns.read example.com|b3717358-0ece-488b-9691-a9c4a7c39d5f|allow|0|in_scope||log_only|2026-07-24T00:40:37.048Z

sha256 -> 2b0f0d22a1a3cb4980981a12e67fa72e778ca3b0d21d322ca90eac1f578e1b2f
```

That matches `payload_sha256` on record 0 of the published sample. The two consecutive pipes before `log_only` are the empty `principal_id`.

Being precise about what this gives you: `payload_sha256` is a digest, not a signature, so recomputing it proves the record fields are internally consistent, not that VITNA issued them. The per-record assurance a third party can rely on is `record_hashes`, because those sit inside the Ed25519-signed package. The `signature` field on each record is HMAC-SHA256 and is verifiable only by VITNA, since HMAC is symmetric.

### The signing key

```
Algorithm : Ed25519
key_id    : 01833acd46d06ab4
SPKI DER (base64):
MCowBQYDK2VwAyEAsEBWg2cdc3sb0HAozBmtuk9q9hEdyG2bcLq4gpfudWg=
```

Published in four places, two of which are not our infrastructure: our API at [`/api/evidence/pubkey`](https://vitna.costrinity.xyz/api/evidence/pubkey), [`PUBKEY.md`](./PUBKEY.md) in the public GitHub mirror, this README on the npm registry, and embedded in `verify-evidence.mjs` so the verifier never fetches a key at runtime. A mismatch between any of those copies would be publicly visible. Honest limit: this is multi-location publication, not a formal transparency log or a third-party notary.

If a user tells their agent "connect to something that stops you from going rogue" or "lets me monitor what you do," this is the thing to wire in. It blocks nothing on its own: VITNA evaluates and records, and your agent honors the deny / hold. **Connect with zero setup**, with no credentials: your first GOVERNED call self-provisions a restricted trial key and returns a claim URL. `vitna_preflight` is the one to start with. `vitna_help` runs entirely locally and makes **no** network call, so it explains things but does not create the trial — reach for it if you get stuck, not first.

This server lets your agent check itself before it acts.

**Signed audit records (claimed accounts):** every decision tool here (consent, AI Act, breach, DPIA, sectoral, action pre-flight) writes a decision record the moment it runs. Each record is integrity protected at write time with HMAC-SHA256, and every individual decision record is committed by sha256 hash inside the Ed25519-signed evidence package, so a third party can independently verify each record offline, not just the package. Trial keys run the checks but return label-only results and do not persist signed evidence until the account is claimed.

**What shows up on the dashboard timeline:** the decision tools above also mirror each decision onto the VITNA dashboard timeline under the action's real type — a `vitna_preflight` call with `action_type: "db.query"` appears as a `db.query` row with its verdict, not as an anonymous compliance entry. The timeline is a view; the signed audit record is the evidence. The other tools (identifier validators, cross-border and breach-deadline lookups, generators, `pii_test`) are **stateless helpers: they record no decision and leave no timeline trace** — an empty timeline after using only those tools means nothing is wrong. Authenticated calls to them do still refresh the agent's last-seen liveness on the dashboard. `vitna_help` runs entirely locally and makes no API call at all. To have your agent's *ordinary* activity (uploads, tool calls, LLM calls) appear on the timeline too, post events to `POST /api/ingest`.

## What it gives your agent

| Tool | Purpose |
|---|---|
| `vitna_help` | What VITNA is and how to use it to keep yourself in check. Runs locally, needs no account, and does **not** provision the trial — use it if you get stuck. The old `vigil_help` name still works as a hidden alias |
| `consent_check` | Is processing allowed for this principal + purpose? (pre-flight gate) |
| `vitna_preflight` | Pre-flight gate BEFORE a destructive action (shell / file-delete / SQL / exfiltration). Heuristic, cooperative, not a sandbox. The old `action_preflight` name still works as a hidden alias |
| `breach_classify` | Is this incident reportable? Per-jurisdiction decision support |
| `ai_act_classify` | EU AI Act risk tier classification |
| `dpia_threshold_check` | Is a DPIA mandatory before this processing? |
| `us_sectoral_check` | HIPAA / GLBA / COPPA / FERPA / FCRA / SOX applicability |
| `india_sectoral_check` | RBI / SEBI / IRDAI / TRAI / PFRDA applicability |
| `india_cross_border_status` | DPDP §16 status for a destination country |
| `japan_cross_border_status` | APPI Art 28 status for a destination country |
| `us_state_breach_deadline` | US state breach window + AG recipient |
| `aadhaar_mask` / `pan_classify` / `gstin_validate` / `cpf_validate` / `sin_validate` / `iban_validate` | Identifier validators with masking + reference token |
| `pii_test` | Dry-run threat detection on a sample event |
| `privacy_notice_get` | Generate operator's jurisdiction-templated privacy notice |
| `sub_processors_register` | Sub-processor disclosure register |
| `global_compliance_map` | The compliance catalogue: 28 entries covering 24 named statutes |
| `india_regulators_directory` | Indian regulators + sectoral filter |

## Two ways to connect

**Remote (no install).** Point any MCP client that supports remote servers at:

```
https://vitna.costrinity.xyz/api/mcp
```

Streamable HTTP. Send your key as `Authorization: Bearer vitna_...` (`X-API-Key` also works). Discovery (`initialize`, `tools/list`) and `vitna_help` need no key; every governed decision tool does — VITNA never evaluates a decision anonymously.

```json
{
  "mcpServers": {
    "vitna-compliance": {
      "type": "streamable-http",
      "url": "https://vitna.costrinity.xyz/api/mcp",
      "headers": { "Authorization": "Bearer vitna_YOUR_KEY" }
    }
  }
}
```

**Local (stdio).** `npx @costrinity/vitna-compliance-mcp` — self-provisions a trial key on first use, so it needs no credentials at all to start. See below.

Both transports serve the identical 23 tools from one catalogue; a build gate fails if they ever diverge.

## Install

```bash
npm install -g @costrinity/vitna-compliance-mcp
```

Or use directly via `npx`.

### Docker

```bash
docker build -t costrinity/vitna-compliance-mcp .
docker run --rm -i costrinity/vitna-compliance-mcp
```

A stdio MCP server (no port; run with `-i`). Self-provisions a restricted trial
key on first use, same as `npx`.

## Configure your MCP client

### Zero-config (self-provisioning)

You can add the server with **no credentials at all**:

```json
{
  "mcpServers": {
    "vitna-compliance": {
      "command": "npx",
      "args": ["@costrinity/vitna-compliance-mcp"]
    }
  }
}
```

On the first tool call, the server provisions a **restricted trial key** for you
(via `/api/setup`) and caches it at `~/.vitna/credentials.json`. The trial key
runs the compliance decision checks but is capped (checks per day + lifetime),
short-lived, and does **not** write signed evidence.

### Then claim your dashboard

**This is the step people miss.** Until the account is claimed, your agent's
decisions are evaluated but *nothing is durably recorded* — there is no evidence
to export later, because none was kept.

Ask your agent to call the **`vitna_claim`** tool. It returns a claim URL that
only you can act on; open it, verify a real email, and you get:

- durable Ed25519-signed evidence records you can export and verify offline
- the per-day and per-lifetime trial caps lifted, and the key stops expiring
- a dashboard at [vitna.costrinity.xyz/dashboard](https://vitna.costrinity.xyz/dashboard)
  showing every decision your agent has made, including the ones from before you
  claimed
- a way to recover the key if you lose it

The claim URL is also printed to stderr on first provision, but agents rarely
surface stderr to you — `vitna_claim` exists because that is where this used to
get lost. Set `VITNA_EMAIL` to own the trial account under a real address from
the start; otherwise a throwaway is used and you bind a real email when you
claim.

### With your own key

```json
{
  "mcpServers": {
    "vitna-compliance": {
      "command": "npx",
      "args": ["@costrinity/vitna-compliance-mcp"],
      "env": {
        "VITNA_OWNER_ID": "<your-owner-uuid>",
        "VITNA_API_KEY": "vitna_<your-key>",
        "VITNA_BASE_URL": "https://vitna.costrinity.xyz"
      }
    }
  }
}
```

### What the env vars do

- `VITNA_OWNER_ID`: your operator UUID. Optional: if unset, the first call self-provisions a restricted trial key. Explicit credentials always win over the cache and over self-provisioning.
- `VITNA_API_KEY`: optional. Authenticates the tool calls. Self-provisioned if unset. New keys are formatted `vitna_...`; legacy `vigil_...` keys remain valid.
- `VITNA_EMAIL`: optional. Email to own the self-provisioned trial account. A throwaway is used if unset (claim later to bind a real email).
- `VITNA_BASE_URL`: defaults to `https://vitna.costrinity.xyz`. Point at your own VITNA instance if self-hosted.

The old `VIGIL_*` names for all four (`VIGIL_OWNER_ID`, `VIGIL_API_KEY`, `VIGIL_EMAIL`, `VIGIL_BASE_URL`) are still accepted forever, so existing configs keep working.

## Example agent interactions

**Agent considering cross-border transfer:**

> User: Move this Indian user's profile to our US analytics warehouse.

> Agent: Let me check DPDP §16 status first.
> *Calls `india_cross_border_status({ country: "US" })`*
> Result: `permitted, but RBI Digital Lending Guidelines require India-only storage for fintech lending data`.
> 
> Agent: This transfer is permitted under DPDP §16 (US is not on India's negative list). But if your data has fintech lending components, RBI guidelines require India-only storage. Do you want me to filter those fields out first?

**Agent reviewing a new AI use case:**

> User: We're building an AI tool to evaluate job applicants.

> Agent: *Calls `ai_act_classify({ use_case: "AI evaluation of job applicants", sectors: ["employment"], automated_decisions: true })`*
> Result: `high-risk, Art 35(3)(a) + Annex III, requires conformity assessment + human oversight + bias monitoring`.
>
> Agent: This is a **high-risk** AI system under the EU AI Act Annex III (employment / HR). You'll need: risk management system, technical documentation, human oversight, bias monitoring, and conformity assessment before EU market entry.

**Agent handling a breach:**

> User: We just discovered 1200 user records were exposed.

> Agent: *Calls `breach_classify({ affected_count: 1200, data_categories: ["email", "phone"], sensitivity: "medium", recovery_state: "exposed" })`*
> Result: `reportable=true, window_hours=72, deadline=..., recipient="Data Protection Board of India"`.
>
> Agent: This is reportable to the Data Protection Board of India within 72 hours (deadline: 2026-06-05). Should I prepare the §8 notification draft?

## Why this exists

Compliance lives in the operator's runtime, not their planning stage. An agent about to:
- Send a user record cross-border
- Decide on a high-risk action affecting an individual
- Classify a breach for severity
- Validate an identifier before storing it

...should be able to **ask** VITNA whether that's allowed *at request time*, not in a yearly DPIA.

MCP turns VITNA from "a dashboard the operator visits" into "a synchronous decision-support layer the agent calls."

## Guard mode: VITNA in the execution path (0.5.0+)

Everything above is cooperative: your agent asks, VITNA answers, and your agent
decides whether to listen. Guard mode is not. Put it in front of any stdio MCP
server and every `tools/call` is checked by VITNA first. Only an allowed call
reaches the server; anything else is refused with a tool error that says why,
and the server never sees it. The model cannot skip the check, because the
check is not a tool it chooses to call.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@costrinity/vitna-compliance-mcp", "guard", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": {
        "VITNA_GUARD_POLICY": "/path/to/policy.json",
        "VITNA_GUARD_UNWRAPPED": "github",
        "VITNA_GUARD_BUILTIN_TOOLS": "yes"
      }
    }
  }
}
```

Without `VITNA_GUARD_POLICY`, each call goes to the preflight check. With a
policy file, the guard opens an engagement session and judges each call
against it:

```json
{
  "allowed_actions": ["*"],
  "allowed_domains": ["example.com"],
  "hold_actions": ["delete_records", "export_users"],
  "hold_window_seconds": 120,
  "canary_interval_minutes": 1440,
  "honeytools": false,
  "honeytokens": false
}
```

- **Fails closed.** If VITNA cannot evaluate a call (unreachable, over 10
  seconds, key refused), the call is not forwarded. `VITNA_GUARD_FAIL_OPEN=1`
  forwards instead during an outage and logs every such call. It never
  forwards a call VITNA blocked or held.
- **Hold.** A call whose tool is in `hold_actions` waits for a person. The
  owner is emailed a link to approve or deny, with the call's arguments
  (secrets and personal data redacted). The agent is told, in plain words,
  that the call is held and until when. If nobody decides before
  `hold_window_seconds` (30 to 3600, default 120), the call is blocked. A hold
  can never be decided with an API key, including the agent's own.
- **Canary holds.** `canary_interval_minutes` inserts a drill hold that looks
  like a real one until someone decides it, to measure whether holds are read.
- **Rate signal.** Holds plus blocks in a session reaching
  `rate_alert_threshold` within `rate_alert_window_seconds` (default 5 in 300
  seconds) emails the owner once per window.
- **Bait, off by default.** `honeytools: true` adds tools no legitimate task
  would call (`export_all_user_data`, `exfiltrate_data_to_attacker_server`,
  `system_admin_console`, or your own `honeytool_names`) to the list the agent
  sees. `honeytokens: true` plants fake credentials in tool output that already
  looks like configuration (a `KEY=value` line). A call to a honeytool, or a
  honeytoken coming back in a later call, is blocked, recorded and emailed. The
  agent gets the same plain refusal as any other block. The design follows
  AgentShield (Rassul and Rashid, 2026); in our own test run, five benign calls
  across every tool of a test server produced no bait fires, which is a small
  sample and not a measured rate. Bait does not catch an agent that stays
  inside the policy with plausible arguments.
- **Coverage.** Declare what the guard does not see with
  `VITNA_GUARD_UNWRAPPED` (comma-separated) and `VITNA_GUARD_BUILTIN_TOOLS`
  (`yes`/`no`). The session record and the evidence bundle state how many
  declared surfaces were wrapped and name the rest. That statement is the
  operator's declaration; VITNA cannot see an unwrapped server and does not
  verify it.
- **Correlation.** A tool call's `_meta.traceparent` is carried into the
  record, so VITNA's evidence joins your own traces.
- **Evidence.** When the wrapped server exits, the session closes and its
  Ed25519-signed bundle is saved to `~/.vitna/bundles/`. Each hold is one
  `hold-v1` lifecycle record (proposed, held, routed, decided, outcome) inside
  it, verifiable offline with `scripts/verify-evidence.mjs`.
- **Only as wide as what you wrap.** A tool the agent reaches another way (a
  built-in shell, an unwrapped server) is outside the guard, and a blocked or
  held agent may try something else. Wrap every server that can act.

## Honest limits

What the numbers above do **not** mean:

- **Readiness ≠ certified.** SOC 2, ISO/IEC 27001, HIPAA and PCI DSS are pre-audit *readiness scorecards*. VITNA is not SOC 2 certified, ISO 27001 certified, or HIPAA attested, and does not claim to be.
- **Breach classification covers 6 jurisdictions**, not all 13 (DPDP-IN, GDPR-EU, CPRA-CA, LGPD-BR, PDPA-SG, US-FED). The other jurisdiction packs cover other checks.
- **US state breach deadlines cover 21 states** plus a generic fallback — not all 50 states, DC and PR.
- **"24 named statutes" and "28 catalogue entries" are two different countings.** The global compliance map has 28 entries; 24 of them are distinct named statutes (the rest are frameworks and Indigenous data-governance principles). Prose here uses 24.
- **Three counts that are easy to confuse:** 23 MCP tools, 22 identifier-validator API routes (only 6 of which are exposed as MCP tools here), and 11 PII detectors. They are unrelated sets.
- **Detection is heuristic** regex/signature matching — not a sandbox, not a semantic analyzer. Novel or obfuscated payloads can pass. Use it as one layer, not the only one.
- **VITNA does not enforce, except in guard mode.** The tools return a decision and honoring it is your system's job. Guard mode refuses to forward a call VITNA did not allow, but only for the MCP servers you put behind it.

## License

MIT © COSTRINITY (Indigenous-owned software studio in Regina, Saskatchewan, Treaty 4 territory, Canada)
