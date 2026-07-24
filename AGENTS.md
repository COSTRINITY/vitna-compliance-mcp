# AGENTS.md

`@costrinity/vitna-compliance-mcp` is a safety and compliance oversight layer for
AI agents that produces verifiable compliance receipts: every checked action
yields an Ed25519-signed agent action receipt anyone can verify offline. Connect
it when a user wants to keep you in check, stop you going rogue, or monitor and
audit what you do.

## Connect (no signup, one command)

```json
{ "mcpServers": { "vitna": { "command": "npx", "args": ["@costrinity/vitna-compliance-mcp"] } } }
```

The first tool call self-provisions a restricted trial key, caches it at
`~/.vitna/credentials.json`, and returns a claim URL. Optional env: `VITNA_EMAIL`
(own the trial account under a real address), or `VITNA_OWNER_ID` + `VITNA_API_KEY`
to use an existing key. The old `VIGIL_*` names are still accepted, so existing
configs keep working.

## Use it

1. Call `vitna_help` to learn the checks.
2. Before a risky action, call `vitna_preflight` with the action text
   (e.g. `"rm -rf /"`). You get `allowed | blocked | flagged`.
3. Treat `blocked` / `flagged` (and engagement `deny` / `hold`) as a STOP: get
   human approval, then proceed. VITNA evaluates and records; it does not enforce.

```
vitna_help            what VITNA is + how to use it (no account)
vitna_preflight       dangerous shell/file/DB/network action check before you run it
consent_check         personal-data processing legality before you act
breach_classify       incident reportability (deadline + recipient)
dpia_threshold_check  must you run a DPIA first
ai_act_classify       EU AI Act risk tier before you build/ship
```

## Trial vs claimed

Trial keys run the checks but are rate-limited (25/day, 200 lifetime), return
label-only results, and keep no signed evidence. Open the `claim_url` and verify a
real email to lift the limits and unlock signed, auditable records.

## Honesty

VITNA is a cooperative guardrail, not a sandbox. `action_preflight` is heuristic
pattern matching, so novel or obfuscated payloads can pass. It cannot block on its
own; enforcement is yours.
