#!/usr/bin/env bash
#
# VITNA pre-flight + signed-record demo. Runs the REAL flow against the live
# VITNA API using YOUR account credentials: it runs a couple of compliance
# decision checks (each writes a signed, tamper-evident audit record to your
# account) and then retrieves and shows those signed records. Nothing is
# deleted. Your API key is masked in the output.
#
# Usage:
#   VIGIL_API_KEY=vigil_xxx VIGIL_OWNER_ID=<your-owner-uuid> ./demo-preflight.sh
#   (optional) VIGIL_BASE_URL=https://vitna.costrinity.xyz
#
# Get VIGIL_API_KEY and VIGIL_OWNER_ID from your VITNA dashboard.
# Requires: bash, curl, node.
set -euo pipefail

APP="${VIGIL_BASE_URL:-https://vitna.costrinity.xyz}"
KEY="${VIGIL_API_KEY:-}"
OWNER="${VIGIL_OWNER_ID:-}"
if [ -z "$KEY" ] || [ -z "$OWNER" ]; then
  echo "Set VIGIL_API_KEY and VIGIL_OWNER_ID (from your VITNA dashboard) and re-run."
  echo "  VIGIL_API_KEY=vigil_xxx VIGIL_OWNER_ID=<uuid> ./demo-preflight.sh"
  exit 1
fi
MASK="${KEY:0:12}**********"

# Print selected JSON fields as key=value (via node; no jq dependency).
fields() { printf '%s' "$1" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const o=JSON.parse(s);console.log(process.argv.slice(1).map(k=>k+'='+JSON.stringify(o[k])).join('  '))})" "${@:2}"; }

echo "===================================================================="
echo " VITNA pre-flight checks -> signed audit records    LIVE: $APP"
echo " owner ${OWNER:0:8}...   key ${MASK}   (api key masked)"
echo "===================================================================="
echo ""
echo " CHECK 1  ai-act-classify  (employment + automated decisions)"
R=$(curl -s -X POST "$APP/api/compliance/ai-act-classify?owner_id=$OWNER" -H "x-vigil-key: $KEY" -H "Content-Type: application/json" -d '{"use_case":"screen job applicants","sectors":["employment"],"automated_decisions":true}')
echo "   $(fields "$R" check risk_tier effect)"
echo ""
echo " CHECK 2  breach-classify  (1200 records exposed)"
R=$(curl -s -X POST "$APP/api/compliance/breach-classify?owner_id=$OWNER" -H "x-vigil-key: $KEY" -H "Content-Type: application/json" -d '{"affected_count":1200,"data_categories":["email","phone"],"sensitivity":"medium","recovery_state":"exposed"}')
echo "   $(fields "$R" check reportable effect)"
echo ""
echo " SIGNED RECORDS  (GET /api/compliance/preflight-audit) -- written before each response:"
curl -s "$APP/api/compliance/preflight-audit?owner_id=$OWNER&limit=10" -H "x-vigil-key: $KEY" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const recs=(JSON.parse(s).records)||[];for(const n of ['ai_act_classify','breach_classify']){const r=recs.find(x=>x.check===n);if(r)console.log('   '+n.padEnd(18)+'decision='+String(r.decision).padEnd(14)+'signed='+r.signed+'  verified='+r.signature_verified+'  sha256='+String(r.payload_sha256).slice(0,16)+'...');}})"
echo ""
echo "===================================================================="
echo " Real calls against $APP. HMAC-SHA256 signed, owner-scoped, no raw PII."
echo "===================================================================="
