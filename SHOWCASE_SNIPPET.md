# VITNA Compliance MCP showcase snippet

Paste-ready showcase for `@costrinity/vitna-compliance-mcp` (bin: `vitna-compliance-mcp`). Share after publishing the release (see RUNBOOK.md).

Run:
`npx @costrinity/vitna-compliance-mcp`

MCP client config:

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

Replace `VITNA_OWNER_ID` and `VITNA_API_KEY` with the values from your VITNA dashboard.

Tools (22): consent_check, breach_classify, ai_act_classify, dpia_threshold_check, us_sectoral_check, india_sectoral_check, india_cross_border_status, japan_cross_border_status, us_state_breach_deadline, aadhaar_mask, pan_classify, gstin_validate, cpf_validate, sin_validate, iban_validate, pii_test, privacy_notice_get, sub_processors_register, global_compliance_map, india_regulators_directory
