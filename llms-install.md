# Installing the VITNA guard (for AI agents and installers)

The VITNA guard wraps stdio MCP servers: it sits between the MCP client and one
stdio server, and each tool call goes to VITNA before the server sees it.
Calls to tools in the policy's hold list wait for a person; no answer, no run.
Detection is heuristic, not a sandbox. VITNA's remote endpoint is cooperative
checks, not containment.

## 1. Write a policy file

Save this as `policy.json` (the tool names are the reference filesystem
server's; use your server's own):

```json
{
  "allowed_actions": ["*"],
  "hold_actions": ["write_file", "edit_file", "move_file"]
}
```

## 2. Wrap the stdio server

Put `npx -y @costrinity/vitna-compliance-mcp guard --` in front of the server's
own command. For the reference filesystem server, in a client that uses an
`mcpServers` JSON config (Claude Desktop, Cline and others):

```json
{
  "mcpServers": {
    "files-guarded": {
      "command": "npx",
      "args": ["-y", "@costrinity/vitna-compliance-mcp", "guard", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/folder"],
      "env": {
        "VITNA_OWNER_ID": "<your VITNA owner id>",
        "VITNA_API_KEY": "<your VITNA API key>",
        "VITNA_GUARD_POLICY": "/path/to/policy.json"
      }
    }
  }
}
```

## 3. Environment variables

- `VITNA_OWNER_ID` and `VITNA_API_KEY`: the agent's VITNA owner id and API key
  (VITNA dashboard). Without them, the first call starts a restricted trial.
- `VITNA_GUARD_POLICY`: the path to `policy.json`.
- `VITNA_GUARD_CLIENT_TIMEOUT_SECONDS`: optional. Set it only together with the
  client's own tool-call timeout, to a value no higher than that timeout.

## 4. Timeouts

A held call waits for a person. The guard reads the client's name and waits
at most that client's documented timeout, less a margin; a client it does not
know is waited on for 4 seconds. (The timeouts come from each client's docs or
source and are not yet confirmed by a recorded run.) When the wait ends with
the hold still open, the call is answered "held, not run"; if the person
approves later, the same call retried within 10 minutes of the approval runs
once. To wait longer in place, raise the
client's own tool-call timeout and set `VITNA_GUARD_CLIENT_TIMEOUT_SECONDS` to
match. Per-client settings: https://vitna.costrinity.xyz/connect

## Scope

The guard covers the tool calls of the stdio servers it wraps. Tools the client
has outside the guard, and the model provider's own built-in tools, are not
checked. Setup for each client: https://vitna.costrinity.xyz/connect
