# VITNA evidence signing key (public)

This is the **public** half of the key VITNA uses to sign evidence packages.
It is published here, on GitHub, so the key exists on infrastructure COSTRINITY
does not control, in addition to our own API. Compare the copies.

```
Algorithm : Ed25519
key_id    : 01833acd46d06ab4
SPKI DER (base64):
MCowBQYDK2VwAyEAsEBWg2cdc3sb0HAozBmtuk9q9hEdyG2bcLq4gpfudWg=
```

PEM form:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsEBWg2cdc3sb0HAozBmtuk9q9hEdyG2bcLq4gpfudWg=
-----END PUBLIC KEY-----
```

## Where this key is published

Four independent locations. Two of them are not our infrastructure:

1. Our API: <https://vitna.costrinity.xyz/api/evidence/pubkey>
2. This file, in the public GitHub mirror (GitHub, not our infrastructure)
3. The README of the npm package `@costrinity/vitna-compliance-mcp` (npm registry, not our infrastructure)
4. Embedded directly in `verify-evidence.mjs`, so the verifier never fetches a key at runtime

Because the verifier ships with the key embedded and the same key is published
on GitHub and npm, a mismatch between any of those copies and our API would be
publicly visible. Stating the honest limit: this is multi-location publication,
not a formal key transparency log and not a third-party notary.

## Verify an evidence package with it

```bash
curl -sO https://raw.githubusercontent.com/COSTRINITY/vitna-compliance-mcp/main/verify-evidence.mjs
curl -sO https://vitna.costrinity.xyz/sample-evidence.json
node verify-evidence.mjs sample-evidence.json
```

The verifier checks the Ed25519 signature over the whole package, then
recomputes the sha256 of each individual decision record and confirms it
matches the hash committed inside the signed package, printing PASS or FAIL per
record.

A VALID result proves the package was issued by VITNA and has not been altered
since export, and that every record matches its committed hash. It does not
prove the actions were performed or that the records are factually true.

## What is never published

The private signing key. It lives only in server-side environment
configuration, is not in this repository, and is not in the repository history.
If you ever find private key material in a COSTRINITY repository, please report
it via the contact in `SECURITY.md` of the main project.
