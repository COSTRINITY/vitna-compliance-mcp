#!/usr/bin/env node
/**
 * Offline, independent verifier for a VITNA evidence package.
 *
 *   node verify-evidence.mjs path/to/evidence.json     (or pipe the JSON via stdin)
 *
 * Uses ONLY Node's built-in crypto and VITNA's published Ed25519 public key
 * (below). No VITNA account, no VITNA secret, no network. Cross-check the
 * embedded key against the published one at:
 *   https://vitna.costrinity.xyz/api/evidence/pubkey   (key_id must match)
 *
 * A VALID result proves: this package was issued by VITNA (holder of the
 * evidence private key) and has not been altered since export, and, when the
 * package carries record_hashes, that every individual decision record matches
 * its committed hash inside the signed package. It does NOT prove the
 * underlying records are factually true.
 */
import { readFileSync } from 'node:fs';
import { createPublicKey, createHash, verify } from 'node:crypto';

const PUBLIC_KEY_B64 = 'MCowBQYDK2VwAyEAsEBWg2cdc3sb0HAozBmtuk9q9hEdyG2bcLq4gpfudWg=';
const KEY_ID = '01833acd46d06ab4';

// MUST byte-for-byte match lib/evidenceSign.ts canonicalize().
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

const src = process.argv[2] ? readFileSync(process.argv[2], 'utf8') : readFileSync(0, 'utf8');
const doc = JSON.parse(src);
const pkg = doc.evidence_package ?? doc;
const sig = doc.package_signature?.signature ?? doc.signature;
if (!pkg || typeof pkg !== 'object' || typeof sig !== 'string') {
  console.error('ERROR: could not find evidence_package + package_signature.signature in the input.');
  process.exit(2);
}

const pub = createPublicKey({ key: Buffer.from(PUBLIC_KEY_B64, 'base64'), format: 'der', type: 'spki' });
const pkgOk = verify(null, Buffer.from(canonicalize(pkg), 'utf8'), pub, Buffer.from(sig, 'base64'));
const inPkgKeyId = doc.package_signature?.public_key_id ?? '(none)';

console.log('VITNA evidence verification (offline, Ed25519)');
console.log('  expected key_id    :', KEY_ID);
console.log('  package key_id      :', inPkgKeyId, inPkgKeyId === KEY_ID ? '(match)' : '(MISMATCH)');
console.log('  package signature   :', pkgOk ? 'valid' : 'INVALID');

// Per-record verification. Present on current bundles (record_hashes committed
// inside the signed package). Absent on legacy bundles, which still verify at
// the package level.
const records = Array.isArray(pkg.decisions)
  ? pkg.decisions
  : Array.isArray(pkg.records)
    ? pkg.records
    : null;
const hashes = Array.isArray(pkg.record_hashes) ? pkg.record_hashes : null;
let recordsOk = true;
if (hashes && records) {
  console.log('  record hash algo    :', pkg.record_hash_algorithm ?? '(unspecified)');
  console.log('  per-record checks   :', records.length, 'record(s)');
  if (hashes.length !== records.length) {
    recordsOk = false;
    console.log('    FAIL: record_hashes length ' + hashes.length + ' does not match records ' + records.length);
  }
  for (let i = 0; i < records.length; i++) {
    const pass = sha256hex(canonicalize(records[i])) === hashes[i];
    if (!pass) recordsOk = false;
    const label = records[i]?.action ?? records[i]?.check ?? records[i]?.id ?? ('#' + i);
    console.log('    [' + (pass ? 'PASS' : 'FAIL') + '] record ' + i + ': ' + label);
  }
} else {
  console.log('  per-record checks   : not available (legacy bundle without record_hashes; package-level verification only)');
}

console.log('');
if (pkgOk && recordsOk) {
  console.log('VALID: issued by VITNA, not altered since export' + (hashes ? ', and every record matches its committed hash.' : '.'));
  console.log('       (Does NOT prove the underlying records are factually true.)');
  process.exit(0);
}
console.log('INVALID: ' + (!pkgOk
  ? 'package signature failed (altered, not signed by VITNA, or key mismatch).'
  : 'a decision record does not match its committed hash (record tampered).'));
process.exit(1);
