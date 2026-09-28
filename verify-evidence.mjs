#!/usr/bin/env node
/**
 * Offline, independent verifier for a VITNA evidence package.
 *
 *   node verify-evidence.mjs path/to/evidence.json     (or pipe the JSON via stdin)
 *   node verify-evidence.mjs --pubkey <key> path/to/evidence.json
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
 *
 * VITNA Desktop bundles are the exception. VITNA Desktop signs on the user's
 * machine with a key it generated there, and says so inside the signed
 * package: issuer "vitna-desktop-local", signer_key_id, signer_public_key.
 * Such a bundle is checked against --pubkey <base64 SPKI DER, or a file
 * holding it> when given, else against the signer_public_key it carries, and
 * is reported as signed by a local VITNA Desktop key, not by VITNA. VALID then
 * proves only that whoever holds that key signed it and nothing changed since;
 * anyone with access to that machine's app data could re-sign.
 *
 * The carried key is used for that issuer ONLY. Every other package is checked
 * against VITNA's key (or --pubkey, reported as the reader's key), so a
 * self-signed package that carries its own key cannot pass as issued by VITNA.
 */
import { readFileSync, existsSync, statSync } from 'node:fs';
import { createPublicKey, createHash, verify } from 'node:crypto';

const PUBLIC_KEY_B64 = 'MCowBQYDK2VwAyEAsEBWg2cdc3sb0HAozBmtuk9q9hEdyG2bcLq4gpfudWg=';
const KEY_ID = '01833acd46d06ab4';
// What VITNA Desktop writes as `issuer` inside every package it signs locally.
const LOCAL_ISSUER = 'vitna-desktop-local';

// MUST byte-for-byte match lib/evidenceSign.ts canonicalize().
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

const usage = 'Usage: node verify-evidence.mjs [--pubkey <base64 SPKI DER | file>] [evidence.json]';
const fail = (msg) => { console.error('ERROR: ' + msg); process.exit(2); };

// Two key id schemes, one per signer, both 16 hex chars. VITNA's
// (lib/evidenceSign.ts) hashes the SPKI DER; VITNA Desktop's hashes the raw
// 32-byte key, which is the tail of an Ed25519 SPKI DER.
const spkiDer = (key) => key.export({ format: 'der', type: 'spki' });
const cloudKeyId = (key) => createHash('sha256').update(spkiDer(key)).digest('hex').slice(0, 16);
const localKeyId = (key) => createHash('sha256').update(spkiDer(key).subarray(-32)).digest('hex').slice(0, 16);

// A public key given as base64 SPKI DER, PEM, or raw DER bytes. Anything that
// is not an Ed25519 public key throws, so a wrong key is refused, not guessed at.
function parsePublicKey(bytes) {
  const der = bytes[0] === 0x30 && bytes[1] === 0x2a
    ? bytes
    : Buffer.from(bytes.toString('utf8').replace(/-----[^-]*-----/g, '').replace(/\s+/g, ''), 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 public key');
  return key;
}

let inputPath = null;
let pubkeyArg = null;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--help' || a === '-h') {
    console.log(usage);
    process.exit(0);
  } else if (a === '--pubkey' || a.startsWith('--pubkey=')) {
    pubkeyArg = a === '--pubkey' ? argv[++i] : a.slice('--pubkey='.length);
    if (!pubkeyArg) fail('--pubkey needs a value.\n' + usage);
  } else if (a.startsWith('--')) fail('unknown option ' + a + '.\n' + usage);
  else if (inputPath === null) inputPath = a;
  else fail('more than one input file given.\n' + usage);
}

// A value that names an existing file is read from it; anything else is the key.
let supplied = null;
if (pubkeyArg) {
  try {
    const isFile = existsSync(pubkeyArg) && statSync(pubkeyArg).isFile();
    supplied = parsePublicKey(isFile ? readFileSync(pubkeyArg) : Buffer.from(pubkeyArg, 'utf8'));
  } catch {
    fail('--pubkey is not an Ed25519 public key (base64 SPKI DER, or a path to a file holding it).');
  }
}

const src = inputPath ? readFileSync(inputPath, 'utf8') : readFileSync(0, 'utf8');
const doc = JSON.parse(src);
const pkg = doc.evidence_package ?? doc;
const sig = doc.package_signature?.signature ?? doc.signature;
if (!pkg || typeof pkg !== 'object' || typeof sig !== 'string') {
  console.error('ERROR: could not find evidence_package + package_signature.signature in the input.');
  process.exit(2);
}

// Which kind of package this is comes from the issuer INSIDE the signed
// package, never from the unsigned package_signature beside it. Adding or
// removing the field changes the signed bytes, so a package cannot switch
// sides after it was signed.
const isLocal = pkg.issuer === LOCAL_ISSUER;
const vitnaKey = createPublicKey({ key: Buffer.from(PUBLIC_KEY_B64, 'base64'), format: 'der', type: 'spki' });
const suppliedIsVitna = supplied !== null && spkiDer(supplied).equals(spkiDer(vitnaKey));

// source: 'vitna' (VITNA's published key), 'supplied' (--pubkey) or
// 'embedded' (signer_public_key, desktop-local packages only).
let pub = null;
let source;
if (isLocal && supplied) {
  pub = supplied;
  source = 'supplied';
} else if (isLocal) {
  source = 'embedded';
  try { pub = parsePublicKey(Buffer.from(String(pkg.signer_public_key ?? ''), 'utf8')); } catch { pub = null; }
} else if (supplied && !suppliedIsVitna) {
  pub = supplied;
  source = 'supplied';
} else {
  pub = vitnaKey;
  source = 'vitna';
}
const usedKeyId = !pub ? null : source === 'vitna' ? KEY_ID : isLocal ? localKeyId(pub) : cloudKeyId(pub);

let pkgOk = false;
if (pub) {
  try { pkgOk = verify(null, Buffer.from(canonicalize(pkg), 'utf8'), pub, Buffer.from(sig, 'base64')); } catch { pkgOk = false; }
}
const inPkgKeyId = doc.package_signature?.public_key_id ?? '(none)';

// For a desktop-local package the key id is the reader's only link to a
// machine, so every id the package states must name the key that verified it.
let keyIdsOk = true;

console.log('VITNA evidence verification (offline, Ed25519)');
if (isLocal) {
  console.log('  issuer              :', LOCAL_ISSUER);
  console.log('  signed by a local VITNA Desktop key, not by VITNA');
  console.log('  key used            :', source === 'supplied'
    ? 'the key given with --pubkey'
    : pub ? 'signer_public_key, carried inside the signed package' : 'none (the package carries no usable signer_public_key)');
  if (pub) {
    console.log('  signer key_id       :', usedKeyId);
    for (const [label, id] of [['package key_id      :', doc.package_signature?.public_key_id], ['in-package key_id   :', pkg.signer_key_id]]) {
      if (id !== usedKeyId) keyIdsOk = false;
      console.log('  ' + label, id ?? '(none)', id === usedKeyId ? '(match)' : '(MISMATCH)');
    }
    if (source === 'supplied' && pkg.signer_public_key !== undefined) {
      let same = false;
      try { same = spkiDer(parsePublicKey(Buffer.from(String(pkg.signer_public_key), 'utf8'))).equals(spkiDer(pub)); } catch { same = false; }
      if (!same) keyIdsOk = false;
      console.log('  carried signer key  :', same ? 'same as --pubkey (match)' : 'differs from --pubkey (MISMATCH)');
    }
  }
  console.log('  package signature   :', pkgOk ? 'valid' : 'INVALID');
  if (source === 'embedded' && pub) {
    console.log('    This key came from inside the package. Compare key_id ' + usedKeyId + ' with the');
    console.log('    one shown in VITNA Desktop (Settings) on the machine that produced it:');
    console.log('    that comparison is what ties this package to that machine.');
  }
} else {
  if (source === 'supplied') console.log("  key used            : supplied by the reader with --pubkey, not VITNA's published key");
  else if (supplied) console.log("  key used            : the key given with --pubkey, which is VITNA's published key");
  if (pkg.signer_public_key !== undefined) {
    console.log('  embedded signer key : ignored; a package is checked with a key it carries only when');
    console.log('                        its signed issuer is ' + LOCAL_ISSUER);
  }
  if (doc.package_signature?.issuer === LOCAL_ISSUER) {
    console.log('  signature issuer    : ' + LOCAL_ISSUER + ', but the signed package does not say so;');
    console.log('                        checked as a VITNA package');
  }
  console.log('  expected key_id    :', usedKeyId);
  console.log('  package key_id      :', inPkgKeyId, inPkgKeyId === usedKeyId ? '(match)' : '(MISMATCH)');
  console.log('  package signature   :', pkgOk ? 'valid' : 'INVALID');
}
// Coverage first: how much of the agent's tool surface the guard covered, as
// declared by the operator. Shown before any decision, because a verified
// record of a partial surface is still a partial record.
if (pkg.coverage) {
  // Desktop output puts full coverage in words rather than the schema's data
  // value. The cloud line stays as already published.
  const level = String(pkg.coverage.coverage);
  console.log('  guard coverage      :', (isLocal && level === 'complete' ? 'every declared surface wrapped' : level).toUpperCase());
  console.log('    ' + pkg.coverage.statement);
}

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
  const canons = [...new Set(records.map((r) => r?.canon_version ?? '(none)'))];
  console.log('  decision canon      :', canons.join(', '));
} else {
  console.log('  per-record checks   : not available (legacy bundle without record_hashes; package-level verification only)');
}

// Hold lifecycles (canon hold-v1): each hold's whole life, proposed to outcome,
// in one record committed by hash inside the signed bundle. A hold approved
// after the fact cannot be rewritten as approved before: the timestamps are in
// the hashed record.
if (Array.isArray(pkg.holds)) {
  const hh = Array.isArray(pkg.hold_record_hashes) ? pkg.hold_record_hashes : [];
  console.log('  hold canon          :', pkg.hold_canon_version ?? '(unspecified)');
  console.log('  hold lifecycles     :', pkg.holds.length, 'record(s)');
  if (hh.length !== pkg.holds.length) {
    recordsOk = false;
    console.log('    FAIL: hold_record_hashes length ' + hh.length + ' does not match holds ' + pkg.holds.length);
  }
  pkg.holds.forEach((h, i) => {
    const pass = sha256hex(canonicalize(h)) === hh[i];
    if (!pass) recordsOk = false;
    console.log('    [' + (pass ? 'PASS' : 'FAIL') + '] hold ' + i + ' (' + (h?.canon_version ?? '?') + '): ' + (h?.action ?? '?') + ' -> ' + (h?.decision ?? '?') + (h?.drill ? ' [drill]' : '') + (h?.decided_by ? ' by ' + h.decided_by : ''));
  });
}

// Completeness. A signature proves authenticity and integrity; it says
// nothing about whether the package holds every record in its scope. An
// export capped at 1000 records used to verify VALID and look identical to
// a complete one, so the verdict below distinguishes the two explicitly.
const completeness = pkg.completeness ?? null;
const missing = completeness && typeof completeness.records_matching_scope === 'number'
  ? completeness.records_matching_scope - (completeness.records_included ?? 0)
  : 'an unknown number of';
console.log('');
if (isLocal) {
  // Same question, desktop wording: does the package state how many records
  // its scope holds, and are they all here.
  if (completeness) {
    console.log('  records in scope    :', completeness.complete ? 'ALL INCLUDED' : 'PARTIAL');
    console.log('    records included  :', completeness.records_included);
    console.log('    matching scope    :', completeness.records_matching_scope ?? 'unknown');
    if (!completeness.complete) console.log('    MISSING           : ' + missing + ' record(s) are NOT in this package');
  } else {
    console.log('  records in scope    : NOT ATTESTED');
    console.log('    This package does not state how many records its scope holds, so');
    console.log('    neither it nor its signature can tell you whether any were left out.');
  }
} else if (completeness) {
  console.log('  completeness        :', completeness.complete ? 'COMPLETE' : 'PARTIAL');
  console.log('    records included  :', completeness.records_included);
  console.log('    matching scope    :', completeness.records_matching_scope ?? 'unknown');
  if (!completeness.complete) {
    console.log('    MISSING           : ' + missing + ' record(s) are NOT in this package');
  }
} else {
  console.log('  completeness        : NOT ATTESTED (pre-v2 package)');
  console.log('    This package predates completeness attestation. It may be a');
  console.log('    complete export or a silently truncated one; the format does');
  console.log('    not say, and the signature cannot tell you.');
}

console.log('');
if (pkgOk && keyIdsOk && recordsOk) {
  if (isLocal) {
    const line = 'signed by a local VITNA Desktop key, not by VITNA (key_id ' + usedKeyId + '), not altered since it was signed' + (hashes ? ', and every record matches its committed hash.' : '.');
    if (completeness && completeness.complete) {
      console.log('VALID, all records in scope: ' + line);
    } else if (completeness) {
      console.log('VALID but PARTIAL: ' + line);
      console.log('       This package is a SUBSET of its own stated scope. Every record in');
      console.log('       it is authentic, but records matching the scope are missing. Do not');
      console.log('       treat it as a full record of the period it claims to cover.');
    } else {
      console.log('VALID, record count not attested: ' + line);
      console.log('       Whether it holds every record in its scope is not stated and cannot');
      console.log('       be determined from the package.');
    }
    console.log('       VITNA did not sign or countersign it. Anyone with access to the app data');
    console.log('       of the machine holding this key could re-sign a package with it.');
    console.log('       (Does NOT prove the underlying records are factually true.)');
    process.exit(0);
  }
  const signer = source === 'vitna'
    ? 'issued by VITNA'
    : "signed by the key given with --pubkey (key_id " + usedKeyId + "), which is not VITNA's published key";
  const line = signer + ', not altered since export' + (hashes ? ', and every record matches its committed hash.' : '.');
  if (completeness && completeness.complete) {
    console.log('VALID and COMPLETE: ' + line);
  } else if (completeness) {
    console.log('VALID but PARTIAL: ' + line);
    console.log('       This package is a SUBSET of its own stated scope. Every record in');
    console.log('       it is authentic, but records matching the scope are missing. Do not');
    console.log('       treat it as a full record of the period it claims to cover.');
  } else {
    console.log('VALID, completeness unknown: ' + line);
    console.log('       Pre-v2 package: whether it contains every record in its scope is');
    console.log('       not attested and cannot be determined from the package.');
  }
  console.log('       (Does NOT prove the underlying records are factually true.)');
  process.exit(0);
}
if (isLocal) {
  console.log('INVALID: ' + (!pub
    ? 'no usable signer key. The package carries no valid signer_public_key; pass the signer\'s public key with --pubkey.'
    : !pkgOk
      ? 'package signature failed with ' + (source === 'supplied' ? 'the key given with --pubkey' : 'the key carried in the package') + ' (altered since it was signed, or signed by a different key).'
      : !keyIdsOk
        ? 'the package names a signer key that is not the key that verified it (' + usedKeyId + ').'
        : 'a decision or hold record does not match its committed hash (record tampered).'));
  console.log('       This package names a local VITNA Desktop key as its signer, not VITNA.');
  process.exit(1);
}
console.log('INVALID: ' + (!pkgOk
  ? (source === 'vitna'
    ? 'package signature failed (altered, not signed by VITNA, or key mismatch).'
    : 'package signature failed with the key given with --pubkey (altered, or signed by a different key).')
  : 'a decision or hold record does not match its committed hash (record tampered).'));
process.exit(1);
