#!/usr/bin/env node
// ap2-verify — independent JavaScript verifier of ap2-evidence-pack evidence files (SPEC_AP2_EVIDENCE.md), Node with OpenSSL >= 3.5 for ML-DSA-65,
// node:crypto only (no ap2_evidence code, no dependency). Same normative facts as ap2_evidence.verify_evidence:
// digest_ok, per-artifact ES256 signature / disclosures / KB-JWT, bindings, producer signatures (ed25519, ecdsa-p256;
// ml-dsa-65 through the Node build's OpenSSL >= 3.5, else SKIP = incomplete, never a pass), policy flags, valid.
// Acceptance profile of the file (SPEC §3.1): strict UTF-8, no BOM, no duplicate keys, no floats, integers within
// +/-(2^53-1), nesting <= 512, no lone surrogate escape, 64 MiB bound. A refused file is a receipt with valid=false.
// Usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--tsa-cert PEM]
import { readFileSync, statSync } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

const MAX_DEPTH = 512, MAX_BYTES = 64 * 1024 * 1024, SAFE = 2 ** 53 - 1;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
class Refused extends Error {}

// ---- strict JSON parser (keeps number lexemes; refuses what the profile refuses) ----
function parseStrict(text) {
  let i = 0, depth = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const err = (m) => { throw new Refused(m + " at " + i); };
  function str() {
    i++; let out = "";
    for (;;) { if (i >= text.length) err("eof in string"); const c = text[i++];
      if (c === '"') return out;
      if (c === "\\") { const e = text[i++];
        if (e === "u") { const h = text.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) err("bad \\u"); i += 4; let cp = parseInt(h, 16);
          if (cp >= 0xd800 && cp <= 0xdbff) { if (text[i] === "\\" && text[i + 1] === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { const lo = parseInt(text.slice(i + 2, i + 6), 16); if (lo >= 0xdc00 && lo <= 0xdfff) { i += 6; cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); } else err("lone surrogate"); } else err("lone surrogate"); }
          else if (cp >= 0xdc00 && cp <= 0xdfff) err("lone surrogate");
          out += String.fromCodePoint(cp); }
        else { const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }; if (!(e in map)) err("bad escape"); out += map[e]; } }
      else { if (c.charCodeAt(0) < 0x20) err("control character in string"); out += c; } }
  }
  function value() {
    ws(); const c = text[i];
    if (c === "{") { if (++depth > MAX_DEPTH) err("too deep"); i++; const o = Object.create(null); ws(); if (text[i] === "}") { i++; depth--; return o; }
      for (;;) { ws(); if (text[i] !== '"') err("key"); const k = str(); ws(); if (text[i] !== ":") err("colon"); i++; if (k in o) err("duplicate key " + k); o[k] = value(); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "}") { i++; depth--; return o; } err("object"); } }
    if (c === "[") { if (++depth > MAX_DEPTH) err("too deep"); i++; const a = []; ws(); if (text[i] === "]") { i++; depth--; return a; }
      for (;;) { a.push(value()); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "]") { i++; depth--; return a; } err("array"); } }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; } if (text.startsWith("false", i)) { i += 5; return false; } if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i)); if (!m) err("value");
    if (m[2] || m[3]) err("float " + m[0]); const n = Number(m[0]); if (!Number.isSafeInteger(n) || Math.abs(n) > SAFE) err("integer out of range"); i += m[0].length; return n;
  }
  const v = value(); ws(); if (i !== text.length) err("trailing data"); return v;
}
// ---- canonical form (SPEC §3): sorted keys, "," ":" separators, ensure_ascii (non-ASCII -> \uXXXX, lowercase hex, surrogate pairs) ----
function esc(s) { let o = '"'; for (const ch of s) { const cp = ch.codePointAt(0);
  if (ch === '"') o += '\\"'; else if (ch === "\\") o += "\\\\"; else if (ch === "\n") o += "\\n"; else if (ch === "\r") o += "\\r"; else if (ch === "\t") o += "\\t"; else if (ch === "\b") o += "\\b"; else if (ch === "\f") o += "\\f";
  else if (cp < 0x20 || cp === 0x7f) o += "\\u" + cp.toString(16).padStart(4, "0");
  else if (cp > 0x7f) { if (cp > 0xffff) { const v = cp - 0x10000; o += "\\u" + (0xd800 + (v >> 10)).toString(16).padStart(4, "0") + "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0"); } else o += "\\u" + cp.toString(16).padStart(4, "0"); }
  else o += ch; } return o + '"'; }
const cmp = (a, b) => { const A = Array.from(a, (c) => c.codePointAt(0)), B = Array.from(b, (c) => c.codePointAt(0)); for (let k = 0; k < Math.min(A.length, B.length); k++) if (A[k] !== B[k]) return A[k] - B[k]; return A.length - B.length; };
function canon(v) { if (v === null) return "null"; if (v === true) return "true"; if (v === false) return "false"; if (typeof v === "number") return String(v); if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]"; return "{" + Object.keys(v).sort(cmp).map((k) => esc(k) + ":" + canon(v[k])).join(",") + "}"; }
const sha256 = (b) => createHash("sha256").update(b).digest();
const b64u = (b) => Buffer.from(b).toString("base64url");
const B64URL = /^[A-Za-z0-9_-]+$/;
function b64uDecode(s) { if (typeof s !== "string" || !s || !B64URL.test(s) || s.length % 4 === 1) throw new Refused("invalid base64url segment"); const raw = Buffer.from(s, "base64url"); if (b64u(raw) !== s) throw new Refused("non-canonical base64url"); return raw; }
const b64Strict = (s) => { if (typeof s !== "string" || !s || s.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null; const raw = Buffer.from(s, "base64"); return raw.toString("base64") === s ? raw : null; };
function jsonOf(buf) { const t = UTF8.decode(buf); return parseStrict(t); }

// ---- SD-JWT ----
function parseSdJwt(compact) {
  if (typeof compact !== "string") throw new Refused("sd_jwt_compact not a string");
  compact = compact.trim(); let jwt, middle, kb;
  if (compact.includes("~")) { const parts = compact.split("~"); jwt = parts[0]; middle = parts.slice(1, -1); kb = parts[parts.length - 1] || null; } else { jwt = compact; middle = []; kb = null; }
  const seg = jwt.split("."); if (seg.length !== 3) throw new Refused("issuer JWT must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("JWT header/payload not valid JSON/base64url: " + e.message); }
  return { compact, jwt, header, payload, signature: b64uDecode(seg[2]), signingInput: Buffer.from(seg[0] + "." + seg[1], "ascii"), disclosures: middle.filter((d) => d), kbJwt: kb };
}
function resolveDisclosures(payload, disclosures) {
  // r2: SHAPES imposed, present-with-null is not absent (`??` said it was; the reference's dict.get did not): _sd_alg absent or "sha-256",
  // _sd absent or a list of strings, {"...": x} with x a string, a disclosed claim name a string
  if ("_sd_alg" in payload && payload._sd_alg !== "sha-256") throw new Refused("_sd_alg unsupported");
  const byDigest = new Map();
  for (const d of disclosures) { let arr; try { arr = jsonOf(b64uDecode(d)); } catch (e) { throw new Refused("malformed disclosure: " + e.message); }
    if (!Array.isArray(arr) || ![2, 3].includes(arr.length)) throw new Refused("disclosure must be [salt,name,value] or [salt,value]");
    const dig = b64u(sha256(Buffer.from(d, "ascii"))); if (byDigest.has(dig)) throw new Refused("duplicate disclosure digest"); byDigest.set(dig, arr); }
  const used = new Set();
  function walk(node) {
    if (node !== null && typeof node === "object" && !Array.isArray(node)) { const out = Object.create(null);
      for (const k of Object.keys(node)) { if (k === "_sd" || k === "_sd_alg") continue; out[k] = walk(node[k]); }
      const sd = "_sd" in node ? node._sd : []; if (!Array.isArray(sd) || sd.some((x) => typeof x !== "string")) throw new Refused("_sd must be a list of digest strings");
      for (const dig of sd) { if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 3) throw new Refused("object disclosure must be [salt,name,value]"); if (typeof arr[1] !== "string") throw new Refused("disclosed claim name must be a string"); if (arr[1] in out) throw new Refused("disclosed claim collides"); out[arr[1]] = walk(arr[2]); used.add(dig); } }
      return out; }
    if (Array.isArray(node)) { const out = []; for (const item of node) { if (item !== null && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length === 1 && "..." in item) { const dig = item["..."]; if (typeof dig !== "string") throw new Refused("array disclosure placeholder must be a digest string"); if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 2) throw new Refused("array disclosure must be [salt,value]"); out.push(walk(arr[1])); used.add(dig); } } else out.push(walk(item)); } return out; }
    return node;
  }
  const resolved = walk(payload); for (const dig of byDigest.keys()) if (!used.has(dig)) throw new Refused("disclosure(s) match no digest");
  return resolved;
}
function es256Verify(signingInput, signature, jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk) || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Refused("jwk is not EC P-256");
  const x = b64uDecode(jwk.x), y = b64uDecode(jwk.y);   // r1: Node's JWK import decodes leniently (padding, +/); the reference is strict — decode strictly first
  if (x.length !== 32 || y.length !== 32) throw new Refused("jwk coordinates must be 32 bytes");
  if (signature.length !== 64) throw new Refused("ES256 signature must be 64 bytes");
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y) }, format: "jwk" });
  try { return cryptoVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature); } catch { return false; }
}
function verifyKbJwt(parsed, resolved) {
  const kb = parsed.kbJwt; if (!kb) return { present: false };
  const seg = kb.split("."); if (seg.length !== 3) throw new Refused("kb-jwt must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("kb-jwt header/payload invalid"); }
  if (header.alg !== "ES256") throw new Refused("kb-jwt alg unsupported");
  if (typeof header !== "object" || header === null || Array.isArray(header) || typeof payload !== "object" || payload === null || Array.isArray(payload)) throw new Refused("kb-jwt header and payload must be objects");
  const cnf = resolved !== null && typeof resolved === "object" && "cnf" in resolved ? resolved.cnf : undefined;   // r2: cnf absent or object; cnf.jwk absent or object
  if (cnf !== undefined && (cnf === null || typeof cnf !== "object" || Array.isArray(cnf))) throw new Refused("cnf must be an object");
  const jwk = cnf !== undefined && "jwk" in cnf ? cnf.jwk : undefined; if (jwk === undefined) return { present: true, verified: null };
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw new Refused("cnf.jwk must be an object");
  const sigOk = es256Verify(Buffer.from(seg[0] + "." + seg[1], "ascii"), b64uDecode(seg[2]), jwk);
  const presentation = parsed.compact.slice(0, parsed.compact.lastIndexOf("~")) + "~";
  const sdHashOk = payload.sd_hash === b64u(sha256(Buffer.from(presentation, "ascii")));
  return { present: true, verified: Boolean(sigOk && sdHashOk) };
}
function findBindings(arts) {
  const digests = Object.create(null); for (const a of arts) { const raw = Buffer.from(a.compact, "ascii"); digests[a.name] = { hex: sha256(raw).toString("hex"), b64url: b64u(sha256(raw)) }; }
  const found = [];
  function scan(node, path, holder) { if (node !== null && typeof node === "object" && !Array.isArray(node)) { for (const k of Object.keys(node)) scan(node[k], path ? path + "." + k : k, holder); }
    else if (Array.isArray(node)) node.forEach((v, i) => scan(v, path + "[" + i + "]", holder));
    else if (typeof node === "string") { for (const [other, d] of Object.entries(digests)) { if (other === holder) continue; if (node === d.hex || node === d.b64url) found.push({ in: holder, claim: path, commits_to: other, encoding: node === d.hex ? "hex" : "b64url" }); } } }
  for (const a of arts) scan(a.resolved, "", a.name); return found;
}
// ---- producer signatures ----
const MLDSA65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");   // SEQ{ SEQ{OID 2.16.840.1.101.3.4.3.18}, BIT STRING(0x00||1952 bytes) } — the wrapping measured in omega-evidence
const HAVE_MLDSA = (() => { try { createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.alloc(1952)]), format: "der", type: "spki" }); return true; } catch { return false; } })();
function verifyProducer(alg, pubB64, sigB64, message) {
  const pk = b64Strict(pubB64), sig = b64Strict(sigB64); if (!pk || !sig) return false;
  try {
    if (alg === "ed25519") { if (pk.length !== 32 || sig.length !== 64) return false; const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pk]), format: "der", type: "spki" }); return cryptoVerify(null, message, key, sig); }
    if (alg === "ecdsa-p256") { if (sig.length !== 64 || pk.length !== 65 || pk[0] !== 4) return false; const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: pk.subarray(1, 33).toString("base64url"), y: pk.subarray(33).toString("base64url") }, format: "jwk" }); return cryptoVerify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, sig); }
    if (alg === "ml-dsa-65") { if (!HAVE_MLDSA) return null; if (pk.length !== 1952 || sig.length !== 3309) return false;
      const key = createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, pk]), format: "der", type: "spki" }); return cryptoVerify(null, message, key, sig); }
  } catch { return false; }
  return null;   // unknown alg = verification gap, never a pass
}
function verifyProducerBlock(block, message, trusted) {
  const results = []; let pq = false, allPinned = trusted !== null, nPass = 0, nFail = 0, nSkip = 0;
  for (const s of Array.isArray(block?.signatures) ? block.signatures : []) {
    const alg = s?.sig_alg, pub = s?.public_key_b64 ?? "";
    if (typeof alg !== "string") { nFail++; results.push({ sig_alg: null, status: "FAIL", post_quantum: false, key_trusted: null }); allPinned = false; continue; }   // r2: "constructor"/"__proto__" as sig_alg crashed the pin lookup on a prototype-bearing table
    const v = verifyProducer(alg, pub, s?.signature_b64 ?? "", message);
    const status = v === true ? "PASS" : v === null ? "SKIP" : "FAIL"; if (v === true) nPass++; else if (v === false) nFail++; else nSkip++;
    let keyTrusted = null; if (trusted !== null) { const allowed = Object.hasOwn(trusted, alg) ? trusted[alg] : []; keyTrusted = allowed.includes(pub); if (!keyTrusted) allPinned = false; }
    if (v === true && alg === "ml-dsa-65" && (trusted === null || keyTrusted)) pq = true;
    results.push({ sig_alg: alg, status, post_quantum: alg === "ml-dsa-65", key_trusted: keyTrusted });
  }
  const ok = nPass >= 1 && nFail === 0 && nSkip === 0; const trustedOk = trusted === null ? null : (results.length > 0 && allPinned && nSkip === 0);
  return { ok, incomplete: nSkip > 0 && nFail === 0, pq_protected: pq, trusted: trustedOk, results };
}
// ---- RFC 3161 token: minimal DER walk — TimeStampResp{ status PKIStatusInfo{ INTEGER }, timeStampToken ContentInfo{ OID, [0] SignedData{ ..., encapContentInfo{ OID id-ct-TSTInfo, [0] OCTET STRING TSTInfo } } } }
// TSTInfo{ version, policy OID, messageImprint{ AlgorithmIdentifier, OCTET STRING hash } ... }. Same two facts the reference checks
// (SPEC §3.2). TSA signature/chain: only the reference, with `--tsa-cert` through `openssl ts -verify`; here `tsa_verified` is null (declared).
function derTLV(buf, off) { if (off + 2 > buf.length) throw new Refused("der"); const tag = buf[off]; let len = buf[off + 1], hl = 2;
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4 || off + 2 + n > buf.length) throw new Refused("der len"); len = 0; for (let k = 0; k < n; k++) len = len * 256 + buf[off + 2 + k]; hl = 2 + n; }   // r3: `<<` is int32 — 0x84 80 00 00 00 went negative and passed the overrun check
  if (off + hl + len > buf.length) throw new Refused("der overrun"); return { tag, start: off + hl, end: off + hl + len, next: off + hl + len }; }
function derChildren(buf, tlv) { const out = []; let o = tlv.start; while (o < tlv.end) { const c = derTLV(buf, o); out.push(c); o = c.next; } return out; }
function verifyRfc3161(tsrB64, expectedDigestHex) {
  const raw = b64Strict(tsrB64); if (!raw) return { verified: false, note: "tsr_b64 is not canonical base64" };
  try {
    const resp = derTLV(raw, 0); if (resp.tag !== 0x30) return { verified: false, note: "not a TimeStampResp" };
    const [status, token] = derChildren(raw, resp); const st = derChildren(raw, status)[0]; if (!st || st.tag !== 0x02) return { verified: false, note: "no status" };
    const granted = st.end - st.start === 1 && (raw[st.start] === 0 || raw[st.start] === 1);   // granted (0) / grantedWithMods (1)
    if (!token) return { verified: false, granted, imprint_ok: false };
    const ci = derChildren(raw, token); const sd = ci[1] && derChildren(raw, ci[1])[0]; if (!sd) return { verified: false, granted, imprint_ok: false };
    const sdc = derChildren(raw, sd);           // version, digestAlgorithms, encapContentInfo, [certs], [crls], signerInfos
    const eci = sdc[2]; const ecic = derChildren(raw, eci); const wrap = ecic[1] && derChildren(raw, ecic[1])[0]; if (!wrap || wrap.tag !== 0x04) return { verified: false, granted, imprint_ok: false };
    const tst = derTLV(raw, wrap.start); const tstc = derChildren(raw, tst);   // version, policy, messageImprint, serial, genTime, ...
    const mi = tstc[2]; const mic = derChildren(raw, mi); const hash = mic[1]; if (!hash || hash.tag !== 0x04) return { verified: false, granted, imprint_ok: false };
    const imprint = raw.subarray(hash.start, hash.end).toString("hex"); const imprintOk = imprint === expectedDigestHex.toLowerCase();
    let genTime = null; const gt = tstc[4]; if (gt && gt.tag === 0x18) { const s = raw.subarray(gt.start, gt.end).toString("latin1"); if (/^\d{14}(\.\d+)?Z$/.test(s)) genTime = s; }   // r4: TSTInfo.genTime, reported as in the reference
    return { verified: Boolean(granted && imprintOk), granted, imprint_ok: imprintOk, gen_time: genTime };
  } catch (e) { return { verified: false, note: "token not parseable: " + (e.message ?? e) }; }
}
// ---- evidence ----
export function verifyEvidence(path, opts = {}) {
  const refuse = (m) => ({ digest_ok: false, artifacts: [], producer_signatures: { present: false, pq_protected: false, trusted: null }, pq_protected: false, bindings_ok: false, rfc3161: { claimed: false, verified: null }, provenance_classes: [], self_asserted_only: false, policy_ok: false, valid: false, honest_scope: null, refused: m });
  let ev; try { if (statSync(path).size > MAX_BYTES) return refuse("evidence file exceeds bound"); const raw = readFileSync(path); const text = UTF8.decode(raw); if (text.startsWith("﻿")) return refuse("BOM"); ev = parseStrict(text); } catch (e) { return refuse(String(e.message ?? e)); }
  if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return refuse("not a JSON object");
  // shape of the top-level fields (SPEC §1), the same refusals as the reference
  if (!Array.isArray(ev.artifacts) || ev.artifacts.some((a) => a === null || typeof a !== "object" || Array.isArray(a))) return refuse("artifacts must be a list of objects");
  const names = ev.artifacts.map((a) => a.name); if (names.some((n) => typeof n !== "string" || !n)) return refuse("artifacts[].name must be a non-empty string");   // r3
  if (new Set(names).size !== names.length) return refuse("artifacts[].name must be unique within the pack");
  if ("bindings" in ev && !Array.isArray(ev.bindings)) return refuse("bindings must be a list");
  if ("rfc3161_timestamp" in ev && (ev.rfc3161_timestamp === null || typeof ev.rfc3161_timestamp !== "object" || Array.isArray(ev.rfc3161_timestamp))) return refuse("rfc3161_timestamp must be an object");
  if ("rfc3161_timestamp" in ev && typeof ev.rfc3161_timestamp.anchored !== "boolean") return refuse("rfc3161_timestamp.anchored must be a boolean");   // r2: [] / {} were "anchored, unverified" here and "not anchored" in the reference
  if ("producer_signatures" in ev && (ev.producer_signatures === null || typeof ev.producer_signatures !== "object" || Array.isArray(ev.producer_signatures))) return refuse("producer_signatures must be an object");
  const e2 = Object.create(null); for (const k of Object.keys(ev)) if (!["evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures"].includes(k)) e2[k] = ev[k];
  const recomputed = sha256(Buffer.from(canon(e2), "utf-8")).toString("hex"); const digestOk = recomputed === ev.evidence_digest_sha256;
  const artResults = []; let allOk = true; const forBindings = [];
  for (const a of ev.artifacts) {
    try { const compact = a.sd_jwt_compact; if (typeof compact !== "string" || compact !== compact.trim() || !/^[\x00-\x7f]*$/.test(compact)) throw new Refused("sd_jwt_compact must be the exact ASCII compact serialization");
      if (!a.key || typeof a.key !== "object" || Array.isArray(a.key)) throw new Refused("artifact key.jwk must be an object");
      if ("provenance_class" in a.key && a.key.provenance_class !== null && typeof a.key.provenance_class !== "string") throw new Refused("artifact key.provenance_class must be a string");   // r2: a list was sorted here and a TypeError in the reference
      const parsed = parseSdJwt(compact); if (parsed.payload === null || typeof parsed.payload !== "object" || Array.isArray(parsed.payload) || parsed.header === null || typeof parsed.header !== "object" || Array.isArray(parsed.header)) throw new Refused("JWT header and payload must be objects");
      const sigOk = es256Verify(parsed.signingInput, parsed.signature, a.key.jwk); const resolved = resolveDisclosures(parsed.payload, parsed.disclosures);
      const claimsOk = canon(resolved) === canon(a.resolved_claims ?? null); const kb = verifyKbJwt(parsed, resolved);
      artResults.push({ name: a.name, signature_ok: sigOk, claims_match: claimsOk, kb_jwt: kb, provenance_class: a.key?.provenance_class });
      allOk = allOk && sigOk && claimsOk && kb.verified !== false; forBindings.push({ name: a.name, compact: parsed.compact, resolved });
    } catch (e) { artResults.push({ name: a?.name, error: String(e.message ?? e) }); allOk = false; }
  }
  const asSet = (l) => l.map((b) => canon(b)).sort().join("\n");   // r4: binding SET (SPEC §4) — Object.keys enumerates index keys first, so the scan order is not the reference's
  const bindingsOk = allOk ? asSet(findBindings(forBindings)) === asSet(ev.bindings ?? []) : false;   // `bindings` absent = [] in both; null is refused above
  const ts = ev.rfc3161_timestamp ?? {}; let rfc = { claimed: Boolean(ts.anchored), verified: null };   // `anchored` is a boolean by the shape check above
  if (ts.anchored && typeof ts.tsr_b64 === "string") rfc = { claimed: true, ...verifyRfc3161(ts.tsr_b64, recomputed), tsa_verified: null };   // BINDING only (status granted + messageImprint == digest, SPEC §3.2); TSA signature/chain: this verifier cannot (no openssl) -> tsa_verified null = incomplete under --tsa-cert
  else if (ts.anchored) rfc = { claimed: true, verified: false, note: "anchored claimed but tsr_b64 absent or not a string" };
  const classes = [...new Set(artResults.map((r) => r.provenance_class).filter(Boolean))].sort();
  let producer; const prod = ev.producer_signatures;
  if (prod) { const pv = verifyProducerBlock(prod, Buffer.from(recomputed, "ascii"), opts.trusted ?? null); producer = { present: true, scheme: prod.scheme, ok: pv.ok, incomplete: pv.incomplete, pq_protected: pv.pq_protected, trusted: pv.trusted, signatures: pv.results };
    if (!pv.ok) allOk = false; if ((opts.trusted ?? null) !== null && pv.trusted !== true) allOk = false; }
  else producer = { present: false, pq_protected: false, trusted: null };
  let policyOk = true; if (opts.requireProducer && !(producer.present && producer.ok)) policyOk = false;
  if (opts.requirePq && !(producer.pq_protected && producer.trusted === true)) policyOk = false;
  if (opts.requireAnchor && rfc.verified !== true) policyOk = false;
  if (opts.requireAnchor && opts.tsaCert && rfc.tsa_verified !== true) policyOk = false;   // TSA verification requested: this verifier cannot perform it -> not a pass (declared)
  return { digest_ok: digestOk, artifacts: artResults, producer_signatures: producer, pq_protected: producer.pq_protected ?? false, bindings_ok: bindingsOk, rfc3161: rfc, provenance_classes: classes,
    self_asserted_only: classes.length > 0 && classes.every((c) => c === "jwk_header"), policy_ok: policyOk,
    valid: Boolean(artResults.length && digestOk && allOk && bindingsOk && rfc.verified !== false && policyOk), honest_scope: ev.honest_scope ?? null, mldsa_backend: HAVE_MLDSA };
}
function main(argv) {
  const usage = () => { console.error("usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--tsa-cert PEM]"); process.exit(2); };
  const a = argv.slice(2); const opts = { trusted: null }; let path = null;
  for (let i = 0; i < a.length; i++) { let tok = a[i], eqv = null; const eq = tok.indexOf("="); if (eq > 0 && tok.startsWith("--")) { eqv = tok.slice(eq + 1); tok = tok.slice(0, eq); }
    const nx = () => { const v = eqv !== null ? eqv : a[++i]; if (v === undefined || v === "" || v.startsWith("-")) usage(); return v; };
    if (tok === "--trusted-producer-key") { const v = nx(); const k = v.indexOf("="); if (k <= 0 || k === v.length - 1) usage(); opts.trusted = opts.trusted ?? Object.create(null); (opts.trusted[v.slice(0, k)] ??= []).push(v.slice(k + 1)); }   // r2: a null-prototype table, so "constructor=…" is a pin like any other
    else if (tok === "--tsa-cert") opts.tsaCert = nx();
    else if (tok === "--require-producer" && eqv === null) opts.requireProducer = true; else if (tok === "--require-pq" && eqv === null) opts.requirePq = true; else if (tok === "--require-anchor" && eqv === null) opts.requireAnchor = true;
    else if (tok.startsWith("-") || path !== null) usage(); else path = tok; }
  if (!path) usage();
  const r = verifyEvidence(path, opts); console.log(JSON.stringify(r, null, 1)); return r.valid ? 0 : 1;
}
if (process.argv[1] && /ap2-verify\.mjs$/.test(process.argv[1])) process.exit(main(process.argv));
