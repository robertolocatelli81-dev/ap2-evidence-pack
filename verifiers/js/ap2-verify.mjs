#!/usr/bin/env node
// ap2-verify — independent JavaScript verifier of ap2-evidence-pack evidence files (SPEC_AP2_EVIDENCE.md), Node with OpenSSL >= 3.5 for ML-DSA-65,
// node:crypto only (no ap2_evidence code, no dependency). Same normative facts as ap2_evidence.verify_evidence:
// digest_ok, per-artifact ES256 signature / disclosures / KB-JWT, bindings, producer signatures (ed25519, ecdsa-p256;
// ml-dsa-65 through the Node build's OpenSSL >= 3.5, else SKIP = incomplete, never a pass), policy flags, valid.
// Acceptance profile of the file (SPEC §3.1): strict UTF-8, no BOM, no duplicate keys, no floats, integers within
// +/-(2^53-1), nesting <= 512, no lone surrogate escape, 64 MiB bound. A refused file is a receipt with valid=false.
// Inside the SD-JWTs (1.7.2) a literal with a fraction or an exponent is that artifact's error; with --accept-integral-floats
// one whose value is an integer in that range is read as it, and the receipt names it.
// 1.8.0 (SPEC §12): the `not_before` block — closed grammar, NIST Beacon pulse pair, NB1-NB3 and the receipt member
// `not_before` as the reference; `paymentCommitment` / `checkDisclosure` exported. No TSA verification here, so NB3 never
// closes the window (declared, as tsa_verified).
// Usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--min-anchors N] [--tsa-cert PEM] [--trust-set-complete] [--accept-integral-floats]
import { statSync, accessSync, readFileSync, openSync, fstatSync, readSync, closeSync, writeSync, constants as FS } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

const MAX_DEPTH = 512, MAX_BYTES = 64 * 1024 * 1024, SAFE = 2 ** 53 - 1;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
class Refused extends Error {}
class UnknownMember extends Refused {}
class FormatUnsupported extends Refused {}   // 1.6.0: an anchor mechanism a later revision may define   // 1.6.0 — SPEC §9.1/§6.9: a key outside a closed list = a refusal of class unknown_member

// SPEC §6.10: the bytes of a regular file that holds at least one CERTIFICATE (X509 / TRUSTED) PEM block whose base64 characters
// decode to a DER SEQUENCE; else null. The same test as the reference's _pem_certificate_file: bytes outside the base64 alphabet
// are ignored, and a device or a FIFO is never read (verifyEvidence is called without the command line's check).
function pemCertificateFile(path) {
  let raw; try { if (!statSync(path).isFile()) return null; raw = readFileSync(path); } catch { return null; }
  for (const m of raw.toString("latin1").matchAll(/-----BEGIN ((?:X509 |TRUSTED )?CERTIFICATE)-----[^\n]*\n([^]+?)-----END \1-----/g)) {
    const body = m[2].replace(/[^A-Za-z0-9+\/=]/g, "");
    if (body.length % 4 || !/^[A-Za-z0-9+\/]*={0,2}$/.test(body)) continue;
    const der = Buffer.from(body, "base64");
    if (der.length >= 2 && der[0] === 0x30) return raw;
  }
  return null;
}

// ---- strict JSON parser (keeps number lexemes; refuses what the profile refuses) ----
// 1.7.2 (SPEC §3.1, the SD-JWT layer): the integer a literal with a fraction or an exponent denotes when its value is an
// integer within +/-(2^53-1), else null — decided on the decimal DIGITS (BigInt), never through Number(): the same digit
// algorithm as the reference's `_integral_literal`, so both verifiers read, or refuse, the same literals.
function integralLiteral(m) {
  const neg = m[0][0] === "-", ip = m[1], fp = m[2] ? m[2].slice(1) : "", ex = m[3] ? m[3].slice(1) : "0";
  let digits = (ip + fp).replace(/^0+/, "");
  if (!digits) return 0;                                                 // 0.0, -0.0, 0e99999: zero, whatever the exponent
  if (ex.replace(/^[+-]/, "").replace(/^0+/, "").length > 9) return null; // ten exponent digits or more: outside the range either way
  let shift = parseInt(ex, 10) - fp.length;                              // value = digits * 10**shift
  if (shift < 0) {
    if (digits.length <= -shift || /[1-9]/.test(digits.slice(shift))) return null;   // a non-zero digit below the units
    digits = digits.slice(0, shift); shift = 0;
  }
  if (digits.length + shift > 16) return null;                           // 2^53-1 has 16 digits
  const v = BigInt(digits) * 10n ** BigInt(shift);
  if (v > BigInt(SAFE)) return null;
  return Number(neg ? -v : v);
}
// 1.7.2 (SPEC §3.1): null = the default (a literal with a fraction or an exponent in a token is that artifact's error); an
// array = acceptIntegralFloats was asked: an integral one is read as its integer and its text recorded here.
let INTEGRAL_READ = null;
function parseStrict(text, inToken = false) {
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
    if (m[2] || m[3]) { if (!inToken) err("float " + m[0]); const shown = m[0].length <= 30 ? m[0] : m[0].slice(0, 30) + "…";
      const v = integralLiteral(m); if (v === null) err("float " + shown + " in the SD-JWT: not an integer within +/-(2^53-1)");   // 1.9.0: said first, also without the option (which does not read it)
      if (INTEGRAL_READ === null) err("float " + shown + " in the SD-JWT needs accept_integral_floats"); INTEGRAL_READ.push(shown); i += m[0].length; return v; }
    const n = Number(m[0]); if (!Number.isSafeInteger(n) || Math.abs(n) > SAFE) err("integer out of range"); i += m[0].length; return n;
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
const EVIDENCE_FORMAT = "ap2-evidence-pack/1.0";
const HONEST_SCOPE_SHA256 = "a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf";   // SPEC §1: sha256 of the canonical honest scope of this format version
const HONEST_SCOPE_SHA256_1_0 = "431877e44b759e99d306f79dd52739f08bd94bc05d70a6a03ee82f74fc0f15db";   // 1.9.0 (SPEC §1): the scope 1.0.0-1.0.2 sealed, named in the refusal
const B64URL = /^[A-Za-z0-9_-]+$/;
function b64uDecode(s) { if (typeof s !== "string" || !s || !B64URL.test(s) || s.length % 4 === 1) throw new Refused("invalid base64url segment"); const raw = Buffer.from(s, "base64url"); if (b64u(raw) !== s) throw new Refused("non-canonical base64url"); return raw; }
const b64Strict = (s) => { if (typeof s !== "string" || !s || s.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null; const raw = Buffer.from(s, "base64"); return raw.toString("base64") === s ? raw : null; };
function jsonOf(buf) { const t = UTF8.decode(buf); return parseStrict(t, true); }   // 1.7.2: the SD-JWT layer reads integral literals

// ---- SD-JWT ----
function parseSdJwt(compact) {
  if (typeof compact !== "string") throw new Refused("sd_jwt_compact not a string");
  compact = compact.trim();
  // 1.8.1 (SPEC §6 step 2, RFC 9901 §4): the grammar is closed, as the reference — no '~', an empty component before the last, or a last
  // component that is neither empty nor a KB-JWT (three dot-separated segments) is refused by name (up to 1.8.0: read as a plain JWT,
  // dropped in silence, taken as the KB-JWT)
  if (!compact.includes("~")) throw new Refused("sd_jwt_no_separator: an SD-JWT has at least one '~' after the issuer JWT (RFC 9901 §4: <Issuer-signed JWT>~<D.1>~...~<D.N>~[<KB-JWT>]); a plain JWS such as an AP2 receipt enters as <jwt>~, an SD-JWT with no disclosures (SPEC §2.1)");
  const parts = compact.split("~"); const jwt = parts[0]; const middle = parts.slice(1, -1); const kb = parts[parts.length - 1] || null;
  if (middle.some((d) => d === "")) throw new Refused("sd_jwt_empty_component: an empty component between two '~' (RFC 9901 §4: DISCLOSURE = 1*base64url; only the last component may be empty; an AP2 chain joins its hops with '~~' before an issuer JWT, and `build` splits it into hops, SPEC §2.1)");
  if (kb !== null && kb.split(".").length !== 3) throw new Refused("sd_jwt_final_component_not_kb_jwt: the last '~'-separated component is neither empty nor a KB-JWT of three dot-separated segments, so it would be read as the KB-JWT: is the trailing '~' missing? (RFC 9901 §4: an SD-JWT without a KB-JWT ends with '~')");
  const seg = jwt.split("."); if (seg.length !== 3) throw new Refused("issuer JWT must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("JWT header/payload not valid JSON/base64url: " + e.message); }
  return { compact, jwt, header, payload, signature: b64uDecode(seg[2]), signingInput: Buffer.from(seg[0] + "." + seg[1], "ascii"), disclosures: middle, kbJwt: kb };
}
function resolveDisclosures(payload, disclosures, census = null) {
  let reservedDots = 0;   // variant "report, do not refuse": a plain "..." key outside an array placeholder is kept and counted
  // r2: SHAPES imposed, present-with-null is not absent (`??` said it was; the reference's dict.get did not): _sd_alg absent or "sha-256",
  // _sd absent or a list of strings, {"...": x} with x a string, a disclosed claim name a string
  if ("_sd_alg" in payload && payload._sd_alg !== "sha-256") throw new Refused("_sd_alg unsupported");
  const byDigest = new Map();
  for (const d of disclosures) { let arr; try { arr = jsonOf(b64uDecode(d)); } catch (e) { throw new Refused("malformed disclosure: " + e.message); }
    if (!Array.isArray(arr) || ![2, 3].includes(arr.length)) throw new Refused("disclosure must be [salt,name,value] or [salt,value]");
    const dig = b64u(sha256(Buffer.from(d, "ascii"))); if (byDigest.has(dig)) throw new Refused("duplicate disclosure digest"); byDigest.set(dig, arr); }
  const used = new Set(); const seen = new Set();
  // 1.7.0 — SPEC §6 step 2: a digest value encountered more than once (an `_sd` entry or an array placeholder, in the payload or inside a disclosed
  // value, matched or decoy) is refused at the second encounter, before anything under it is resolved (RFC 9901 §7.1 step 4; up to 1.6.0 a
  // repeated placeholder expanded the mandate twice); a disclosed claim named `_sd` or `...` is refused (§7.1 step 3.c.ii.2; up to 1.6.0 inserted as a claim)
  function meet(dig) { if (seen.has(dig)) throw new Refused("digest encountered more than once in the issuer payload (RFC 9901 §7.1 step 4, rejected fail-closed)"); seen.add(dig); }
  // 1.7.1 — SPEC §6 step 2: the resolved claims nest no deeper than MAX_DEPTH (the §3.1 bound), else disclosures_too_deep; the walk is
  // iterative (an explicit stack of generators: `yield [child, depth]` hands a child to run(), which passes back its resolved value), so
  // neither the bound nor the error depends on the engine's stack (up to 1.7.0 a chain of 20000 disclosures was "Maximum call stack size exceeded")
  function* walk(node, depth) {
    if (node !== null && typeof node === "object" && depth > MAX_DEPTH) throw new Refused("disclosures_too_deep: the resolved claims nest deeper than " + MAX_DEPTH + " (SPEC §6 step 2, rejected fail-closed)");
    if (node !== null && typeof node === "object" && !Array.isArray(node)) { const out = Object.create(null);
      // 1.8.1 — SPEC §6 step 2: "..." only as an array placeholder (RFC 9901 §4.1 item 7), _sd_alg only at the payload's top level (§4.1.1)
      if (Object.hasOwn(node, "...")) reservedDots++;   // RFC 9901 §4.1 item 7 is the Issuer's rule: reported in the receipt (reserved_names_in_clear)
      if (Object.hasOwn(node, "_sd_alg") && depth > 1) throw new Refused("sd_alg_not_top_level: a key _sd_alg below the top level of the issuer payload (RFC 9901 §4.1.1, rejected fail-closed)");
      for (const k of Object.keys(node)) { if (k === "_sd" || k === "_sd_alg") continue; out[k] = yield [node[k], depth + 1]; }
      const sd = "_sd" in node ? node._sd : []; if (!Array.isArray(sd) || sd.some((x) => typeof x !== "string")) throw new Refused("_sd must be a list of digest strings");
      for (const dig of sd) { meet(dig); if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 3) throw new Refused("object disclosure must be [salt,name,value]"); if (typeof arr[1] !== "string") throw new Refused("disclosed claim name must be a string"); if (arr[1] === "_sd" || arr[1] === "...") throw new Refused("disclosed claim name is reserved (RFC 9901 §7.1 step 3.c.ii.2, rejected fail-closed)"); if (arr[1] in out) throw new Refused("disclosed claim collides"); out[arr[1]] = yield [arr[2], depth + 1]; used.add(dig); } }
      return out; }
    if (Array.isArray(node)) { const out = []; for (const item of node) { if (item !== null && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length === 1 && "..." in item) { const dig = item["..."]; if (typeof dig !== "string") throw new Refused("array disclosure placeholder must be a digest string"); meet(dig); if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 2) throw new Refused("array disclosure must be [salt,value]"); out.push(yield [arr[1], depth + 1]); used.add(dig); } } else out.push(yield [item, depth + 1]); } return out; }
    return node;
  }
  function run(root) { const stack = [walk(root, 1)]; let value;
    while (stack.length) { const r = stack[stack.length - 1].next(value); if (r.done) { stack.pop(); value = r.value; } else { stack.push(walk(r.value[0], r.value[1])); } }   // a fresh generator ignores the value of its first next()
    return value; }
  const resolved = run(payload); for (const dig of byDigest.keys()) if (!used.has(dig)) throw new Refused("disclosure(s) match no digest");
  if (census !== null) census.reserved = reservedDots;
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
function checkUnknown(obj, what, allowed) {   // 1.6.0 — SPEC §9.1/§6.9: only the unknown-key rule (the reference's _check_unknown)
  if (!isObj(obj)) return;
  const has = allowed instanceof Set ? (k) => allowed.has(k) : (k) => Object.hasOwn(allowed, k);
  const unknown = Object.keys(obj).filter((k) => !has(k)).sort(byCodePoint);
  if (unknown.length) throw new UnknownMember(what + ": unknown key " + JSON.stringify(unknown[0]) + " (SPEC §9.1)");
}
// ---- 1.6.0 — SPEC §6.9: the five subjects of an admitted pack (the same derivation as the reference's derive_states) ----
export const STATES_VOCABULARY = "ap2-evidence-pack/states-1";
const POLICY_UNMET = ["require_producer", "require_pq", "require_anchor", "min_anchors", "require_binding", "trusted_producer_keys", "trust_set_complete"];   // require_binding: 1.9.0
function subject(elements) {   // [state, reason, detail?]: contradicted > not_evaluated/instrument_failure > other not_evaluated > verified
  const rank = (e) => e[0] === "contradicted" ? 3 : e[1] === "instrument_failure" ? 2 : e[0] === "not_evaluated" ? 1 : 0;
  let top = elements[0]; for (const e of elements) if (rank(e) > rank(top)) top = e;
  const state = top[0];
  const reasons = state === "verified" ? elements.filter((e) => e[1]).map((e) => e[1]) : elements.filter((e) => e[0] !== "verified").map((e) => e[1]);
  const out = { state, reasons }; const details = elements.filter((e) => e[2]).map((e) => e[2]); if (details.length) out.detail = details.join("; ");
  return out;
}
function anchorElement(r, tsaRequested) {
  if (r.verified !== true) return ["contradicted", r.imprint_ok === false ? "binding_mismatch" : "token_invalid"];
  if (!tsaRequested) return ["not_evaluated", "tsa_not_checked"];
  if (r.tsa_verified === true) return ["verified", null];
  if (r.tsa_verified === false) return ["not_evaluated", "tsa_invalid"];
  return ["not_evaluated", "instrument_failure", r.tsa_note ?? "TSA signature not checked by this verifier"];
}
function deriveStates({ digestOk, artResults, bindingSetMatch, tsBlock, rfcBlock, anchorResults, tsaRequested, producer, pinned, trustAnchorGiven }) {
  const sealed = [digestOk ? ["verified", null] : ["contradicted", "digest_mismatch"]];
  if (!artResults.length) sealed.push(["contradicted", "artifact_invalid", "the pack carries no artifact"]);
  for (const r of artResults) sealed.push(("error" in r || r.signature_ok !== true || r.claims_match !== true) ? ["contradicted", "artifact_invalid"] : ["verified", null]);
  if (bindingSetMatch !== null) sealed.push(bindingSetMatch ? ["verified", null] : ["contradicted", "binding_mismatch"]);   // recomputed whenever every signature and claims verified
  const verifiedArts = artResults.filter((r) => !("error" in r));
  const notSeen = verifiedArts.length === artResults.length ? null : "artifacts that are errors are stated in sealed_content only";
  let holder = [];
  for (const r of verifiedArts) { if (r.chain_hop) holder.push(["verified", null]);   // 1.9.0 (SPEC §2.1, §6.9): an AP2 hop is the holder binding of the hop before it
    const kb = r.kb_jwt ?? {}; if (!kb.present) continue;
    if (kb.verified === true) holder.push(["verified", null]);
    else if (kb.verified === false) holder.push(["contradicted", kb.signature_ok !== true ? "kb_signature_invalid" : "sd_hash_mismatch"]);
    else holder.push(["not_evaluated", "holder_key_unknown"]); }
  if (!holder.length) holder = [["not_evaluated", "not_present", notSeen]];
  let time = [];
  if (tsBlock.anchored) time.push(typeof tsBlock.tsr_b64 === "string" ? anchorElement(rfcBlock, tsaRequested) : ["contradicted", "token_missing"]);
  for (const r of anchorResults) time.push(anchorElement(r, tsaRequested));
  if (!time.length) time = [["not_evaluated", "not_present"]];
  let prod = [];
  if (!producer.present) prod = [["not_evaluated", "not_present"]];
  else {
    for (const e of producer.signatures ?? []) {
      if (e.status === "FAIL") prod.push(["contradicted", "signature_invalid"]);
      else if (e.status === "SKIP") prod.push(["not_evaluated", "backend_missing"]);
      else if (!pinned) prod.push(["not_evaluated", "self_asserted"]);
      else if (e.key_trusted === true) prod.push(["verified", null]);
      else prod.push(["not_evaluated", "key_unresolved"]); }
    if (!(producer.signatures ?? []).length) prod.push(["contradicted", "signature_invalid", "the producer block carries no signature entry"]);
    else if (producer.scheme_ok !== true) prod.push(["contradicted", "signature_invalid", "scheme " + JSON.stringify(producer.scheme ?? null) + " does not match its entries (SPEC §5)"]);
  }
  let issuer = [];
  for (const r of verifiedArts) {
    if (r.provenance_class !== "x5c_header") issuer.push(["not_evaluated", "self_asserted"]);
    else if (!trustAnchorGiven) issuer.push(["not_evaluated", "no_trust_anchor"]);
    else issuer.push(["not_evaluated", "instrument_failure", "x5c chain not checked by this verifier"]);   // unreachable: --trust-anchor is a usage error here
  }
  if (!issuer.length) issuer = [["not_evaluated", "not_present", notSeen ?? "the pack carries no artifact"]];
  return { sealed_content: subject(sealed), holder_binding: subject(holder), time_anchor: subject(time), producer_signature: subject(prod), issuer_identity: subject(issuer) };
}
// SPEC §13 (1.8.1), as the reference's _media_type: RFC 7515 §4.1.9 (type, subtype and parameter names case-insensitive,
// parameter values case-sensitive; "application/" implied without "/"), the grammar of RFC 9110 §8.3.1/§5.6.6 with every
// ";" followed by a parameter (this format's rule: RFC 9110 allows an empty parameter, here it is no media type), ASCII only,
// A-Z only folded (toLowerCase makes U+212A KELVIN SIGN a "k"), a quoted-string read without quotes and quoted-pairs,
// parameters in any order, a name twice is no media type. null when typ is not a media type; else a comparable string.
const TCHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]$/;
const foldAZ = (t) => t.replace(/[A-Z]/g, (c) => c.toLowerCase());
function mediaType(typ) {
  if (typeof typ !== "string") return null;
  const n = typ.length; let i = 0;
  const token = (k) => { let j = k; while (j < n && TCHAR.test(typ[j])) j++; return j > k ? [typ.slice(k, j), j] : [null, k]; };
  let t; [t, i] = token(0); if (t === null) return null;
  let full;
  if (i < n && typ[i] === "/") { let sub; [sub, i] = token(i + 1); if (sub === null) return null; full = t + "/" + sub; }
  else if (typ.includes("/")) return null;
  else full = "application/" + t;
  const params = new Map();
  while (i < n) {
    while (i < n && (typ[i] === " " || typ[i] === "\t")) i++;
    if (i >= n || typ[i] !== ";") return null;
    i++;
    while (i < n && (typ[i] === " " || typ[i] === "\t")) i++;
    if (i >= n || typ[i] === ";") return null;   // SPEC §13: a ';' with no parameter after it is no media type here
    let name; [name, i] = token(i);
    if (name === null || i >= n || typ[i] !== "=") return null;
    i++;
    let value;
    if (i < n && typ[i] === '"') {
      i++; const val = [];
      for (;;) {
        if (i >= n) return null;
        const c = typ[i]; const o = c.charCodeAt(0);
        if (c === '"') { i++; break; }
        if (c === "\\") {
          if (i + 1 >= n) return null;
          const d = typ[i + 1]; const od = d.charCodeAt(0);
          if (!(d === "\t" || d === " " || (od >= 0x21 && od <= 0x7e))) return null;
          val.push(d); i += 2;
        } else if (c === "\t" || c === " " || c === "!" || (o >= 0x23 && o <= 0x5b) || (o >= 0x5d && o <= 0x7e)) { val.push(c); i++; }
        else return null;
      }
      value = val.join("");
    } else { [value, i] = token(i); if (value === null) return null; }
    const key = foldAZ(name);
    if (params.has(key)) return null;
    params.set(key, value);
  }
  const sorted = [...params.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return JSON.stringify([foldAZ(full), sorted]);
}
function verifyKbJwt(parsed, resolved, chainHop = false) {
  const kb = parsed.kbJwt; if (!kb) return { present: false };
  const seg = kb.split("."); if (seg.length !== 3) throw new Refused("kb-jwt must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("kb-jwt header/payload invalid: " + e.message); }   // 1.4.0: the inner reason, as the reference
  if (header.alg !== "ES256") throw new Refused("kb-jwt alg unsupported");
  if (typeof header !== "object" || header === null || Array.isArray(header) || typeof payload !== "object" || payload === null || Array.isArray(payload)) throw new Refused("kb-jwt header and payload must be objects");
  // 1.4.0 (SPEC §9.2): RFC 9901 §4.3 — typ REQUIRED, MUST be kb+jwt (§7.3 step 5.d); iat/aud/nonce/sd_hash REQUIRED with their types.
  // Presence and type, never the values (sealed scope: recorded, not validated). Checked whether or not the holder key is known.
  // 1.8.0 (SPEC §7.3, §13): compared as RFC 7515 §4.1.9 says (only A-Z folded; "application/" implied), as the reference
  if (typeof header.typ !== "string" || mediaType(header.typ) !== mediaType("kb+jwt")) throw new Refused('kb-jwt typ must be "kb+jwt" (RFC 9901 §4.3)');
  const ignored = { kb_jwt_header: joseHeaderIgnored(header, "kb-jwt header") };
  for (const [claim, pred, desc] of [["iat", (v) => Number.isInteger(v), "an integer"], ["aud", isStr, "a string"], ["nonce", isStr, "a string"], ["sd_hash", isStr, "a string"]]) {
    if (!(claim in payload)) throw new Refused("kb-jwt payload: missing " + claim + " (RFC 9901 §4.3)");
    if (!pred(payload[claim])) throw new Refused("kb-jwt payload: " + claim + " must be " + desc + " (RFC 9901 §4.3)"); }
  ignored.kb_jwt_claims = unknownMembers(payload, KB_CLAIMS_REGISTERED);
  const cnf = resolved !== null && typeof resolved === "object" && "cnf" in resolved ? resolved.cnf : undefined;   // r2: cnf absent or object; cnf.jwk absent or object
  if (cnf !== undefined && (cnf === null || typeof cnf !== "object" || Array.isArray(cnf))) throw new Refused("cnf must be an object");
  ignored.cnf = unknownMembers(cnf, CNF_REGISTERED);   // RFC 7800 §3.1: not understood -> ignored, here reported
  b64uDecode(seg[2]);   // §3.1 applies to all three segments even when the holder key is unknown (see the reference)
  const recorded = {}; for (const k of ["aud", "nonce", "iat"]) if (k in payload) recorded[k] = payload[k];   // the sealed scope says these are RECORDED whenever a KB-JWT is present
  const presentation = parsed.compact.slice(0, parsed.compact.lastIndexOf("~")) + "~";
  const sdHashOk = payload.sd_hash === b64u(sha256(Buffer.from(presentation, "ascii")));   // RFC 9901 §4.3.1: no key needed
  let cnfKey = cnf;   // 1.9.0 (SPEC §2.1): the delegate KB-JWT of a dSD-JWT+KB, under the key this hop delegates to (the reference's chain_hop)
  if (chainHop) { try { cnfKey = { jwk: chainCnfJwk(resolved) }; } catch (e) { if (!String(e.message).startsWith("chain_cnf_missing")) throw e; cnfKey = undefined; } }
  const jwk = cnfKey !== undefined && "jwk" in cnfKey ? cnfKey.jwk : undefined;
  // 1.8.1 (SPEC §9.2): sd_hash checked without the holder key too; `verified` stays null, as the reference
  if (jwk === undefined && !sdHashOk) throw new Refused("sd_hash_mismatch: the KB-JWT sd_hash is not the hash of this presentation (RFC 9901 §4.3.1; checked without cnf.jwk, SPEC §9.2)");   // 1.8.1, as the reference
  if (jwk === undefined) return { present: true, verified: null, sd_hash_ok: sdHashOk, claims_recorded_not_validated: recorded, note: "no cnf.jwk in issuer payload — holder key unknown (declared)", _ignored: ignored };
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw new Refused("cnf.jwk must be an object");
  ignored.cnf_jwk = unknownMembers(jwk, JWK_REGISTERED);   // RFC 7517 §4
  const sigOk = es256Verify(Buffer.from(seg[0] + "." + seg[1], "ascii"), b64uDecode(seg[2]), jwk);
  return { present: true, verified: Boolean(sigOk && sdHashOk), signature_ok: sigOk, sd_hash_ok: sdHashOk, note: null, claims_recorded_not_validated: recorded, _ignored: ignored };   // final check: the sealed scope says these are RECORDED — the reference did it, this verifier did not
}
const PROVENANCE_CLASSES = new Set(["supplied", "x5c_header", "jwk_header", "jwks_fetched", "chain_cnf"]);   // chain_cnf: 1.9.0 (SPEC §2.1)
// ---- closed schema (SPEC §9, 1.4.0): every object this format defines is an exhaustive key list (unknown = refusal / artifact
// error / FAIL entry, the key named); every object a standard defines follows that standard's rule for the unknown (ignored AND
// reported). Measured 2026-10-10 on 1.3.0: a key nobody defined inside rfc3161_timestamp, the producer block or a signature entry
// was accepted with valid: true and no trace in the receipt. Same lists, same three messages as the reference.
const JOSE_HEADER_REGISTERED = new Set(["alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"]);   // RFC 7515 §4.1, RFC 7519 §5
const JWK_REGISTERED = new Set(["kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "d"]);   // RFC 7517 §4, RFC 7518 §6.2
const CNF_REGISTERED = new Set(["jwk", "jwe", "jku", "kid"]);                                                                     // RFC 7800 §3.1
const KB_CLAIMS_REGISTERED = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "sd_hash"]);                      // RFC 7519 §4.1, RFC 9901 §4.3
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v) => typeof v === "string", isBool = (v) => typeof v === "boolean", isList = Array.isArray;
const T = {
  str: [isStr, "a string"], bool: [isBool, "a boolean"], obj: [isObj, "an object"], list: [isList, "a list"], any: [() => true, ""],
  strOrNull: [(v) => v === null || isStr(v), "a string or null"], boolOrNull: [(v) => v === null || isBool(v), "a boolean or null"],
  isTrue: [(v) => v === true, "true"], listOfStr: [(v) => isList(v) && v.every(isStr), "a list of strings"],
  scheme: [(v) => v === "hybrid" || v === "classical-only", '"hybrid" or "classical-only"'], over: [(v) => v === "evidence_digest_sha256", '"evidence_digest_sha256"'],
  enc: [(v) => v === "hex" || v === "b64url", '"hex" or "b64url"'] };
// [type, required]
const TOP_KEYS = { evidence_format: [T.str, 1], subject: [T.str, 1], created_utc: [T.str, 1], artifacts: [T.list, 1], bindings: [T.list, 0], honest_scope: [T.str, 1],
                   evidence_digest_sha256: [T.str, 1], rfc3161_timestamp: [T.obj, 0], producer_signatures: [T.obj, 0],
                   anchors: [[(v) => isList(v) && v.length > 0, "a non-empty list"], 0],   // 1.5.0 — SPEC §3.3
                   not_before: [T.obj, 0] };   // 1.8.0 — SPEC §12
const ANCHOR_MECHANISMS = ["rfc3161"];   // SPEC §3.3: the mechanisms this revision defines; any other is a refusal naming it
const ANCHOR_RFC3161_KEYS = { mechanism: [[(v) => v === "rfc3161", '"rfc3161"'], 1], tsr_b64: [T.str, 1], tsa_url: [T.str, 0], note: [T.str, 0] };
const DIGEST_EXCLUDED = ["evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures", "anchors"];   // SPEC §3 (1.5.0: + anchors)
const RFC3161_KEYS = { anchored: [T.bool, 1], tsr_b64: [T.str, 0], tsa_url: [T.str, 0], tsa: [T.str, 0], note: [T.str, 0] };   // tsr_b64 ABSENT under anchored: §6.4, rfc3161_verified false
const PRODUCER_KEYS = { scheme: [T.scheme, 1], over: [T.over, 1], signatures: [T.list, 1] };
const BINDING_KEYS = { in: [T.str, 1], claim: [T.str, 1], commits_to: [T.str, 1], encoding: [T.enc, 1], over: [[(v) => v === "issuer_jwt", '"issuer_jwt"'], 0] };   // over: 1.9.0 (SPEC §4)
const ARTIFACT_KEYS = { name: [T.str, 1], sd_jwt_compact: [T.str, 1], header: [T.obj, 1], key: [T.obj, 1], resolved_claims: [T.any, 1], kb_jwt: [T.obj, 1], verified_at_build: [T.obj, 1] };
const KEY_KEYS = { jwk: [T.obj, 1], provenance_class: [T.str, 1], note: [T.str, 0], x5c_chain_sha256: [T.listOfStr, 0], jwks_url: [T.str, 0], jwks_sha256: [T.str, 0], fetched_utc: [T.str, 0], chain_from: [T.str, 0] };   // chain_from: 1.9.0 (SPEC §2.1)
const KB_COPY_KEYS = { present: [T.bool, 1], verified: [T.boolOrNull, 0], signature_ok: [T.bool, 0], sd_hash_ok: [T.bool, 0], note: [T.strOrNull, 0], claims_recorded_not_validated: [T.obj, 0] };
const VAB_KEYS = { signature_ok: [T.isTrue, 1], disclosures_ok: [T.isTrue, 1] };
const ENTRY_KEYS = new Set(["sig_alg", "public_key_b64", "signature_b64", "post_quantum"]);
const byCodePoint = (a, b) => { const x = Array.from(a), y = Array.from(b); for (let i = 0; i < Math.min(x.length, y.length); i++) { const d = x[i].codePointAt(0) - y[i].codePointAt(0); if (d) return d; } return x.length - y.length; };
function entryShapeNote(entry) {   // SPEC §9.1 FAIL entry: the same note as the reference's _entry_shape_note (unknown keys by code point, then missing)
  const own = isObj(entry) ? Object.keys(entry) : [];
  const unknown = own.filter((k) => !ENTRY_KEYS.has(k)).sort(byCodePoint), missing = [...ENTRY_KEYS].filter((k) => !own.includes(k)).sort(byCodePoint);
  let note = "entry is not the closed shape of SPEC §9.1";
  if (unknown.length) note += "; unknown key(s) " + JSON.stringify(unknown);
  if (missing.length) note += "; missing " + JSON.stringify(missing);
  return note;
}
function checkClosed(obj, what, allowed) {   // SPEC §9.1 — the same three messages as the reference's _check_closed
  if (!isObj(obj)) throw new Refused(what + " must be an object (SPEC §9.1)");
  const unknown = Object.keys(obj).filter((k) => !Object.hasOwn(allowed, k)).sort(byCodePoint);   // 1.4.1: the first by code point, as the reference
  if (unknown.length) throw new UnknownMember(what + ": unknown key " + JSON.stringify(unknown[0]) + " (SPEC §9.1)");
  for (const [k, [[pred, desc], required]] of Object.entries(allowed)) {
    if (k in obj) { if (!pred(obj[k])) throw new Refused(what + ": " + k + " must be " + desc + " (SPEC §9.1)"); }
    else if (required) throw new Refused(what + ": missing " + k + " (SPEC §9.1)"); }
}
function joseHeaderIgnored(header, what) {   // RFC 7515 §4 (ignore when not understood) and §4.1.11 (crit: an extension not understood = the JWS is invalid)
  if ("crit" in header) { const c = header.crit;
    if (!isList(c) || !c.length || c.some((x) => !isStr(x)) || new Set(c).size !== c.length || c.some((x) => JOSE_HEADER_REGISTERED.has(x) || !(x in header))) throw new Refused(what + ": malformed crit (RFC 7515 §4.1.11)");
    throw new Refused(what + ": crit names extension(s) this verifier does not understand (RFC 7515 §4.1.11: the JWS is invalid)"); }
  return Object.keys(header).filter((k) => !JOSE_HEADER_REGISTERED.has(k)).sort(cmp);
}
const unknownMembers = (obj, registered) => isObj(obj) ? Object.keys(obj).filter((k) => !registered.has(k)).sort(cmp) : [];
function checkProvenance(pc, parsed, key) {   // returns: is this key SELF-ASSERTED as far as an offline verifier can tell? (r7, fail-closed)
  // r5: `jwk_header`/`x5c_header` are RECONCILED with the header the verifier just parsed (relabelling jwk_header as
  // x5c_header used to flip self_asserted_only to false with no x5c anywhere); `supplied`/`jwks_fetched` are capture-time
  // assertions that cannot be checked offline (SPEC §2).
  if (pc !== "jwk_header" && pc !== "x5c_header") return { selfAsserted: true, ident: null };   // supplied / jwks_fetched: capture-time labels, not checkable here
  const header = parsed.header && typeof parsed.header === "object" ? parsed.header : {};
  const jwk = key.jwk ?? {};
  if (pc === "jwk_header") {
    const hj = header.jwk;
    if (!hj || typeof hj !== "object" || Array.isArray(hj) || ["kty", "crv", "x", "y"].some((f) => hj[f] !== jwk[f])) throw new Refused("provenance_class jwk_header but the signed header carries no matching jwk");
    return { selfAsserted: true, ident: null };
  }
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || !x5c.length || typeof x5c[0] !== "string") throw new Refused("provenance_class x5c_header but the signed header carries no x5c");
  let leaf, ident;
  try {
    const der = b64Strict(x5c[0]); if (!der) throw new Error("leaf not base64");
    const cert = readLeaf(der);   // 1.10.0 — SPEC §2 (d): read by the walk, the same way as the reference
    leaf = cert.jwk;
    // r9: the receipt names WHO the certificate was issued to — a cleared flag means "a CA under your anchor certified this key",
    // never "the key belongs to the mandate's issuer", and an auditor cannot tell CN=the-bank from CN=attacker without this
    // r10: RFC 4514 (most specific RDN first, comma-separated) in both verifiers; 1.10.0: written by the walk (SPEC §2 (d))
    ident = { subject: cert.subject, issuer: cert.issuer, serial: cert.serial,
              not_valid_before: cert.not_valid_before, not_valid_after: cert.not_valid_after,
              sha256: createHash("sha256").update(der).digest("hex"), chain_verified: null,
              key_purpose: leafKeyPurpose(der) };   // 1.10.0 — SPEC §6 step 7: reported here too; this verifier never clears the flag
  } catch (e) { throw new Refused("provenance_class x5c_header but the x5c leaf is unusable" + leafWhy(e)); }
  if (["kty", "crv", "x", "y"].some((f) => leaf[f] !== jwk[f])) throw new Refused("provenance_class x5c_header but the x5c leaf key differs from the snapshotted jwk");
  // r8: r7 read "issued by someone else" off `subject !== issuer` — two DN strings the forger writes himself (a leaf
  // self-signed with its own key, declaring CN=DigiCert Global Root CA, cleared the flag). Offline that is not
  // establishable; only a chain validated to a relying-party trust anchor clears it, and this verifier cannot validate
  // chains, so it always reports the key as self-asserted and `chain_verified: null` (declared, like tsa_verified).
  return { selfAsserted: true, ident };   // this verifier cannot validate chains: always self-asserted (declared)
}
// 1.7.3 (SPEC §2 (d), §6 step 2, §9.2): the key sources of the protected header that are not where the snapshotted key came
// from are NAMED (ignored.key_material), and a jwk or x5c among them must name that same key (RFC 7515 §4.1.3/§4.1.6),
// otherwise that artifact's error — this format's choice, the reference does the same
const HEADER_KEY_SOURCES = ["jku", "jwk", "x5u", "x5c"];
const SOURCE_OF_CLASS = { jwk_header: "jwk", x5c_header: "x5c" };
const sameKey = (a, b) => isObj(a) && isObj(b) && ["kty", "crv", "x", "y"].every((f) => a[f] === b[f]);
function keyMaterialNotUsed(header, pc) { const used = SOURCE_OF_CLASS[pc]; return HEADER_KEY_SOURCES.filter((k) => Object.hasOwn(header, k) && k !== used).sort(cmp); }
function reconcileUnusedHeaderKeys(header, jwk, pc) {
  const used = SOURCE_OF_CLASS[pc];
  if (Object.hasOwn(header, "jwk") && used !== "jwk" && !sameKey(header.jwk, jwk)) throw new Refused("the header jwk names another key than the one the artifact verifies under (SPEC §2 (d), RFC 7515 §4.1.3)");
  if (Object.hasOwn(header, "x5c") && used !== "x5c") {
    const x5c = header.x5c;
    if (!Array.isArray(x5c) || !x5c.length || typeof x5c[0] !== "string") throw new Refused("the header x5c is not a non-empty list of certificates (SPEC §2 (d), RFC 7515 §4.1.6)");
    let leaf;
    try {
      const der = b64Strict(x5c[0]); if (!der) throw new Error("leaf not base64");
      leaf = readLeaf(der).jwk;   // as in checkProvenance
    } catch (e) { throw new Refused("the header x5c leaf is unusable" + leafWhy(e) + " (SPEC §2 (d), RFC 7515 §4.1.6)"); }
    if (!sameKey(leaf, jwk)) throw new Refused("the header x5c leaf names another key than the one the artifact verifies under (SPEC §2 (d), RFC 7515 §4.1.6)");
  }
}
function findBindings(arts) {
  const byValue = new Map();   // r5: inverse index (digest string -> [name, encoding]) — the per-leaf scan was O(artifacts), quadratic
  for (const a of arts) { const h = sha256(Buffer.from(a.compact, "ascii")); const hj = sha256(Buffer.from(a.compact.split("~")[0], "ascii"));   // 1.9.0 (SPEC §4): also over the issuer JWT
    for (const [v, enc, over] of [[h.toString("hex"), "hex", null], [b64u(h), "b64url", null], [hj.toString("hex"), "hex", "issuer_jwt"], [b64u(hj), "b64url", "issuer_jwt"]]) { if (!byValue.has(v)) byValue.set(v, []); byValue.get(v).push([a.name, enc, over]); } }
  const found = [];
  function scan(node, path, holder) { if (node !== null && typeof node === "object" && !Array.isArray(node)) { for (const k of Object.keys(node)) scan(node[k], path ? path + "." + k : k, holder); }
    else if (Array.isArray(node)) node.forEach((v, i) => scan(v, path + "[" + i + "]", holder));
    else if (typeof node === "string") { for (const [other, enc, over] of byValue.get(node) ?? []) { if (other === holder) continue; found.push({ in: holder, claim: path, commits_to: other, encoding: enc, ...(over ? { over } : {}) }); } } }
  for (const a of arts) scan(a.resolved, "", a.name); return found;
}
// 1.9.0 — SPEC §2.1: AP2 delegation chains (draft-gco-oauth-delegate-sd-jwt-00 §6 as the AP2 SDK implements it, e1ea56d)
const HOP_TERMINAL = ["kb+sd-jwt", "kb-sd-jwt"], HOP_INTERMEDIATE = ["kb+sd-jwt+kb", "kb-sd-jwt+kb"];
function chainCnfJwk(resolved) {   // the reference's chain_cnf_jwk: delegate_payload object elements first, then the top level
  const found = []; const dp = isObj(resolved) ? resolved.delegate_payload : undefined;
  for (const h of (Array.isArray(dp) ? dp.filter((x) => isObj(x)) : []).concat([resolved])) {
    if (isObj(h) && Object.hasOwn(h, "cnf")) { const c = h.cnf; if (!isObj(c) || !isObj(c.jwk)) throw new Refused("chain_cnf_malformed: a cnf of the previous hop is not an object with a jwk object (SPEC §2.1)"); found.push(c.jwk); } }
  if (!found.length) throw new Refused("chain_cnf_missing: the previous hop carries no cnf.jwk to verify this hop with (SPEC §2.1)");
  if (found.slice(1).some((f) => !sameKey(f, found[0]))) throw new Refused("chain_cnf_ambiguous: the previous hop carries two cnf.jwk naming different keys (SPEC §2.1)");
  const o = {}; for (const f of ["kty", "crv", "x", "y"]) if (Object.hasOwn(found[0], f)) o[f] = found[0][f]; return o;
}
function checkChainHop(parsed, resolved, prevCompact) {   // the reference's check_chain_hop
  const typ = parsed.header.typ; const mt = typeof typ === "string" ? mediaType(typ) : null; const k = mt === null ? null : JSON.stringify(mt);
  const term = k !== null && HOP_TERMINAL.some((t) => JSON.stringify(mediaType(t)) === k), inter = k !== null && HOP_INTERMEDIATE.some((t) => JSON.stringify(mediaType(t)) === k);
  if (!term && !inter) throw new Refused("chain_hop_typ: a hop after the first must have typ kb+sd-jwt or kb+sd-jwt+kb (SPEC §2.1)");
  const has = ["sd_hash", "issuer_jwt_hash"].filter((c) => isObj(resolved) && Object.hasOwn(resolved, c));
  if (has.length !== 1) throw new Refused("chain_binding_mismatch: a hop must carry exactly one of sd_hash and issuer_jwt_hash (SPEC §2.1)");
  const prevSd = prevCompact.slice(0, prevCompact.lastIndexOf("~") + 1);
  const want = b64u(sha256(Buffer.from(has[0] === "sd_hash" ? prevSd : prevCompact.split("~")[0], "ascii")));
  if (resolved[has[0]] !== want) throw new Refused("chain_binding_mismatch: " + has[0] + " is not the hash of the previous hop (SPEC §2.1)");
  const dp = resolved.delegate_payload;
  if (!Array.isArray(dp) || dp.length !== 1) throw new Refused("chain_delegate_payload: a hop discloses exactly one element of delegate_payload (draft-ietf-oauth-delegate-sd-jwt-00 §6 step 3.2, SPEC §2.1)");   // as the reference
  const hasCnf = Array.isArray(dp) && dp.some((x) => isObj(x) && isObj(x.cnf));
  if (term && hasCnf) throw new Refused("chain_terminal_with_cnf: a terminal hop (kb+sd-jwt) must not carry cnf (SPEC §2.1)");
  if (inter && !hasCnf) throw new Refused("chain_intermediate_without_cnf: an intermediate hop (kb+sd-jwt+kb) must carry cnf (SPEC §2.1)");
  if (term && parsed.kbJwt) throw new Refused("chain_kb_jwt_after_terminal_hop: a KB-JWT ends the chain, so its last hop must be a KB-SD-JWT+KB (typ kb-sd-jwt+kb), not a terminal kb+sd-jwt (draft-ietf-oauth-delegate-sd-jwt-00 §6 step 4.2, SPEC §2.1)");
  if (term && !Object.hasOwn(resolved, "iat")) throw new Refused("chain_terminal_without_iat: a terminal hop (kb+sd-jwt) must carry iat (SPEC §2.1)");
  return { binding: has[0], terminal: term };
}
// ---- producer signatures ----
const MLDSA65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");   // SEQ{ SEQ{OID 2.16.840.1.101.3.4.3.18}, BIT STRING(0x00||1952 bytes) } — the wrapping measured in omega-evidence
// small-order / non-canonical Ed25519 keys: with the identity key R=identity, S=0 verifies on every message and OpenSSL accepts it (measured 25/09/2026); with any small-order key a signature on any message can be built by choosing R, measured 26/09/2026; same list in verifiers/js/ap2-verify.mjs
const WEAK_ED25519 = new Set(["0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]);
function weakEd25519(pk) {
  if (WEAK_ED25519.has(pk.toString("hex"))) return true;
  if ((pk[31] & 0x7f) !== 0x7f || pk[0] < 0xed) return false;
  for (let i = 1; i < 31; i++) if (pk[i] !== 0xff) return false;
  return true;
}
const HAVE_MLDSA = (() => { try { createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.alloc(1952)]), format: "der", type: "spki" }); return true; } catch { return false; } })();
function verifyProducer(alg, pubB64, sigB64, message) {
  const pk = b64Strict(pubB64), sig = b64Strict(sigB64); if (!pk || !sig) return false;
  try {
    if (alg === "ed25519") { if (pk.length !== 32 || sig.length !== 64 || weakEd25519(pk)) return false; const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pk]), format: "der", type: "spki" }); return cryptoVerify(null, message, key, sig); }
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
    if (typeof alg !== "string") { nFail++; const r = { sig_alg: null, status: "FAIL", post_quantum: false, key_trusted: null }; if (isObj(s)) r.note = entryShapeNote(s); results.push(r); allPinned = false; continue; }   // 1.4.1: an object entry without a string sig_alg names its unknown and missing keys too   // r2: "constructor"/"__proto__" as sig_alg crashed the pin lookup on a prototype-bearing table
    // 1.4.0 — SPEC §9.1: the entry is a CLOSED object (exactly four keys, these types, post_quantum iff ml-dsa-65): otherwise a FAIL entry, never a pass
    const keys = Object.keys(s); if (!isObj(s) || keys.length !== 4 || keys.some((k) => !ENTRY_KEYS.has(k)) || !isStr(s.public_key_b64) || !isStr(s.signature_b64) || !isBool(s.post_quantum) || s.post_quantum !== (alg === "ml-dsa-65")) {
      nFail++; results.push({ sig_alg: alg, status: "FAIL", post_quantum: alg === "ml-dsa-65", key_trusted: null, note: entryShapeNote(s) }); allPinned = false; continue; }
    const v = verifyProducer(alg, pub, s.signature_b64, message);
    const status = v === true ? "PASS" : v === null ? "SKIP" : "FAIL"; if (v === true) nPass++; else if (v === false) nFail++; else nSkip++;
    let keyTrusted = null; if (trusted !== null) { const allowed = Object.hasOwn(trusted, alg) ? [].concat(trusted[alg]) : []; keyTrusted = allowed.includes(pub); if (!keyTrusted) allPinned = false; }   // 1.11.0: a pin given as one string is that key, as in the reference (String.includes was a substring match)
    if (v === true && alg === "ml-dsa-65" && (trusted === null || keyTrusted)) pq = true;
    results.push({ sig_alg: alg, status, post_quantum: alg === "ml-dsa-65", key_trusted: keyTrusted });
  }
  // 1.4.0 — SPEC §5/§9.1: `scheme` reconciled with the entries ("hybrid" = a classical AND an ml-dsa-65 entry; "classical-only" = no ml-dsa-65)
  const algs = results.map((r) => r.sig_alg); const hasPq = algs.includes("ml-dsa-65"), hasClassical = algs.some((a) => a === "ed25519" || a === "ecdsa-p256");
  const schemeOk = (block?.scheme === "hybrid" && hasPq && hasClassical) || (block?.scheme === "classical-only" && !hasPq);
  const ok = nPass >= 1 && nFail === 0 && nSkip === 0 && schemeOk;
  // 1.5.4 — SPEC §5: a block that is not ok states neither trust (null) nor post-quantum protection (false), as the reference
  const trustedOk = trusted === null || !ok ? null : allPinned;
  return { ok, incomplete: nSkip > 0 && nFail === 0, pq_protected: pq && ok, trusted: trustedOk, results, scheme_ok: schemeOk };
}
// ---- RFC 3161 token: minimal DER walk — TimeStampResp{ status PKIStatusInfo{ INTEGER }, timeStampToken ContentInfo{ OID, [0] SignedData{ ..., encapContentInfo{ OID id-ct-TSTInfo, [0] OCTET STRING TSTInfo } } } }
// TSTInfo{ version, policy OID, messageImprint{ AlgorithmIdentifier, OCTET STRING hash } ... }. Same two facts the reference checks
// (SPEC §3.2). TSA signature/chain: only the reference, with `--tsa-cert` through `openssl ts -verify`; here `tsa_verified` is null (declared).
function derTLV(buf, off) { if (off + 2 > buf.length) throw new Refused("der"); const tag = buf[off]; let len = buf[off + 1], hl = 2;
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4 || off + 2 + n > buf.length) throw new Refused("der len"); len = 0; for (let k = 0; k < n; k++) len = len * 256 + buf[off + 2 + k]; hl = 2 + n; }   // r3: `<<` is int32 — 0x84 80 00 00 00 went negative and passed the overrun check
  if (off + hl + len > buf.length) throw new Refused("der overrun"); return { tag, start: off + hl, end: off + hl + len, next: off + hl + len }; }
function derChildren(buf, tlv) { const out = []; let o = tlv.start; while (o < tlv.end) { const c = derTLV(buf, o); out.push(c); o = c.next; } return out; }
// 1.10.0 — SPEC §6 step 7: whether an x5c leaf was issued for signing, the same rule and the same object as the reference's
// leaf_key_purpose. keyUsage (RFC 5280 §4.2.1.3): digitalSignature (bit 0) or nonRepudiation / contentCommitment (bit 1);
// extendedKeyUsage (§4.2.1.12): one of a closed list, this format's choice — id-kp-documentSigning (RFC 9336) and, since
// 1.10.0, the mDL Document Signer purpose 1.0.18013.5.1.2; anyExtendedKeyUsage is not a purpose since 1.10.0. Both
// absent: signing. OBJECT IDENTIFIER contents compared byte for byte; `matched` reports the dotted name.
const ID_CE_KEY_USAGE = "551d0f", ID_CE_EXT_KEY_USAGE = "551d25";
const SIGNING_EKUS = new Map([["2b06010505070324", "1.3.6.1.5.5.7.3.36"],   // id-kp-documentSigning (RFC 9336 §3.1)
  ["28818c5d050102", "1.0.18013.5.1.2"]]);   // mDL Document Signer (1.10.0; name: oid-base.com)
function oidOk(c) {   // X.690 §8.19.2: last octet of each sub-identifier with bit 8 clear, none starting with 0x80
  if (!c.length || c[c.length - 1] & 0x80) return false;
  let start = true; for (const b of c) { if (start && b === 0x80) return false; start = !(b & 0x80); } return true; }
// the purpose walk reads DER: the length in its minimal definite form (X.690 §10.1) and the element inside its parent,
// which ends at `end` — derTLV alone takes a long form where the short one fits and bounds an element by the buffer
function derStrictTLV(buf, off, end) { const t = derTLV(buf, off);
  if (t.end > end || (t.start - off > 2 && (buf[off + 2] === 0 || t.end - t.start < 128))) throw new Refused("der: not DER"); return t; }
function derStrictChildren(buf, tlv) { const out = []; let o = tlv.start; while (o < tlv.end) { const c = derStrictTLV(buf, o, tlv.end); out.push(c); o = c.next; } return out; }
// 1.10.0 — SPEC §2 (d): the x5c leaf walked as DER (ITU-T X.690 02/2021) with the shape of RFC 5280 §4.1, the same rules
// as the reference's x5c_leaf_der_problem; node:crypto (OpenSSL reads BER) does not read the leaf, it is asked only
// whether the key is a point of P-256 (readLeaf). Measured 2026-11-21, when node:crypto still read it: 52 of
// 5205 one-bit and one-byte changes of one leaf were a certificate for one verifier only.
const LEAF_PRIMITIVE = new Set([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1c, 0x1e, 0x81, 0x82]);
const LEAF_CONSTRUCTED = new Set([0x30, 0x31, 0xa0, 0xa1, 0xa2, 0xa3]);
const ATTRIBUTE_VALUE = new Set([0x0c, 0x13, 0x14, 0x16, 0x1c, 0x1e]);
const PRINTABLE = new Set(Buffer.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?", "latin1"));
const NUMERIC = new Set(Buffer.from("0123456789 ", "latin1"));
const LEAF_MAX_DEPTH = 16;   // SPEC §2 (d), `depth`: no element inside more than 16 constructed elements — the reference's _LEAF_MAX_DEPTH
class NotDer extends Error { constructor(rule) { super(rule); this.rule = rule; } }
function derTimeOk(c, utc) {
  const n = utc ? 12 : 14;
  if (c.length !== n + 1 || c[n] !== 0x5a || ![...c.subarray(0, n)].every((b) => b >= 0x30 && b <= 0x39)) return false;
  const d = c.subarray(0, n).toString("latin1"); const two = (i) => Number(d.slice(i, i + 2));
  const y = utc ? two(0) + (two(0) >= 50 ? 1900 : 2000) : Number(d.slice(0, 4));
  const [mo, dd, hh, mi, ss] = [0, 1, 2, 3, 4].map((k) => two(n - 10 + 2 * k));
  if (!(mo >= 1 && mo <= 12 && hh <= 23 && mi <= 59 && ss <= 59 && dd >= 1)) return false;
  if (!utc && y < 2050) return false;   // 1.10.0: RFC 5280 §4.1.2.5, dates through 2049 are UTCTime
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  return dd <= [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
}
function derPrimitiveOk(tag, c) {
  if (tag === 0x01) return c.length === 1 && (c[0] === 0x00 || c[0] === 0xff) ? null : "boolean";
  if (tag === 0x02) return c.length && !(c.length > 1 && ((c[0] === 0 && c[1] < 0x80) || (c[0] === 0xff && c[1] >= 0x80))) ? null : "integer";
  if (tag === 0x03 || tag === 0x81 || tag === 0x82) return c.length && c[0] <= 7 && (c.length > 1 || c[0] === 0) && !(c.length > 1 && (c[c.length - 1] & ((1 << c[0]) - 1))) ? null : "bit_string";
  if (tag === 0x05) return c.length ? "null" : null;
  if (tag === 0x06) return oidOk(c) ? null : "oid";
  if (tag === 0x0c) { try { UTF8.decode(c); return null; } catch { return "string"; } }
  if (tag === 0x13) return [...c].every((b) => PRINTABLE.has(b)) ? null : "string";
  if (tag === 0x12) return [...c].every((b) => NUMERIC.has(b)) ? null : "string";
  if (tag === 0x16) return [...c].every((b) => b < 0x80) ? null : "string";
  if (tag === 0x14) return [...c].every((b) => b < 0x80) ? null : "string";   // 1.10.0: TeletexString in 7 bits
  if (tag === 0x1e) { if (c.length % 2) return "string"; for (let k = 0; k < c.length; k += 2) if (c[k] >= 0xd8 && c[k] <= 0xdf) return "string"; return null; }   // 1.10.0: UCS-2, no surrogate
  if (tag === 0x1c) { if (c.length % 4) return "string"; for (let k = 0; k < c.length; k += 4) { const v = c.readUInt32BE(k); if (v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return "string"; } return null; }   // 1.10.0: UCS-4
  if (tag === 0x17 || tag === 0x18) return derTimeOk(c, tag === 0x17) ? null : "time";
  return null;   // OCTET STRING: any contents
}
function derSetOrderOk(buf, kids) {   // X.690 §11.6: ascending, the shorter padded with 0-octets
  const enc = kids.map((k) => buf.subarray(k.at, k.end));
  for (let i = 0; i + 1 < enc.length; i++) { const n = Math.max(enc[i].length, enc[i + 1].length);
    const a = Buffer.concat([enc[i], Buffer.alloc(n - enc[i].length)]), b = Buffer.concat([enc[i + 1], Buffer.alloc(n - enc[i + 1].length)]);
    if (Buffer.compare(a, b) > 0) return false; }
  return true;
}
function derWalk(buf, start, end, depth = 0) {
  const out = []; let o = start;
  while (o < end) {
    if (depth > LEAF_MAX_DEPTH) throw new NotDer("depth");
    if ((buf[o] & 0x1f) === 0x1f) throw new NotDer("tag");
    let t; try { t = derStrictTLV(buf, o, end); } catch { throw new NotDer("length"); }
    if (LEAF_CONSTRUCTED.has(t.tag)) { const kids = derWalk(buf, t.start, t.end, depth + 1); if (t.tag === 0x31 && !derSetOrderOk(buf, kids)) throw new NotDer("set_order"); }
    else if (LEAF_PRIMITIVE.has(t.tag)) { const why = derPrimitiveOk(t.tag, buf.subarray(t.start, t.end)); if (why) throw new NotDer(why); }
    else throw new NotDer("tag");
    out.push({ tag: t.tag, start: t.start, end: t.end, at: o }); o = t.end;
  }
  return out;
}
const SIGNATURE_ALGORITHMS = new Set(["300a06082a8648ce3d040302", "300a06082a8648ce3d040303", "300a06082a8648ce3d040304",   // ecdsa-with-SHA256/384/512, RFC 5758 §3.2
  "300d06092a864886f70d01010b0500", "300d06092a864886f70d01010c0500", "300d06092a864886f70d01010d0500",   // sha2WithRSA, NULL
  "300b06092a864886f70d01010b", "300b06092a864886f70d01010c", "300b06092a864886f70d01010d",   // the same, absent (RFC 4055 §5)
  "300506032b6570"]);   // Ed25519, RFC 8410 §3
const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200" + "04";   // RFC 5480 §2.1.1, §2.2
const P256_P = (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n;   // the prime of P-256: each coordinate is in [0, p - 1] (SEC 1 §2.3.6)
// RFC 4514 §3 and the string attribute types of the IANA LDAP Descriptors registry that SPEC §2 (d) lists (1.10.0); every
// other type is written dotted (RFC 4514 §2.3: a short name "known to be registered", else the dotted OID)
const NAME_TYPES = new Map([["2.5.4.3", "CN"], ["2.5.4.7", "L"], ["2.5.4.8", "ST"], ["2.5.4.10", "O"], ["2.5.4.11", "OU"], ["2.5.4.6", "C"],
  ["2.5.4.9", "STREET"], ["0.9.2342.19200300.100.1.25", "DC"], ["0.9.2342.19200300.100.1.1", "UID"], ["2.5.4.15", "businessCategory"],
  ["2.5.4.13", "description"], ["2.5.4.27", "destinationIndicator"], ["2.5.4.46", "dnQualifier"], ["2.5.4.44", "generationQualifier"],
  ["2.5.4.42", "givenName"], ["2.5.4.51", "houseIdentifier"], ["2.5.4.43", "initials"], ["2.5.4.25", "internationalISDNNumber"],
  ["2.5.4.41", "name"], ["2.5.4.19", "physicalDeliveryOfficeName"], ["2.5.4.17", "postalCode"], ["2.5.4.18", "postOfficeBox"], ["2.5.4.5",
  "serialNumber"], ["2.5.4.4", "sn"], ["2.5.4.20", "telephoneNumber"], ["2.5.4.12", "title"], ["2.5.4.24", "x121Address"], ["2.5.4.65",
  "pseudonym"], ["1.2.840.113549.1.9.1", "emailAddress"]]);
function oidDotted(c) {
  const out = []; let v = 0n;
  for (const b of c) { v = (v << 7n) | BigInt(b & 0x7f); if (!(b & 0x80)) { out.push(v); v = 0n; } }
  const first = out[0]; const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return head.concat(out.slice(1)).map(String).join(".");
}
function nameValue(tag, c) {
  let text;
  if (tag === 0x0c) text = UTF8.decode(c);
  else if (tag === 0x1e) { text = ""; for (let k = 0; k < c.length; k += 2) text += String.fromCharCode(c.readUInt16BE(k)); }
  else if (tag === 0x1c) { text = ""; for (let k = 0; k < c.length; k += 4) text += String.fromCodePoint(c.readUInt32BE(k)); }
  else text = c.toString("latin1");
  const chars = [...text]; let out = "";
  chars.forEach((ch, k) => {
    const cp = ch.codePointAt(0);
    if ('"+,;<>\\'.includes(ch) || (" #".includes(ch) && k === 0) || (ch === " " && k === chars.length - 1)) out += "\\" + ch;
    else if (cp < 0x20 || cp === 0x7f) out += "\\" + cp.toString(16).toUpperCase().padStart(2, "0");
    else out += ch;
  });
  return out;
}
function nameRender(buf, name) {   // RFC 4514 §2 as SPEC §2 (d) writes it: RDNs last to first, ","; the values of one RDN in DER order, "+"
  const rdns = [];
  for (const rdn of derWalk(buf, name.start, name.end)) {
    const parts = [];
    for (const atv of derWalk(buf, rdn.start, rdn.end)) {
      const [oidEl, val] = derWalk(buf, atv.start, atv.end);
      const dotted = oidDotted(buf.subarray(oidEl.start, oidEl.end)); const short = NAME_TYPES.get(dotted);
      parts.push(short ? short + "=" + nameValue(val.tag, buf.subarray(val.start, val.end)) : dotted + "=#" + buf.subarray(val.at, val.end).toString("hex"));
    }
    rdns.push(parts.join("+"));
  }
  return rdns.reverse().join(",");
}
export function leafNames(der) {   // [subject, issuer] as SPEC §2 (d) writes them: the reference's leaf_names
  const top = derWalk(der, 0, der.length); let tbs = derWalk(der, top[0].start, top[0].end); tbs = derWalk(der, tbs[0].start, tbs[0].end);
  const i = tbs[0].tag === 0xa0 ? 1 : 0; return [nameRender(der, tbs[i + 4]), nameRender(der, tbs[i + 2])];
}
function timeRender(tag, c) {
  let d = c.subarray(0, c.length - 1).toString("latin1");
  if (tag === 0x17) d = (Number(d.slice(0, 2)) >= 50 ? "19" : "20") + d;
  return `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T${d.slice(8, 10)}:${d.slice(10, 12)}:${d.slice(12, 14)}Z`;
}
function x5cLeafShape(buf) {
  const top = derWalk(buf, 0, buf.length); if (top.length !== 1 || top[0].tag !== 0x30) throw new NotDer("tbs");
  const cert = derWalk(buf, top[0].start, top[0].end); if (cert.map((k) => k.tag).join() !== [0x30, 0x30, 0x03].join()) throw new NotDer("tbs");
  const tbs = derWalk(buf, cert[0].start, cert[0].end); let i = 0;
  if (tbs.length && tbs[0].tag === 0xa0) { if (buf.subarray(tbs[0].at, tbs[0].end).toString("hex") !== "a003020102") throw new NotDer("version"); i = 1; }   // v3; v1 is the DEFAULT (X.690 §11.5)
  const body = tbs.slice(i, i + 6).map((k) => k.tag), rest = tbs.slice(i + 6).map((k) => k.tag);
  const restOk = rest.every((x, j) => [0x81, 0x82, 0xa3].includes(x) && (j === 0 || rest[j - 1] < x));
  if (body.join() !== [0x02, 0x30, 0x30, 0x30, 0x30, 0x30].join() || !restOk) throw new NotDer("tbs");
  const spki = derWalk(buf, tbs[i + 5].start, tbs[i + 5].end); if (spki.map((k) => k.tag).join() !== [0x30, 0x03].join()) throw new NotDer("tbs");
  for (const bits of [spki[1], cert[2]]) if (buf[bits.start] !== 0) throw new NotDer("bit_string");   // subjectPublicKey (an ECPoint, octets: RFC 5480 §2.2) and signature: no unused bit
  const serial = buf.subarray(tbs[i].start, tbs[i].end); if ((serial[0] & 0x80) || serial.every((b) => b === 0)) throw new NotDer("serial");   // RFC 5280 §4.1.2.2: positive
  const validity = derWalk(buf, tbs[i + 3].start, tbs[i + 3].end); if (validity.length !== 2 || !validity.every((k) => k.tag === 0x17 || k.tag === 0x18)) throw new NotDer("tbs");
  for (const name of [tbs[i + 2], tbs[i + 4]]) for (const rdn of derWalk(buf, name.start, name.end)) {   // SEQUENCE OF SET OF SEQUENCE { OID, AttributeValue }
    if (rdn.tag !== 0x31) throw new NotDer("tbs");
    for (const atv of derWalk(buf, rdn.start, rdn.end)) { const parts = atv.tag === 0x30 ? derWalk(buf, atv.start, atv.end) : [];
      if (parts.length !== 2 || parts[0].tag !== 0x06) throw new NotDer("tbs"); if (!ATTRIBUTE_VALUE.has(parts[1].tag)) throw new NotDer("attribute_value"); }
    const types = derWalk(buf, rdn.start, rdn.end).map((atv) => { const o = derWalk(buf, atv.start, atv.end)[0]; return buf.subarray(o.start, o.end).toString("hex"); });
    if (!types.length || new Set(types).size !== types.length) throw new NotDer("name"); }   // 1.10.0: SET SIZE (1..MAX), no attribute type twice
  for (const k of tbs.slice(i + 6)) { if (k.tag !== 0xa3) continue;
    const inner = derWalk(buf, k.start, k.end); if (inner.length !== 1 || inner[0].tag !== 0x30) throw new NotDer("extension");
    for (const ext of derWalk(buf, inner[0].start, inner[0].end)) { const parts = ext.tag === 0x30 ? derWalk(buf, ext.start, ext.end) : [];
      const shape = parts.map((p) => p.tag).join(); if (shape !== "6,4" && shape !== "6,1,4") throw new NotDer("extension");
      if (parts.length === 3 && !(parts[1].end - parts[1].start === 1 && buf[parts[1].start] === 0xff)) throw new NotDer("extension"); } }   // critical FALSE is the DEFAULT (X.690 §11.5)
  const sigIn = buf.subarray(tbs[i + 1].at, tbs[i + 1].end).toString("hex");   // 1.10.0: RFC 5280 §4.1.1.2, and a closed list of algorithms
  if (sigIn !== buf.subarray(cert[1].at, cert[1].end).toString("hex") || !SIGNATURE_ALGORITHMS.has(sigIn)) throw new NotDer("algorithm");
  const key = buf.subarray(tbs[i + 5].at, tbs[i + 5].end);
  if (key.length !== P256_SPKI_PREFIX.length / 2 + 64 || !key.toString("hex").startsWith(P256_SPKI_PREFIX)) throw new NotDer("key");   // 1.10.0: EC P-256, uncompressed
  if (BigInt("0x" + key.subarray(key.length - 64, key.length - 32).toString("hex")) >= P256_P || BigInt("0x" + key.subarray(key.length - 32).toString("hex")) >= P256_P)
    throw new NotDer("key");   // SEC 1 §2.3.4 step 3 and §2.3.6: a coordinate not in [0, p - 1] is "invalid"
  return { subject: nameRender(buf, tbs[i + 4]), issuer: nameRender(buf, tbs[i + 2]),
    serial: BigInt("0x" + buf.subarray(tbs[i].start, tbs[i].end).toString("hex")).toString(16),
    not_valid_before: timeRender(validity[0].tag, buf.subarray(validity[0].start, validity[0].end)),
    not_valid_after: timeRender(validity[1].tag, buf.subarray(validity[1].start, validity[1].end)),
    x: key.subarray(key.length - 64, key.length - 32), y: key.subarray(key.length - 32) };
}
// 1.10.0 — SPEC §2 (d): the leaf as the walk reads it; node:crypto is asked only whether the key is a point of P-256 (a JWK
// import). Up to the branch head d76b66c node:crypto read the certificate (X509Certificate): it aborted the process on a
// key that is the point at infinity, and it decided and wrote some leaves otherwise than the reference (SPEC §2 (d)).
function readLeaf(der) {
  let r; try { r = x5cLeafShape(der); } catch (e) { if (e instanceof NotDer) throw new Error("x5c leaf is not DER: " + e.rule); throw e; }
  let jwk; try { jwk = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(r.x), y: b64u(r.y) }, format: "jwk" }).export({ format: "jwk" }); }
  catch { throw new Error("x5c leaf is not DER: key"); }   // not a point of P-256
  return { ...r, jwk };
}
export function x5cLeafIdentity(der) {   // the reference's x5c_leaf_identity: what a receipt says of the leaf, and its key
  const r = readLeaf(der); return { subject: r.subject, issuer: r.issuer, serial: r.serial, not_valid_before: r.not_valid_before, not_valid_after: r.not_valid_after,
    jwk: { kty: r.jwk.kty, crv: r.jwk.crv, x: r.jwk.x, y: r.jwk.y } };
}
// the rule of SPEC §2 (d) in an artifact's error, as the reference writes it (1.10.0)
const leafWhy = (e) => (e instanceof Error && e.message.startsWith("x5c leaf is not DER: ") ? ": " + e.message : "");
export function x5cLeafDerProblem(der) {   // null, or the rule broken (SPEC §2 (d)) — the reference's x5c_leaf_der_problem
  try { x5cLeafShape(der); return null; } catch (e) { if (e instanceof NotDer) return e.rule; throw e; } }
export function leafKeyPurpose(der) {
  const no = (reason) => ({ signing: false, reason, matched: null });
  const found = new Map();
  try {
    const cert = derStrictTLV(der, 0, der.length); if (cert.tag !== 0x30 || cert.end !== der.length) return no("extensions_unreadable");
    const tbs = derStrictChildren(der, cert)[0]; if (!tbs || tbs.tag !== 0x30) return no("extensions_unreadable");
    const exts = derStrictChildren(der, tbs).filter((c) => c.tag === 0xa3);
    if (exts.length > 1) return no("extensions_unreadable");
    if (exts.length) {
      const inner = derStrictChildren(der, exts[0]); if (inner.length !== 1 || inner[0].tag !== 0x30) return no("extensions_unreadable");
      for (const ext of derStrictChildren(der, inner[0])) {
        const parts = ext.tag === 0x30 ? derStrictChildren(der, ext) : [];
        if (!(parts.length >= 2 && parts.length <= 3 && parts[0].tag === 0x06 && parts[parts.length - 1].tag === 0x04 && (parts.length === 2 || parts[1].tag === 0x01))) return no("extensions_unreadable");
        const oid = der.subarray(parts[0].start, parts[0].end).toString("hex");
        if (oid === ID_CE_KEY_USAGE || oid === ID_CE_EXT_KEY_USAGE) {
          if (found.has(oid)) return no("duplicate_extension");   // RFC 5280 §4.2: not more than one instance of a particular extension
          const v = parts[parts.length - 1]; found.set(oid, der.subarray(v.start, v.end)); } } }
  } catch { return no("extensions_unreadable"); }
  const ku = found.get(ID_CE_KEY_USAGE);
  if (ku !== undefined) {
    let t; try { t = derStrictTLV(ku, 0, ku.length); } catch { return no("key_usage_malformed"); }
    const bits = ku.subarray(t.start, t.end);
    if (t.tag !== 0x03 || t.end !== ku.length || !bits.length || bits[0] > 7 || (bits.length === 1 && bits[0] !== 0)
        || (bits.length > 1 && (bits[bits.length - 1] & ((1 << bits[0]) - 1)))
        || (bits.length > 1 && (bits[bits.length - 1] & -bits[bits.length - 1]) !== 1 << bits[0])) return no("key_usage_malformed");   // X.690 §11.2.2: trailing 0 bits removed (1.10.0)
    if (bits.length < 2 || !(bits[1] & 0xc0)) return no("key_usage_not_signing");   // digitalSignature 0x80, nonRepudiation 0x40
  }
  const eku = found.get(ID_CE_EXT_KEY_USAGE);
  if (eku !== undefined) {
    let ids = null; try { const t = derStrictTLV(eku, 0, eku.length); if (t.tag === 0x30 && t.end === eku.length) ids = derStrictChildren(eku, t); } catch { ids = null; }
    if (!ids || !ids.length || ids.some((c) => c.tag !== 0x06 || !oidOk(eku.subarray(c.start, c.end)))) return no("extended_key_usage_malformed");   // SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    const hit = ids.map((c) => SIGNING_EKUS.get(eku.subarray(c.start, c.end).toString("hex"))).find((x) => x !== undefined);
    if (hit === undefined) return no("extended_key_usage_not_signing");   // anyExtendedKeyUsage alone is not a purpose here (1.10.0)
    return { signing: true, reason: null, matched: hit };
  }
  return { signing: true, reason: null, matched: null };
}
function verifyRfc3161(tsrB64, expectedDigestHex) {
  // r11: granted null = no status was read (the bytes never decoded), not "the TSA refused" — a value the receipt never measured
  const raw = b64Strict(tsrB64); if (!raw) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "tsr_b64 is not canonical base64" };   // r11: null = never read
  let grantedRead = null;   // r10: the status read before any later failure, so the receipt reports a measured granted, never an assumed one
  try {
    const resp = derTLV(raw, 0); if (resp.tag !== 0x30) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "not a TimeStampResp" };   // r11: same receipt shape as every other branch
    const [status, token] = derChildren(raw, resp); const st = derChildren(raw, status)[0]; if (!st || st.tag !== 0x02) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "no status" };   // r11
    const granted = st.end - st.start === 1 && (raw[st.start] === 0 || raw[st.start] === 1); grantedRead = granted;   // granted (0) / grantedWithMods (1)
    if (!token) return { verified: false, granted, imprint_ok: null, gen_time: null };   // r11: no token, so no imprint was read
    const ci = derChildren(raw, token); const sd = ci[1] && derChildren(raw, ci[1])[0]; if (!sd) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const sdc = derChildren(raw, sd);           // version, digestAlgorithms, encapContentInfo, [certs], [crls], signerInfos
    const eci = sdc[2]; const ecic = derChildren(raw, eci); const wrap = ecic[1] && derChildren(raw, ecic[1])[0]; if (!wrap || wrap.tag !== 0x04) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const tst = derTLV(raw, wrap.start); const tstc = derChildren(raw, tst);   // version, policy, messageImprint, serial, genTime, ...
    const mi = tstc[2]; const mic = derChildren(raw, mi); const hash = mic[1]; if (!hash || hash.tag !== 0x04) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const imprint = raw.subarray(hash.start, hash.end).toString("hex"); const imprintOk = imprint === expectedDigestHex.toLowerCase();
    let genTime = null; const gt = tstc[4]; if (gt && gt.tag === 0x18) { const s = raw.subarray(gt.start, gt.end).toString("latin1"); if (/^\d{14}(\.\d+)?Z$/.test(s)) genTime = s; }   // r4: TSTInfo.genTime, reported as in the reference
    return { verified: Boolean(granted && imprintOk), granted, imprint_ok: imprintOk, gen_time: genTime };
  } catch (e) { return { verified: false, granted: grantedRead, imprint_ok: null, gen_time: null, note: "token not parseable: " + (e.message ?? e) }; }   // r10: same shape and same measured status as the reference
}
// 1.5.0 — SPEC §3.3: the identity of an anchor is the TSTInfo the TSA signed (eContent of the token), not the bytes around
// it. Called only on a token whose binding verified, so the walk below already succeeded once in verifyRfc3161.
function tstInfoHex(tsrB64) {
  const raw = b64Strict(tsrB64);
  try {
    const resp = derTLV(raw, 0); const token = derChildren(raw, resp)[1];
    const ci = derChildren(raw, token); const sd = derChildren(raw, ci[1])[0]; const sdc = derChildren(raw, sd);
    const wrap = derChildren(raw, derChildren(raw, sdc[2])[1])[0];
    return "tst:" + raw.subarray(wrap.start, wrap.end).toString("hex");
  } catch { return "raw:" + raw.toString("hex"); }
}
// ---- evidence ----
// The file is opened WITHOUT blocking and read only if the OPEN descriptor is a regular file, at most MAX_BYTES bytes: a FIFO
// must not hang the verifier, a symlink to /dev/zero (a device reports size 0) must not be read until memory runs out.
// null = above the bound; a FIFO / device / directory throws "unreadable evidence file: not a regular file".
function readEvidenceBytes(path) {
  if (!statSync(path).isFile()) throw new Refused("unreadable evidence file: not a regular file");   // refused BEFORE it is opened (opening a device can act on it)
  const fd = openSync(path, FS.O_RDONLY | (FS.O_NONBLOCK ?? 0) | (FS.O_NOCTTY ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Refused("unreadable evidence file: not a regular file");
    if (st.size > MAX_BYTES) return null;
    const chunks = [], chunk = Buffer.allocUnsafe(1 << 20); let total = 0;
    for (;;) { const got = readSync(fd, chunk, 0, chunk.length, null); if (got === 0) break; total += got; if (total > MAX_BYTES) return null; chunks.push(Buffer.from(chunk.subarray(0, got))); }
    return Buffer.concat(chunks, total);
  } finally { closeSync(fd); }
}
// ---- not-before block (SPEC §12, 1.8.0): written again here from the SPEC and the reference's rules, line for line
// (ap2_evidence.parse_not_before / check_not_before, ap2_nist_beacon), node:crypto for SHA-2 only; RSA by BigInt as the
// reference does it (pure modular exponentiation), so both verifiers decide the same pulses the same way.
const NB_PROFILE = "ap2-evidence-pack.not-before/1";
const NB_IBAN_MEMBERS = ["payer_iban_commitment", "payee_iban_commitment"];
const NB_TEXT_MEMBERS = ["payer_name_commitment", "payer_details_commitment", "payee_name_commitment"];
const NB_COMMITMENT_MEMBERS = NB_IBAN_MEMBERS.concat(NB_TEXT_MEMBERS);
const NB_MINOR_UNITS = { EUR: 2, USD: 2, GBP: 2, CHF: 2, JPY: 0 };
const NB_PINNED = { "5b6386e6ac8a993bac8d99d6549deda44af82f2fa4a0e9c0025b6474ab0cbfcab67bfff264fda41aac003b0c9ee7fb77d2938dc0f286fb73cc8fa79864ec0c18": 2 };
const NB_AMOUNT = /^(0|[1-9][0-9]{0,17})(?:\.([0-9]{1,4}))?$/, NB_HEX64L = /^[0-9a-f]{64}$/, NB_RECORD_SALT = /^(?:[0-9a-f]{2}){16,64}$/;
const NB_HEX128 = /^[0-9A-Fa-f]{128}$/, NB_PAYMENT_ID = /^[A-Za-z0-9/?:().,'+ -]{1,35}$/;
const nbStr = (v) => typeof v === "string", nbInt = (v) => typeof v === "number" && Number.isInteger(v);
const NB_KEYS = { profile: [[(v) => v === NB_PROFILE, JSON.stringify(NB_PROFILE).replace(/^"|"$/g, "'")], 1], payment: [T.obj, 1], mandate: [T.obj, 1], pulses: [T.obj, 1] };
const NB_PAYMENT_KEYS = { payment_id: [T.str, 1], amount: [T.str, 1], currency: [T.str, 1], payer_iban_commitment: [T.str, 1], payee_iban_commitment: [T.str, 1],
  record_salt: [T.str, 1], beacon: [T.obj, 1], payer_name_commitment: [T.str, 0], payer_details_commitment: [T.str, 0], payee_name_commitment: [T.str, 0] };
const NB_BEACON_KEYS = { source: [[(v) => v === "nist-beacon-2.0", '"nist-beacon-2.0"'], 1], chain_index: [[(v) => nbInt(v) && v >= 0, "an integer >= 0"], 1],
  pulse_index: [[(v) => nbInt(v) && v >= 1, "an integer >= 1"], 1], output_value: [[(v) => nbStr(v) && NB_HEX128.test(v), "128 hexadecimal characters"], 1] };
const NB_MANDATE_KEYS = { artifact: [[(v) => nbStr(v) && v !== "", "a non-empty string"], 1], amount_claim: [[(v) => nbStr(v) && v !== "", "a non-empty string"], 1] };
const NB_PULSES_KEYS = { pulse: [T.obj, 1], previous_pulse: [T.obj, 1], certificate: [T.str, 1] };
class PulseError extends Error {}
// a real calendar time, as Python's datetime(): month 1-12, the month's days, hour 0-23, minute and second 0-59; else null
function nbCalendar([Y, M, D, h, m, s]) {
  if (Y < 1 || M < 1 || M > 12 || D < 1 || h > 23 || m > 59 || s > 59) return null;
  const d = new Date(0); d.setUTCFullYear(Y, M - 1, D); d.setUTCHours(h, m, s, 0);   // setUTCFullYear: no 1900 offset for years 1-99
  return d.getUTCFullYear() === Y && d.getUTCMonth() === M - 1 && d.getUTCDate() === D ? d.getTime() : null;
}
const PULSE_KEYS = ["uri", "version", "cipherSuite", "period", "certificateId", "chainIndex", "pulseIndex", "timeStamp", "localRandomValue", "external",
  "listValues", "precommitmentValue", "statusCode", "signatureValue", "outputValue"];
const LIST_TYPES = ["previous", "hour", "day", "month", "year"];
const P_HEX64 = /^[0-9A-F]{128}$/, P_HEX64L = /^[0-9a-f]{128}$/, P_TS = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.000Z$/;
function checkPulseGrammar(p) {
  if (!isObj(p)) throw new PulseError("pulse_not_object");
  const extra = Object.keys(p).filter((k) => !PULSE_KEYS.includes(k)).sort(byCodePoint); if (extra.length) throw new PulseError("pulse_unknown_member:" + extra[0]);
  const missing = PULSE_KEYS.filter((k) => !Object.hasOwn(p, k)).sort(byCodePoint); if (missing.length) throw new PulseError("pulse_missing_member:" + missing[0]);
  for (const k of ["uri", "version", "timeStamp", "certificateId", "localRandomValue", "precommitmentValue", "signatureValue", "outputValue"]) if (!nbStr(p[k])) throw new PulseError("pulse_member_not_string:" + k);
  for (const k of ["cipherSuite", "period", "chainIndex", "pulseIndex", "statusCode"]) if (!nbInt(p[k]) || p[k] < 0) throw new PulseError("pulse_member_not_integer:" + k);
  if (p.version !== "2.0") throw new PulseError("pulse_version_unsupported");
  if (p.cipherSuite !== 0) throw new PulseError("pulse_cipher_suite_unsupported");
  if (!P_HEX64L.test(p.certificateId)) throw new PulseError("pulse_hex_malformed:certificateId");
  for (const k of ["localRandomValue", "precommitmentValue", "outputValue"]) if (!P_HEX64.test(p[k])) throw new PulseError("pulse_hex_malformed:" + k);
  if (!/^(?:[0-9A-F]{2})+$/.test(p.signatureValue)) throw new PulseError("pulse_hex_malformed:signatureValue");
  if (!P_TS.test(p.timeStamp) || nbCalendar(P_TS.exec(p.timeStamp).slice(1).map(Number)) === null) throw new PulseError("pulse_timestamp_malformed");
  if (p.uri !== `https://beacon.nist.gov/beacon/2.0/chain/${p.chainIndex}/pulse/${p.pulseIndex}`) throw new PulseError("pulse_uri_not_its_index");
  const ex = p.external;
  if (!isObj(ex) || Object.keys(ex).length !== 3 || !["sourceId", "statusCode", "value"].every((k) => Object.hasOwn(ex, k))) throw new PulseError("pulse_external_members");
  if (!(nbStr(ex.sourceId) && P_HEX64.test(ex.sourceId) && nbStr(ex.value) && P_HEX64.test(ex.value) && nbInt(ex.statusCode) && ex.statusCode >= 0 && ex.statusCode < 2 ** 32)) throw new PulseError("pulse_external_malformed");
  const lv = p.listValues; if (!Array.isArray(lv) || lv.length !== 5) throw new PulseError("pulse_list_values_not_five");
  const seen = [];
  for (const v of lv) {
    if (!isObj(v) || Object.keys(v).length !== 3 || !["uri", "type", "value"].every((k) => Object.hasOwn(v, k))) throw new PulseError("pulse_list_value_members");
    if (!(nbStr(v.type) && nbStr(v.value) && nbStr(v.uri) && P_HEX64.test(v.value))) throw new PulseError("pulse_list_value_malformed");
    seen.push(v.type); }
  if (seen.slice().sort(byCodePoint).join("\u0000") !== LIST_TYPES.slice().sort(byCodePoint).join("\u0000")) throw new PulseError("pulse_list_value_types");
  for (const k of ["cipherSuite", "period", "statusCode"]) if (p[k] >= 2 ** 32) throw new PulseError("pulse_member_out_of_range:" + k);
  for (const k of ["chainIndex", "pulseIndex"]) if (p[k] >= 2 ** 64) throw new PulseError("pulse_member_out_of_range:" + k);
}
function nbDer(b, i) {   // (tag, start, end) of the DER element at i; strict definite lengths, as the reference's _der
  if (i + 2 > b.length) throw new PulseError("certificate_der_truncated");
  const tag = b[i]; let ln = b[i + 1]; i += 2;
  if (ln & 0x80) { const n = ln & 0x7f;
    if (n === 0 || n > 4 || i + n > b.length || b[i] === 0) throw new PulseError("certificate_der_length");
    ln = 0; for (let k = 0; k < n; k++) ln = ln * 256 + b[i + k];
    if (ln < 0x80) throw new PulseError("certificate_der_length");
    i += n; }
  if (i + ln > b.length) throw new PulseError("certificate_der_truncated");
  return [tag, i, i + ln];
}
function nbChildren(b, s, e) { const out = []; while (s < e) { const c = nbDer(b, s); out.push(c); s = c[2]; } if (s !== e) throw new PulseError("certificate_der_length"); return out; }
function nbTime(bytes, t) {
  let s = Buffer.from(bytes).toString("latin1");
  if (t === 0x17) { if (!/^[0-9]{12}Z$/.test(s)) throw new PulseError("certificate_time"); s = (parseInt(s.slice(0, 2), 10) >= 50 ? "19" : "20") + s; }
  else if (t === 0x18) { if (!/^[0-9]{14}Z$/.test(s)) throw new PulseError("certificate_time"); }
  else throw new PulseError("certificate_time");
  const [Y, M, D, h, m, sec] = [s.slice(0, 4), s.slice(4, 6), s.slice(6, 8), s.slice(8, 10), s.slice(10, 12), s.slice(12, 14)].map((x) => parseInt(x, 10));
  const ms = nbCalendar([Y, M, D, h, m, sec]); if (ms === null) throw new PulseError("certificate_time");   // strptime refuses an impossible date
  return ms;
}
function nbReadCertificate(pem) {
  if (!nbStr(pem)) throw new PulseError("certificate_not_a_string");
  const m = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?$/.exec(pem);
  if (!m) throw new PulseError("certificate_not_one_pem_block");
  const b64 = m[1].replace(/[\r\n]/g, "");
  if (b64.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new PulseError("certificate_base64");   // base64.b64decode(validate=True)
  const der = Buffer.from(b64, "base64");
  const [t, s, e] = nbDer(der, 0); if (t !== 0x30 || e !== der.length) throw new PulseError("certificate_der_outer");
  const cert = nbChildren(der, s, e); if (cert.length !== 3 || cert[0][0] !== 0x30) throw new PulseError("certificate_der_outer");
  const tbs = nbChildren(der, cert[0][1], cert[0][2]); const k = tbs.length && tbs[0][0] === 0xa0 ? 1 : 0;
  if (tbs.length < k + 6) throw new PulseError("certificate_tbs");
  const validity = nbChildren(der, tbs[k + 3][1], tbs[k + 3][2]); if (validity.length !== 2) throw new PulseError("certificate_validity");
  const nb = nbTime(der.subarray(validity[0][1], validity[0][2]), validity[0][0]), na = nbTime(der.subarray(validity[1][1], validity[1][2]), validity[1][0]);
  const spki = nbChildren(der, tbs[k + 5][1], tbs[k + 5][2]); if (spki.length !== 2 || spki[1][0] !== 0x03) throw new PulseError("certificate_spki");
  const alg = nbChildren(der, spki[0][1], spki[0][2]);
  if (!der.subarray(alg[0][1], alg[0][2]).equals(Buffer.from("2a864886f70d010101", "hex"))) throw new PulseError("certificate_key_not_rsa");
  const bits = der.subarray(spki[1][1], spki[1][2]); if (!bits.length || bits[0] !== 0) throw new PulseError("certificate_spki");
  const [t2, s2, e2] = nbDer(bits, 1); if (t2 !== 0x30 || e2 !== bits.length) throw new PulseError("certificate_spki");
  const ne = nbChildren(bits, s2, e2); if (ne.length !== 2 || ne[0][0] !== 0x02 || ne[1][0] !== 0x02) throw new PulseError("certificate_spki");
  const big = (x) => BigInt("0x" + (Buffer.from(x).toString("hex") || "0"));
  return { der, n: big(bits.subarray(ne[0][1], ne[0][2])), e: big(bits.subarray(ne[1][1], ne[1][2])), nb, na };
}
const nbLp = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
const nbU = (v, n) => { const out = Buffer.alloc(n); let x = BigInt(v); for (let i = n - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; } return out; };
function nbSignedMessage(p) {
  const lv = Object.fromEntries(p.listValues.map((v) => [v.type, Buffer.from(v.value, "hex")])); const ex = p.external;
  const parts = [nbLp(Buffer.from(p.uri, "utf8")), nbLp(Buffer.from(p.version, "utf8")), nbU(p.cipherSuite, 4), nbU(p.period, 4), nbLp(Buffer.from(p.certificateId, "hex")),
    nbU(p.chainIndex, 8), nbU(p.pulseIndex, 8), nbLp(Buffer.from(p.timeStamp, "utf8")), nbLp(Buffer.from(p.localRandomValue, "hex")),
    nbLp(Buffer.from(ex.sourceId, "hex")), nbU(ex.statusCode, 4), nbLp(Buffer.from(ex.value, "hex"))];
  for (const t of LIST_TYPES) parts.push(nbLp(lv[t]));
  parts.push(nbLp(Buffer.from(p.precommitmentValue, "hex")), nbU(p.statusCode, 4));
  return Buffer.concat(parts);
}
function nbModPow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; e >>= 1n; b = (b * b) % m; } return r; }
const NB_SHA512_DIGESTINFO = Buffer.from("3051300d060960864801650304020305000440", "hex");
function nbRsaOk(n, e, msg, sig) {
  const k = Math.ceil(n.toString(2).length / 8); if (sig.length !== k) return false;
  const s = BigInt("0x" + (sig.toString("hex") || "0")); if (s >= n) return false;
  const em = nbU(nbModPow(s, e, n), k); const t = Buffer.concat([NB_SHA512_DIGESTINFO, createHash("sha512").update(msg).digest()]);
  if (k < t.length + 11) return false;
  return em.equals(Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(k - t.length - 3, 0xff), Buffer.from([0]), t]));
}
function nbPulseTime(p) { return nbCalendar(P_TS.exec(p.timeStamp).slice(1).map(Number)); }
function nbVerifyPulse(p, pem, pinned) {
  checkPulseGrammar(p); const c = nbReadCertificate(pem); const t = nbPulseTime(p);
  const res = { ok: false, reason: null, output: p.outputValue, time: t, period_s: Math.floor(p.period / 1000), chain: p.chainIndex, pulse: p.pulseIndex, certificate_id: p.certificateId };
  if (createHash("sha512").update(c.der).digest("hex") !== p.certificateId) res.reason = "certificate_not_the_certificate_id";
  else if (!Object.hasOwn(pinned, p.certificateId) || pinned[p.certificateId] !== p.chainIndex) res.reason = "certificate_not_pinned_for_chain";
  else if (!(c.nb <= t && t <= c.na)) res.reason = "pulse_time_outside_certificate_validity";
  else { const msg = nbSignedMessage(p), sig = Buffer.from(p.signatureValue, "hex");
    if (!nbRsaOk(c.n, c.e, msg, sig)) res.reason = "pulse_signature_invalid";
    else if (createHash("sha512").update(Buffer.concat([msg, sig])).digest("hex").toUpperCase() !== p.outputValue) res.reason = "pulse_output_value_not_recomputed";
    else res.ok = true; }
  return res;
}
function nbVerifyPair(p, prev, pem, pinned) {
  checkPulseGrammar(p); checkPulseGrammar(prev);
  const fail = (why) => Object.assign(nbVerifyPulse(p, pem, pinned), { ok: false, reason: why });
  if (p.statusCode !== 0 || prev.statusCode !== 0) return fail("status_not_supported");
  if (p.chainIndex !== prev.chainIndex || p.pulseIndex !== prev.pulseIndex + 1) return fail("pulse_mismatch");
  if (p.period !== prev.period || p.certificateId !== prev.certificateId) return fail("chain_inconsistent");
  const a = nbVerifyPulse(prev, pem, pinned), res = nbVerifyPulse(p, pem, pinned);
  if (!a.ok) Object.assign(res, { ok: false, reason: "previous_" + a.reason });
  else if (!res.ok) { /* its own reason */ }
  else if (p.listValues.find((v) => v.type === "previous").value !== prev.outputValue) Object.assign(res, { ok: false, reason: "previous_mismatch" });
  else if (nbPulseTime(p) - nbPulseTime(prev) !== p.period) Object.assign(res, { ok: false, reason: "period_mismatch" });
  else if (createHash("sha512").update(Buffer.from(p.localRandomValue, "hex")).digest("hex").toUpperCase() !== prev.precommitmentValue) Object.assign(res, { ok: false, reason: "commitment_mismatch" });
  return res;
}
function parseNotBefore(nb) {   // SPEC §12.2, in the reference's order; UnknownMember / Refused name the member
  checkClosed(nb, "not_before", NB_KEYS); checkClosed(nb.payment, "not_before.payment", NB_PAYMENT_KEYS);
  checkClosed(nb.payment.beacon, "not_before.payment.beacon", NB_BEACON_KEYS); checkClosed(nb.mandate, "not_before.mandate", NB_MANDATE_KEYS);
  checkClosed(nb.pulses, "not_before.pulses", NB_PULSES_KEYS);
  const pay = nb.payment; const m = NB_AMOUNT.exec(pay.amount);
  if (!m) throw new Refused("not_before.payment.amount: not a decimal string (SPEC §12.2)");
  if (/^0+$/.test(m[1]) && /^0*$/.test(m[2] ?? "")) throw new Refused("not_before.payment.amount: not greater than zero (SPEC §12.2)");
  if (!/^[A-Z]{3}$/.test(pay.currency)) throw new Refused("not_before.payment.currency: not three capital letters A-Z (SPEC §12.2)");
  if (!NB_RECORD_SALT.test(pay.record_salt)) throw new Refused("not_before.payment.record_salt: not 32 to 128 lowercase hexadecimal characters, an even number (SPEC §12.2)");
  const pid = pay.payment_id; if (!NB_PAYMENT_ID.test(pid) || pid !== pid.replace(/^ +| +$/g, "")) throw new Refused("not_before.payment.payment_id: not 1 to 35 characters of the allowed set (SPEC §12.2)");
  for (const k of NB_COMMITMENT_MEMBERS) if (Object.hasOwn(pay, k) && !NB_HEX64L.test(pay[k])) throw new Refused("not_before.payment." + k + ": not 64 lowercase hexadecimal characters (SPEC §12.2)");
  for (const k of ["pulse", "previous_pulse"]) {
    try { checkPulseGrammar(nb.pulses[k]); }
    catch (e) { if (!(e instanceof PulseError)) throw e;
      if (e.message.startsWith("pulse_unknown_member")) throw new UnknownMember("not_before.pulses." + k + ": unknown key (" + e.message + ") (SPEC §12.2)");
      throw new Refused("not_before.pulses." + k + ": " + e.message + " (SPEC §12.2)"); } }
  try { nbReadCertificate(nb.pulses.certificate); } catch (e) { if (!(e instanceof PulseError)) throw e; throw new Refused("not_before.pulses.certificate: " + e.message + " (SPEC §12.2)"); }
}
const NB_PATH_TOKEN = /([^.\[\]]+)|\[(0|[1-9][0-9]*)\]/y;
const NB_MISSING = Symbol("missing");
function nbResolvePath(node, path) {   // the value at a §4 path, as the reference's _resolve_path
  let pos = 0, first = true;
  const at = (p) => { NB_PATH_TOKEN.lastIndex = p; return NB_PATH_TOKEN.exec(path); };
  while (pos < path.length) {
    let m;
    if (path[pos] === ".") { if (first) return NB_MISSING; pos += 1; m = at(pos); if (!m || m[1] === undefined) return NB_MISSING; }
    else { m = at(pos); if (!m || (m[1] !== undefined && !first)) return NB_MISSING; }
    if (m[1] !== undefined) { if (!isObj(node) || !Object.hasOwn(node, m[1])) return NB_MISSING; node = node[m[1]]; }
    else { const i = Number(m[2]); if (!Array.isArray(node) || i >= node.length) return NB_MISSING; node = node[i]; }
    pos = m.index + m[0].length; first = false;
  }
  return first ? NB_MISSING : node;
}
function nbAmountEqualsMinor(amount, currency, minor) {
  if (!Object.hasOwn(NB_MINOR_UNITS, currency)) return null;
  const e = NB_MINOR_UNITS[currency]; const [whole, frac = ""] = amount.split(".");
  if (frac.replace(/0+$/, "").length > e) return false;
  if (!(typeof minor === "number" && Number.isInteger(minor))) return false;
  return BigInt(whole) * 10n ** BigInt(e) + BigInt((frac + "0".repeat(e)).slice(0, e) || "0") === BigInt(minor);
}
const nbFmt = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
function checkNotBefore(nb, ev, artResults, provenTime, pinned = NB_PINNED) {   // SPEC §12.3: NB1-NB3, the window
  const pul = nb.pulses, pay = nb.payment, r = nbVerifyPair(pul.pulse, pul.previous_pulse, pul.certificate, pinned), T = r.time;
  const out = { profile: NB_PROFILE, source: "nist-beacon-2.0", chain: r.chain, pulse: r.pulse, time: nbFmt(T), certificate_id: r.certificate_id, checks: {},
    covers: Object.keys(pay).filter((k) => k !== "beacon").sort(byCodePoint).concat(["mandate:" + nb.mandate.artifact]),
    window: { not_before: null, not_before_operator_promise: null, not_after: null }, mandate_payee: null };
  const c = out.checks, b = pay.beacon;
  if (!r.ok) c.NB1 = "failed:" + r.reason;
  else if (b.chain_index !== r.chain || b.pulse_index !== r.pulse || b.output_value.toLowerCase() !== r.output.toLowerCase()) c.NB1 = "failed:beacon_value_mismatch";
  else c.NB1 = "verified";
  const idx = ev.artifacts.findIndex((a) => a.name === nb.mandate.artifact);
  if (idx < 0) c.NB2 = "failed:mandate_not_in_pack";
  else { const ar = artResults[idx];
    if (!(ar.signature_ok === true && ar.claims_match === true)) c.NB2 = "not_evaluated:mandate_not_verified";
    else { const claims = ev.artifacts[idx].resolved_claims; const v = nbResolvePath(claims, nb.mandate.amount_claim);
      if (v === NB_MISSING) c.NB2 = "failed:amount_claim_not_found";
      else if (!(isObj(v) && Object.keys(v).length === 2 && Object.hasOwn(v, "amount") && Object.hasOwn(v, "currency")) || v.currency !== pay.currency) c.NB2 = "failed:amount_not_the_mandate_amount";
      else { const eq = nbAmountEqualsMinor(pay.amount, pay.currency, v.amount); c.NB2 = eq === null ? "not_evaluated:currency_minor_unit_unknown" : eq ? "verified" : "failed:amount_not_the_mandate_amount"; }
      const dp = isObj(claims) ? claims.delegate_payload : undefined;
      for (const holder of [claims, Array.isArray(dp) && dp.length ? dp[0] : null]) if (isObj(holder) && isObj(holder.payee)) { out.mandate_payee = holder.payee; break; } } }
  if (c.NB1 !== "verified") c.NB3 = "not_evaluated:beacon_not_verified";
  else { const cm = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(ev.created_utc);
    const created = cm ? nbCalendar(cm.slice(1).map(Number)) : null;   // §1 checks the pattern only: 2026-02-30 is no time to compare
    if (created === null) c.NB3 = "failed:created_utc_not_a_time";
    else if (created < T) c.NB3 = "failed:created_before_beacon";
    else if (provenTime === null) c.NB3 = "not_evaluated:no_verified_time_anchor";
    else { const [whole, frac = ""] = provenTime.replace(/Z$/, "").split(".");
      const gt = nbCalendar([0, 4, 6, 8, 10, 12].map((i) => +whole.slice(i, i + (i ? 2 : 4))));
      if (gt === null) c.NB3 = "not_evaluated:verified_time_not_a_time";   // 1.8.1 (SPEC §12.3): second 60/61, no calendar time
      else if (gt + Number((frac + "000").slice(0, 3)) < T) c.NB3 = "failed:window_inverted";   // exact: T in whole ms
      else { c.NB3 = "verified"; out.window.not_after = provenTime; } } }
  if (c.NB1 === "verified" && c.NB2 === "verified") { out.window.not_before = nbFmt(T); out.window.not_before_operator_promise = nbFmt(T - r.period_s * 1000); }
  const vals = Object.values(c);
  out.state = vals.some((x) => x.startsWith("failed")) ? "failed" : vals.every((x) => x === "verified") ? "verified" : "not_evaluated";
  return out;
}
// SPEC §12.2: the commitment encoding and a disclosure {member, salt, value}, as the reference's payment_commitment /
// check_disclosure (same outcome names as cryptovalid-opencore SPEC §18). Lengths are counted in code points, as Python's len().
const NB_LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
// SPEC §12.2 "Unicode version": the code points assigned in Unicode 13.0.0, as in ap2_evidence._U13 (NFC of later ones
// differs between runtimes: this verifier's Unicode is the one of its ICU)
const NB_U13 = "0-377,37A-37F,384-38A,38C,38E-3A1,3A3-52F,531-556,559-58A,58D-58F,591-5C7,5D0-5EA,5EF-5F4,600-61C,61E-70D,70F-74A,74D-7B1,7C0-7FA,7FD-82D,830-83E,840-85B,85E,860-86A,8A0-8B4,8B6-8C7,8D3-983,985-98C,98F-990,993-9A8,9AA-9B0,9B2,9B6-9B9,9BC-9C4,9C7-9C8,9CB-9CE,9D7,9DC-9DD,9DF-9E3,9E6-9FE,A01-A03,A05-A0A,A0F-A10,A13-A28,A2A-A30,A32-A33,A35-A36,A38-A39,A3C,A3E-A42,A47-A48,A4B-A4D,A51,A59-A5C,A5E,A66-A76,A81-A83,A85-A8D,A8F-A91,A93-AA8,AAA-AB0,AB2-AB3,AB5-AB9,ABC-AC5,AC7-AC9,ACB-ACD,AD0,AE0-AE3,AE6-AF1,AF9-AFF,B01-B03,B05-B0C,B0F-B10,B13-B28,B2A-B30,B32-B33,B35-B39,B3C-B44,B47-B48,B4B-B4D,B55-B57,B5C-B5D,B5F-B63,B66-B77,B82-B83,B85-B8A,B8E-B90,B92-B95,B99-B9A,B9C,B9E-B9F,BA3-BA4,BA8-BAA,BAE-BB9,BBE-BC2,BC6-BC8,BCA-BCD,BD0,BD7,BE6-BFA,C00-C0C,C0E-C10,C12-C28,C2A-C39,C3D-C44,C46-C48,C4A-C4D,C55-C56,C58-C5A,C60-C63,C66-C6F,C77-C8C,C8E-C90,C92-CA8,CAA-CB3,CB5-CB9,CBC-CC4,CC6-CC8,CCA-CCD,CD5-CD6,CDE,CE0-CE3,CE6-CEF,CF1-CF2,D00-D0C,D0E-D10,D12-D44,D46-D48,D4A-D4F,D54-D63,D66-D7F,D81-D83,D85-D96,D9A-DB1,DB3-DBB,DBD,DC0-DC6,DCA,DCF-DD4,DD6,DD8-DDF,DE6-DEF,DF2-DF4,E01-E3A,E3F-E5B,E81-E82,E84,E86-E8A,E8C-EA3,EA5,EA7-EBD,EC0-EC4,EC6,EC8-ECD,ED0-ED9,EDC-EDF,F00-F47,F49-F6C,F71-F97,F99-FBC,FBE-FCC,FCE-FDA,1000-10C5,10C7,10CD,10D0-1248,124A-124D,1250-1256,1258,125A-125D,1260-1288,128A-128D,1290-12B0,12B2-12B5,12B8-12BE,12C0,12C2-12C5,12C8-12D6,12D8-1310,1312-1315,1318-135A,135D-137C,1380-1399,13A0-13F5,13F8-13FD,1400-169C,16A0-16F8,1700-170C,170E-1714,1720-1736,1740-1753,1760-176C,176E-1770,1772-1773,1780-17DD,17E0-17E9,17F0-17F9,1800-180E,1810-1819,1820-1878,1880-18AA,18B0-18F5,1900-191E,1920-192B,1930-193B,1940,1944-196D,1970-1974,1980-19AB,19B0-19C9,19D0-19DA,19DE-1A1B,1A1E-1A5E,1A60-1A7C,1A7F-1A89,1A90-1A99,1AA0-1AAD,1AB0-1AC0,1B00-1B4B,1B50-1B7C,1B80-1BF3,1BFC-1C37,1C3B-1C49,1C4D-1C88,1C90-1CBA,1CBD-1CC7,1CD0-1CFA,1D00-1DF9,1DFB-1F15,1F18-1F1D,1F20-1F45,1F48-1F4D,1F50-1F57,1F59,1F5B,1F5D,1F5F-1F7D,1F80-1FB4,1FB6-1FC4,1FC6-1FD3,1FD6-1FDB,1FDD-1FEF,1FF2-1FF4,1FF6-1FFE,2000-2064,2066-2071,2074-208E,2090-209C,20A0-20BF,20D0-20F0,2100-218B,2190-2426,2440-244A,2460-2B73,2B76-2B95,2B97-2C2E,2C30-2C5E,2C60-2CF3,2CF9-2D25,2D27,2D2D,2D30-2D67,2D6F-2D70,2D7F-2D96,2DA0-2DA6,2DA8-2DAE,2DB0-2DB6,2DB8-2DBE,2DC0-2DC6,2DC8-2DCE,2DD0-2DD6,2DD8-2DDE,2DE0-2E52,2E80-2E99,2E9B-2EF3,2F00-2FD5,2FF0-2FFB,3000-303F,3041-3096,3099-30FF,3105-312F,3131-318E,3190-31E3,31F0-321E,3220-9FFC,A000-A48C,A490-A4C6,A4D0-A62B,A640-A6F7,A700-A7BF,A7C2-A7CA,A7F5-A82C,A830-A839,A840-A877,A880-A8C5,A8CE-A8D9,A8E0-A953,A95F-A97C,A980-A9CD,A9CF-A9D9,A9DE-A9FE,AA00-AA36,AA40-AA4D,AA50-AA59,AA5C-AAC2,AADB-AAF6,AB01-AB06,AB09-AB0E,AB11-AB16,AB20-AB26,AB28-AB2E,AB30-AB6B,AB70-ABED,ABF0-ABF9,AC00-D7A3,D7B0-D7C6,D7CB-D7FB,E000-FA6D,FA70-FAD9,FB00-FB06,FB13-FB17,FB1D-FB36,FB38-FB3C,FB3E,FB40-FB41,FB43-FB44,FB46-FBC1,FBD3-FD3F,FD50-FD8F,FD92-FDC7,FDF0-FDFD,FE00-FE19,FE20-FE52,FE54-FE66,FE68-FE6B,FE70-FE74,FE76-FEFC,FEFF,FF01-FFBE,FFC2-FFC7,FFCA-FFCF,FFD2-FFD7,FFDA-FFDC,FFE0-FFE6,FFE8-FFEE,FFF9-FFFD,10000-1000B,1000D-10026,10028-1003A,1003C-1003D,1003F-1004D,10050-1005D,10080-100FA,10100-10102,10107-10133,10137-1018E,10190-1019C,101A0,101D0-101FD,10280-1029C,102A0-102D0,102E0-102FB,10300-10323,1032D-1034A,10350-1037A,10380-1039D,1039F-103C3,103C8-103D5,10400-1049D,104A0-104A9,104B0-104D3,104D8-104FB,10500-10527,10530-10563,1056F,10600-10736,10740-10755,10760-10767,10800-10805,10808,1080A-10835,10837-10838,1083C,1083F-10855,10857-1089E,108A7-108AF,108E0-108F2,108F4-108F5,108FB-1091B,1091F-10939,1093F,10980-109B7,109BC-109CF,109D2-10A03,10A05-10A06,10A0C-10A13,10A15-10A17,10A19-10A35,10A38-10A3A,10A3F-10A48,10A50-10A58,10A60-10A9F,10AC0-10AE6,10AEB-10AF6,10B00-10B35,10B39-10B55,10B58-10B72,10B78-10B91,10B99-10B9C,10BA9-10BAF,10C00-10C48,10C80-10CB2,10CC0-10CF2,10CFA-10D27,10D30-10D39,10E60-10E7E,10E80-10EA9,10EAB-10EAD,10EB0-10EB1,10F00-10F27,10F30-10F59,10FB0-10FCB,10FE0-10FF6,11000-1104D,11052-1106F,1107F-110C1,110CD,110D0-110E8,110F0-110F9,11100-11134,11136-11147,11150-11176,11180-111DF,111E1-111F4,11200-11211,11213-1123E,11280-11286,11288,1128A-1128D,1128F-1129D,1129F-112A9,112B0-112EA,112F0-112F9,11300-11303,11305-1130C,1130F-11310,11313-11328,1132A-11330,11332-11333,11335-11339,1133B-11344,11347-11348,1134B-1134D,11350,11357,1135D-11363,11366-1136C,11370-11374,11400-1145B,1145D-11461,11480-114C7,114D0-114D9,11580-115B5,115B8-115DD,11600-11644,11650-11659,11660-1166C,11680-116B8,116C0-116C9,11700-1171A,1171D-1172B,11730-1173F,11800-1183B,118A0-118F2,118FF-11906,11909,1190C-11913,11915-11916,11918-11935,11937-11938,1193B-11946,11950-11959,119A0-119A7,119AA-119D7,119DA-119E4,11A00-11A47,11A50-11AA2,11AC0-11AF8,11C00-11C08,11C0A-11C36,11C38-11C45,11C50-11C6C,11C70-11C8F,11C92-11CA7,11CA9-11CB6,11D00-11D06,11D08-11D09,11D0B-11D36,11D3A,11D3C-11D3D,11D3F-11D47,11D50-11D59,11D60-11D65,11D67-11D68,11D6A-11D8E,11D90-11D91,11D93-11D98,11DA0-11DA9,11EE0-11EF8,11FB0,11FC0-11FF1,11FFF-12399,12400-1246E,12470-12474,12480-12543,13000-1342E,13430-13438,14400-14646,16800-16A38,16A40-16A5E,16A60-16A69,16A6E-16A6F,16AD0-16AED,16AF0-16AF5,16B00-16B45,16B50-16B59,16B5B-16B61,16B63-16B77,16B7D-16B8F,16E40-16E9A,16F00-16F4A,16F4F-16F87,16F8F-16F9F,16FE0-16FE4,16FF0-16FF1,17000-187F7,18800-18CD5,18D00-18D08,1B000-1B11E,1B150-1B152,1B164-1B167,1B170-1B2FB,1BC00-1BC6A,1BC70-1BC7C,1BC80-1BC88,1BC90-1BC99,1BC9C-1BCA3,1D000-1D0F5,1D100-1D126,1D129-1D1E8,1D200-1D245,1D2E0-1D2F3,1D300-1D356,1D360-1D378,1D400-1D454,1D456-1D49C,1D49E-1D49F,1D4A2,1D4A5-1D4A6,1D4A9-1D4AC,1D4AE-1D4B9,1D4BB,1D4BD-1D4C3,1D4C5-1D505,1D507-1D50A,1D50D-1D514,1D516-1D51C,1D51E-1D539,1D53B-1D53E,1D540-1D544,1D546,1D54A-1D550,1D552-1D6A5,1D6A8-1D7CB,1D7CE-1DA8B,1DA9B-1DA9F,1DAA1-1DAAF,1E000-1E006,1E008-1E018,1E01B-1E021,1E023-1E024,1E026-1E02A,1E100-1E12C,1E130-1E13D,1E140-1E149,1E14E-1E14F,1E2C0-1E2F9,1E2FF,1E800-1E8C4,1E8C7-1E8D6,1E900-1E94B,1E950-1E959,1E95E-1E95F,1EC71-1ECB4,1ED01-1ED3D,1EE00-1EE03,1EE05-1EE1F,1EE21-1EE22,1EE24,1EE27,1EE29-1EE32,1EE34-1EE37,1EE39,1EE3B,1EE42,1EE47,1EE49,1EE4B,1EE4D-1EE4F,1EE51-1EE52,1EE54,1EE57,1EE59,1EE5B,1EE5D,1EE5F,1EE61-1EE62,1EE64,1EE67-1EE6A,1EE6C-1EE72,1EE74-1EE77,1EE79-1EE7C,1EE7E,1EE80-1EE89,1EE8B-1EE9B,1EEA1-1EEA3,1EEA5-1EEA9,1EEAB-1EEBB,1EEF0-1EEF1,1F000-1F02B,1F030-1F093,1F0A0-1F0AE,1F0B1-1F0BF,1F0C1-1F0CF,1F0D1-1F0F5,1F100-1F1AD,1F1E6-1F202,1F210-1F23B,1F240-1F248,1F250-1F251,1F260-1F265,1F300-1F6D7,1F6E0-1F6EC,1F6F0-1F6FC,1F700-1F773,1F780-1F7D8,1F7E0-1F7EB,1F800-1F80B,1F810-1F847,1F850-1F859,1F860-1F887,1F890-1F8AD,1F8B0-1F8B1,1F900-1F978,1F97A-1F9CB,1F9CD-1FA53,1FA60-1FA6D,1FA70-1FA74,1FA78-1FA7A,1FA80-1FA86,1FA90-1FAA8,1FAB0-1FAB6,1FAC0-1FAC2,1FAD0-1FAD6,1FB00-1FB92,1FB94-1FBCA,1FBF0-1FBF9,20000-2A6DD,2A700-2B734,2B740-2B81D,2B820-2CEA1,2CEB0-2EBE0,2F800-2FA1D,30000-3134A,E0001,E0020-E007F,E0100-E01EF,F0000-FFFFD,100000-10FFFD".split(",").map((x) => { const [a, b] = x.split("-"); return [parseInt(a, 16), parseInt(b || a, 16)]; });
function nbPortable(v) { for (const ch of v) { const cp = ch.codePointAt(0); if (cp >= 0xd800 && cp <= 0xdfff) return false;
  let lo = 0, hi = NB_U13.length - 1, ok = false; while (lo <= hi) { const m = (lo + hi) >> 1; if (cp < NB_U13[m][0]) hi = m - 1; else if (cp > NB_U13[m][1]) lo = m + 1; else { ok = true; break; } }
  if (!ok) return false; } return true; }   // a lone surrogate is not text (no UTF-8)
const NB_DISCLOSURE_KEYS = { member: [[(v) => NB_COMMITMENT_MEMBERS.includes(v), "one of the five commitment members"], 1],
  salt: [[(v) => nbStr(v) && /^[0-9a-f]{32}$/.test(v), "32 lowercase hexadecimal characters"], 1],
  value: [[(v) => nbStr(v) && [...v].length > 0 && [...v].length <= 1024 && !NB_LONE.test(v) && nbPortable(v), "a non-empty string of at most 1024 characters assigned in Unicode 13.0.0"], 1] };
const nbAscii = (v) => /^[\x00-\x7f]*$/.test(v);
export function ibanProblem(s) {
  if (!nbStr(s) || !/^[A-Z0-9]*$/.test(s)) return "iban_charset";
  if (s.length < 15 || s.length > 34) return "iban_length";
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(s)) return "iban_charset";
  const cd = parseInt(s.slice(2, 4), 10); if (cd < 2 || cd > 98) return "iban_check_digits";
  const digits = [...(s.slice(4) + s.slice(0, 4))].map((c) => parseInt(c, 36).toString()).join("");
  return BigInt(digits) % 97n === 1n ? null : "iban_checksum";
}
export function paymentCommitment(member, salt, value) {
  if (!NB_COMMITMENT_MEMBERS.includes(member)) throw new Error(JSON.stringify(member) + " is not a commitment member");
  if (!nbStr(value) || [...value].length < 1 || [...value].length > 1024 || NB_LONE.test(value)) throw new Error("a value is a non-empty string of at most 1024 characters");
  if (!Buffer.isBuffer(salt) || salt.length !== 16) throw new Error("the salt is exactly 16 bytes");
  let v;
  if (NB_IBAN_MEMBERS.includes(member)) { if (!nbAscii(value)) throw new Error("iban_charset"); v = value.replace(/ /g, "").toUpperCase(); const why = ibanProblem(v); if (why) throw new Error(why); }
  else { if (!nbPortable(value)) throw new Error("value_not_portable: a code point not assigned in Unicode 13.0.0"); v = value.normalize("NFC"); }
  return createHash("sha256").update(Buffer.concat([Buffer.from("cryptovalid-payment/1/", "ascii"), Buffer.from(member, "ascii"), Buffer.from([0]), salt, Buffer.from(v, "utf8")])).digest("hex");
}
export function checkDisclosure(path, disclosure) {   // read-only; Refused for a disclosure or a pack outside the grammar
  checkClosed(disclosure, "disclosure", NB_DISCLOSURE_KEYS);
  const raw = readEvidenceBytes(path); if (raw === null) throw new Refused("evidence file exceeds bound");
  const text = UTF8.decode(raw); if (text.startsWith("\ufeff")) throw new Refused("BOM");
  const ev = parseStrict(text); if (!isObj(ev) || !isObj(ev.not_before)) throw new Refused("the pack carries no not_before block (SPEC §12)");
  parseNotBefore(ev.not_before);
  const m = disclosure.member, out = { member: m, note: "the pack must also verify (verify) for the commitment to be the sealed one" };
  if (NB_IBAN_MEMBERS.includes(m)) { const v = disclosure.value; const why = !nbAscii(v) ? "iban_charset" : ibanProblem(v.replace(/ /g, "").toUpperCase());
    if (why) return { ...out, outcome: "disclosure_iban_invalid", reason: why }; }
  if (!Object.hasOwn(ev.not_before.payment, m)) return { ...out, outcome: "member_absent" };
  const got = paymentCommitment(m, Buffer.from(disclosure.salt, "hex"), disclosure.value);
  return { ...out, outcome: got === ev.not_before.payment[m] ? "matches" : "disclosure_mismatch" };
}
export { checkNotBefore, parseNotBefore };
const PIN_ALGS = ["ed25519", "ecdsa-p256", "ml-dsa-65"];   // the names a pinned producer key can be given under (SPEC §5)
export function verifyEvidence(path, opts = {}) {
  // 1.11.0 (SPEC §5): trusted is {sig_alg: key or list of keys} over the algorithms the format defines, as in the reference;
  // anything else is the caller's error (a Set or a number under "ml-dsa-65" switched the 1.11.0 rule off in silence)
  if ((opts.trusted ?? null) !== null && !(typeof opts.trusted === "object" && !Array.isArray(opts.trusted) && [null, Object.prototype].includes(Object.getPrototypeOf(opts.trusted))
      && Object.keys(opts.trusted).every((k) => PIN_ALGS.includes(k) && ((typeof opts.trusted[k] === "string" && opts.trusted[k] !== "") || (Array.isArray(opts.trusted[k]) && opts.trusted[k].every((x) => typeof x === "string" && x !== ""))))))
    throw new TypeError("trusted must be {sig_alg: key or list of keys}, each key a non-empty string, sig_alg one of " + PIN_ALGS.join(", "));   // "" under "ml-dsa-65" switched the rule off (measured on aedfee6)
  // 1.7.2 (SPEC §3.1): acceptIntegralFloats, a boolean, default false; when true the receipt says so
  if (opts.acceptIntegralFloats !== undefined && typeof opts.acceptIntegralFloats !== "boolean") throw new TypeError("acceptIntegralFloats must be a boolean");
  // 1.9.0 (SPEC §6.9): requireBindings, a list of [in, commits_to] pairs of non-empty names, as the reference's require_bindings
  if (opts.requireBindings !== undefined && opts.requireBindings !== null && !(Array.isArray(opts.requireBindings) && opts.requireBindings.every((pr) => Array.isArray(pr) && pr.length === 2 && pr.every((x) => typeof x === "string" && x !== "")))) throw new TypeError("requireBindings must be a list of [in, commits_to] pairs of non-empty names");
  const saved = INTEGRAL_READ; INTEGRAL_READ = opts.acceptIntegralFloats ? [] : null;
  try { const r = verifyEvidenceInner(path, opts); if (opts.acceptIntegralFloats) r.accept_integral_floats = true; return r; }
  finally { INTEGRAL_READ = saved; }
}
function verifyEvidenceInner(path, opts) {
  if (opts.minAnchors !== undefined && opts.minAnchors !== null && !(Number.isSafeInteger(opts.minAnchors) && opts.minAnchors >= 1))   // SPEC §3.3: an integer >= 1 —
    throw new TypeError("minAnchors must be an integer >= 1 (got " + String(opts.minAnchors) + ")");   // NaN once disabled the policy in silence
  if (opts.trustAnchor !== undefined && opts.trustAnchor !== null) throw new TypeError("trustAnchor: this verifier cannot validate x5c chains (SPEC §6 step 7) — a flag that does nothing is refused (1.6.0)");
  // 1.10.0 — SPEC §6.10, as the reference's ValueError: a tsaCert that holds no certificate is the caller's error, not a statement about the pack
  const tsaCertBytes = opts.tsaCert !== undefined && opts.tsaCert !== null ? pemCertificateFile(opts.tsaCert) : null;
  if (opts.tsaCert !== undefined && opts.tsaCert !== null && tsaCertBytes === null) throw new TypeError("tsaCert: no PEM certificate in " + JSON.stringify(opts.tsaCert) + " (SPEC §6.10)");
  // 1.6.0 — SPEC §6.9: every refusal names its class; a refused pack receives no states and no policy
  const refuse = (m, cls = "malformed") => ({ digest_ok: false, artifacts: [], producer_signatures: { present: false, ok: null, pq_protected: false, trusted: null }, pq_protected: false, bindings_ok: false, rfc3161: { claimed: false, verified: null }, anchors: [], anchors_verified: 0, provenance_classes: [], self_asserted_only: true, chain_verified: null, policy_ok: false, valid: false, honest_scope: null, refused: m, admission: "refused", refusal_class: cls, states_vocabulary: STATES_VOCABULARY, states: null, policy: null, mldsa_backend: HAVE_MLDSA });  // r8: the honesty flag is fail-closed inside a refusal too
  let ev; try { const raw = readEvidenceBytes(path); if (raw === null) return refuse("evidence file exceeds bound"); const text = UTF8.decode(raw); if (text.startsWith("﻿")) return refuse("BOM"); ev = parseStrict(text); } catch (e) { return refuse(String(e.message ?? e)); }
  if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return refuse("not a JSON object");
  // shape of the top-level fields (SPEC §1), the same refusals as the reference
  if (ev.evidence_format !== EVIDENCE_FORMAT) return refuse("evidence_format must be " + JSON.stringify(EVIDENCE_FORMAT), "format_unsupported");   // r5: a "…/2.0" pack was verified under the 1.0 rules
  for (const f of ["subject", "created_utc", "honest_scope"]) if (typeof ev[f] !== "string") return refuse(f + " must be a string (SPEC §1)");
  if (createHash("sha256").update(Buffer.from(ev.honest_scope, "utf8")).digest("hex") !== HONEST_SCOPE_SHA256) return refuse(createHash("sha256").update(Buffer.from(ev.honest_scope, "utf8")).digest("hex") === HONEST_SCOPE_SHA256_1_0 ? "honest_scope is the scope of ap2-evidence-pack 1.0.0-1.0.2 (sha256 431877e4...): a pack built by 1.0.x, sealed under rules 1.1.0 changed (SPEC §1, CHANGELOG 1.1.0); this verifier reads packs built by 1.1.0 and later, and does not verify it" : "honest_scope does not match the canonical scope of this evidence_format (SPEC §1)", "format_unsupported");   // r8: the receipt used to reprint any scope the file carried
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(ev.created_utc)) return refuse("created_utc must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ (SPEC §1)");   // r6
  if (!Array.isArray(ev.artifacts) || ev.artifacts.some((a) => a === null || typeof a !== "object" || Array.isArray(a))) return refuse("artifacts must be a list of objects");
  const names = ev.artifacts.map((a) => a.name); if (names.some((n) => typeof n !== "string" || !n)) return refuse("artifacts[].name must be a non-empty string");   // r3
  if (new Set(names).size !== names.length) return refuse("artifacts[].name must be unique within the pack");
  if ("bindings" in ev && !Array.isArray(ev.bindings)) return refuse("bindings must be a list");
  if ("rfc3161_timestamp" in ev && (ev.rfc3161_timestamp === null || typeof ev.rfc3161_timestamp !== "object" || Array.isArray(ev.rfc3161_timestamp))) return refuse("rfc3161_timestamp must be an object");
  if ("rfc3161_timestamp" in ev && typeof ev.rfc3161_timestamp.anchored !== "boolean") return refuse("rfc3161_timestamp.anchored must be a boolean");   // r2: [] / {} were "anchored, unverified" here and "not anchored" in the reference
  if ("producer_signatures" in ev && (ev.producer_signatures === null || typeof ev.producer_signatures !== "object" || Array.isArray(ev.producer_signatures))) return refuse("producer_signatures must be an object");
  try {   // 1.4.0 — SPEC §9.1: the top-level object, the anchor block, the producer block and every binding entry are CLOSED
    checkClosed(ev, "top level", TOP_KEYS);
    if ("rfc3161_timestamp" in ev) checkClosed(ev.rfc3161_timestamp, "rfc3161_timestamp", RFC3161_KEYS);
    if ("rfc3161_timestamp" in ev && ev.rfc3161_timestamp.anchored === false && Object.hasOwn(ev.rfc3161_timestamp, "tsr_b64"))   // 1.10.0 — SPEC §1/§9.1
      throw new Refused("rfc3161_timestamp: tsr_b64 is not allowed under anchored false (SPEC §9.1)");
    if ("producer_signatures" in ev) checkClosed(ev.producer_signatures, "producer_signatures", PRODUCER_KEYS);
    (ev.bindings ?? []).forEach((b, i) => checkClosed(b, "bindings[" + i + "]", BINDING_KEYS));
    (ev.anchors ?? []).forEach((an, i) => {   // 1.5.0 — SPEC §3.3/§9.1: closed entries, the mechanism first (the reference's order)
      if (!isObj(an)) throw new Refused("anchors[" + i + "] must be an object (SPEC §9.1)");
      if (!Object.hasOwn(an, "mechanism")) throw new Refused("anchors[" + i + "]: missing mechanism (SPEC §9.1)");
      if (typeof an.mechanism !== "string") throw new Refused("anchors[" + i + "]: mechanism must be a string (SPEC §9.1)");
      if (!ANCHOR_MECHANISMS.includes(an.mechanism)) throw new FormatUnsupported("anchors[" + i + "]: mechanism " + JSON.stringify(an.mechanism) + " is not defined by this revision (SPEC §3.3)");
      checkClosed(an, "anchors[" + i + "]", ANCHOR_RFC3161_KEYS); });
    // 1.6.0 — SPEC §9.1/§6.9 (not additive): an unknown key in an artifact entry (and its key, kb_jwt, verified_at_build) or in a
    // producer-signature entry is a refusal of class unknown_member; a wrong type or a missing key stays an artifact error / FAIL entry
    ev.artifacts.forEach((a, i) => { checkUnknown(a, "artifacts[" + i + "]", ARTIFACT_KEYS);
      for (const [sub, keys] of [["key", KEY_KEYS], ["kb_jwt", KB_COPY_KEYS], ["verified_at_build", VAB_KEYS]]) checkUnknown(a[sub], "artifacts[" + i + "]." + sub, keys); });
    const sigs = ev.producer_signatures?.signatures; if (Array.isArray(sigs)) sigs.forEach((e, i) => checkUnknown(e, "producer_signatures.signatures[" + i + "]", ENTRY_KEYS));
    if ("not_before" in ev) parseNotBefore(ev.not_before);   // 1.8.0 — SPEC §12.2: closed at every level, before any check runs
  } catch (e) { return refuse(String(e.message ?? e), e instanceof UnknownMember ? "unknown_member" : e instanceof FormatUnsupported ? "format_unsupported" : "malformed"); }
  const e2 = Object.create(null); for (const k of Object.keys(ev)) if (!DIGEST_EXCLUDED.includes(k)) e2[k] = ev[k];
  const recomputed = sha256(Buffer.from(canon(e2), "utf-8")).toString("hex"); const digestOk = recomputed === ev.evidence_digest_sha256;
  const artResults = []; let allOk = true; const forBindings = []; const chainSeen = new Map();   // chainSeen: 1.9.0 (SPEC §2.1)
  for (const a of ev.artifacts) {
    const read0 = INTEGRAL_READ === null ? null : INTEGRAL_READ.length;   // 1.7.2: the literals this artifact had read as integers
    try { checkClosed(a, "artifact", ARTIFACT_KEYS); checkClosed(a.key, "artifact key", KEY_KEYS); checkClosed(a.kb_jwt, "artifact kb_jwt", KB_COPY_KEYS); checkClosed(a.verified_at_build, "artifact verified_at_build", VAB_KEYS);   // 1.4.0 — SPEC §9.1
      const compact = a.sd_jwt_compact; if (typeof compact !== "string" || compact !== compact.trim() || !/^[\x00-\x7f]*$/.test(compact)) throw new Refused("sd_jwt_compact must be the exact ASCII compact serialization");
      if (!a.key || typeof a.key !== "object" || Array.isArray(a.key)) throw new Refused("artifact key.jwk must be an object");
      const pc = a.key.provenance_class;   // r2: a list was sorted here; r5: out-of-enum passed as a strong class; r7: absent/null used to CLEAR self_asserted_only
      if (typeof pc !== "string" || !PROVENANCE_CLASSES.has(pc)) throw new Refused("artifact key.provenance_class must be one of " + [...PROVENANCE_CLASSES].sort().join(", "));
      if ((pc === "chain_cnf") !== Object.hasOwn(a.key, "chain_from")) throw new Refused("artifact key.chain_from goes with provenance_class chain_cnf, and only with it (SPEC §2.1)");
      let prevHop = null;
      if (pc === "chain_cnf") { prevHop = chainSeen.get(a.key.chain_from) ?? null;   // 1.9.0 — SPEC §2.1: reconciled against the previous hop the pack carries
        if (prevHop === null) throw new Refused("artifact key.chain_from " + JSON.stringify(a.key.chain_from) + " names no artifact before this one that verified (SPEC §2.1)");
        if (!sameKey(chainCnfJwk(prevHop.resolved), a.key.jwk)) throw new Refused("provenance_class chain_cnf but the key is not the cnf.jwk of the artifact named by chain_from (SPEC §2.1)"); }
      const parsed = parseSdJwt(compact);
      // r6: this shape check spent round 5 INSIDE an unterminated line comment — a signed payload that is a JSON array
      // verified in this verifier and failed in the reference. It runs before checkProvenance, which reads the header.
      if (parsed.payload === null || typeof parsed.payload !== "object" || Array.isArray(parsed.payload) || parsed.header === null || typeof parsed.header !== "object" || Array.isArray(parsed.header)) throw new Refused("JWT header and payload must be objects");
      if (canon(a.header) !== canon(parsed.header)) throw new Refused("artifact header copy differs from the decoded protected header (SPEC §2)");   // 1.4.0: the informative copy must say what the signed header says
      if (parsed.header.alg !== "ES256") throw new Refused("issuer_alg_not_es256: the signed header does not name alg ES256 (RFC 7515 §5.2 step 8, SPEC §6 step 2)");   // 1.10.0: up to 1.9.0 ES256 was checked whatever the header said
      if (Boolean(parsed.kbJwt) !== a.kb_jwt.present) throw new Refused("artifact kb_jwt.present contradicts the compact serialization (SPEC §9.1)");
      // SPEC §9.2 — the standards' rule for the unknown: ignored, and REPORTED (crit: RFC 7515 §4.1.11, a rejection)
      const ignored = { header: joseHeaderIgnored(parsed.header, "JWT header"), header_jwk: unknownMembers(parsed.header.jwk, JWK_REGISTERED), key_jwk: unknownMembers(a.key.jwk, JWK_REGISTERED) };
      const prov = checkProvenance(pc, parsed, a.key); const selfAsserted = prov.selfAsserted;   // r5: reconciled with the signed header; r7: decides self_asserted_only
      reconcileUnusedHeaderKeys(parsed.header, a.key.jwk, pc); ignored.key_material = keyMaterialNotUsed(parsed.header, pc);   // 1.7.3 (SPEC §2 (d), §6 step 2, §9.2)
      const sigOk = es256Verify(parsed.signingInput, parsed.signature, a.key.jwk); const census = {}; const resolved = resolveDisclosures(parsed.payload, parsed.disclosures, census);
      const claimsOk = canon(resolved) === canon(a.resolved_claims ?? null);
      const chainHop = (prevHop !== null && sigOk && claimsOk) ? { ...checkChainHop(parsed, resolved, prevHop.compact), from: a.key.chain_from } : null;   // 1.9.0 — SPEC §2.1
      const kb = verifyKbJwt(parsed, resolved, prevHop !== null);
      for (const k of ["verified", "signature_ok", "sd_hash_ok", "claims_recorded_not_validated"]) if (Object.hasOwn(a.kb_jwt, k) && (!Object.hasOwn(kb, k) || canon(a.kb_jwt[k]) !== canon(kb[k]))) throw new Refused("artifact kb_jwt." + k + " contradicts the KB-JWT (SPEC §9.1)");   // SPEC §9.1 (NEMESIS 2026-10-11)
      Object.assign(ignored, kb._ignored ?? {}); delete kb._ignored; const ign = {}; for (const k of Object.keys(ignored).sort(cmp)) if (ignored[k].length) ign[k] = ignored[k];   // SPEC §9.2: only the non-empty slots
      artResults.push({ name: a.name, signature_ok: sigOk, claims_match: claimsOk, kb_jwt: kb, provenance_class: a.key?.provenance_class, self_asserted: selfAsserted, ignored: ign, ...(prov.ident ? { x5c_leaf: prov.ident } : {}), ...(chainHop ? { chain_hop: chainHop } : {}), ...(census.reserved ? { reserved_names_in_clear: { "...": census.reserved } } : {}) });
      allOk = allOk && sigOk && claimsOk && kb.verified !== false; forBindings.push({ name: a.name, compact: parsed.compact, resolved });
      if (sigOk && claimsOk && typeof a.name === "string") chainSeen.set(a.name, { compact: parsed.compact, resolved });
    } catch (e) { artResults.push({ name: a?.name, error: String(e.message ?? e) }); allOk = false; }
    if (read0 !== null) artResults[artResults.length - 1].integral_literals_read = INTEGRAL_READ.slice(read0);
  }
  // 1.9.0 — SPEC §4 (the reference's bindings_recorded_match): null = not the recomputed set; else the recomputed bindings the pack does
  // not record — [] when equal, and for a pack recording no binding over the issuer JWT (built before 1.9.0) ALL of those, never some
  const recordedMatch = (found, recorded) => { const rec = asSet(recorded); if (asSet(found) === rec) return []; return asSet(found.filter((b) => !Object.hasOwn(b, "over"))) === rec ? found.filter((b) => Object.hasOwn(b, "over")).sort((x, y) => cmp(canon(x), canon(y))) : null; };   // sorted by canonical form, as the reference
  const asSet = (l) => l.map((b) => canon(b)).sort().join("\n");   // r4: binding SET (SPEC §4) — Object.keys enumerates index keys first, so the scan order is not the reference's
  // 1.6.0 — SPEC §6.9: the binding set as an element of sealed_content, recomputed whenever every artifact's signature and
  // claims verified (also when a KB-JWT failed, where bindings_ok is false by §6 step 3 without a recomputation)
  let bindingSetMatch = null;
  if (artResults.length && forBindings.length === artResults.length && artResults.every((r) => r.signature_ok === true && r.claims_match === true)) {
    try { bindingSetMatch = recordedMatch(findBindings(forBindings), ev.bindings ?? []) !== null; } catch { bindingSetMatch = false; } }
  const notRecorded = allOk ? recordedMatch(findBindings(forBindings), ev.bindings ?? []) : null;   // `bindings` absent = [] in both; null is refused above
  const bindingsOk = notRecorded !== null;
  const ts = ev.rfc3161_timestamp ?? {}; let rfc = { claimed: Boolean(ts.anchored), verified: null };   // `anchored` is a boolean by the shape check above
  if (ts.anchored && typeof ts.tsr_b64 === "string") rfc = { claimed: true, ...verifyRfc3161(ts.tsr_b64, recomputed), tsa_verified: null };   // BINDING only (status granted + messageImprint == digest, SPEC §3.2); TSA signature/chain: this verifier cannot (no openssl) -> tsa_verified null = incomplete under --tsa-cert
  else if (ts.anchored) rfc = { claimed: true, verified: false, note: "anchored claimed but tsr_b64 absent" };
  // 1.5.0 — SPEC §3.3: each `anchors` entry checked like the block; COUNTING = binding verified (+ TSA-verified when --tsa-cert:
  // never here, no openssl -> 0 under --tsa-cert, declared); DISTINCT = a different signed TSTInfo (a copied token is one anchor,
  // however it is wrapped); any failing claim fails the pack
  const anchorResults = (ev.anchors ?? []).map((an) => ({ mechanism: an.mechanism, claimed: true, ...verifyRfc3161(an.tsr_b64, recomputed), tsa_verified: null }));
  const counted = new Set();
  const pairs = (rfc.claimed ? [[rfc, ts.tsr_b64]] : []).concat(anchorResults.map((r, i) => [r, ev.anchors[i].tsr_b64]));
  for (const [r, tok] of pairs) if (r.verified === true && (!opts.tsaCert || r.tsa_verified === true)) counted.add(tstInfoHex(tok));
  const anchorsVerified = counted.size;
  const rfcBlock = rfc;   // 1.6.0: the block's own result, before the §3.3 aggregate
  if (anchorResults.length) rfc = { ...rfc, claimed: true, verified: (rfc.verified === false || anchorResults.some((x) => x.verified !== true)) ? false : true };
  const classes = [...new Set(artResults.map((r) => r.provenance_class).filter(Boolean))].sort(cmp);   // r5: by code point, as the reference (default sort is by UTF-16 code unit)
  let producer; const prod = ev.producer_signatures;
  if (prod) { const pv = verifyProducerBlock(prod, Buffer.from(recomputed, "ascii"), opts.trusted ?? null); producer = { present: true, scheme: prod.scheme, scheme_ok: pv.scheme_ok, ok: pv.ok, incomplete: pv.incomplete, pq_protected: pv.pq_protected, trusted: pv.trusted, signatures: pv.results };
    if (!pv.ok) allOk = false; if ((opts.trusted ?? null) !== null && pv.trusted !== true) allOk = false; }
  else producer = { present: false, ok: null, pq_protected: false, trusted: null };   // 1.6.0: `ok` always present
  // 1.6.0 — SPEC §6.9: each requirement not met is NAMED; policy_ok keeps its 1.5.x meaning, policy.met also covers the pinned set
  const unmet = [];
  if (opts.requireProducer && !(producer.present && producer.ok)) unmet.push("require_producer");
  if (opts.requirePq && !(producer.pq_protected && producer.trusted === true)) unmet.push("require_pq");
  if (opts.requireAnchor && anchorsVerified < 1) unmet.push("require_anchor");
  if (opts.minAnchors !== undefined && opts.minAnchors !== null && anchorsVerified < opts.minAnchors) unmet.push("min_anchors");   // under --tsa-cert nothing counts here (no openssl): not a pass (declared)
  let bindingMissing = null;   // 1.9.0 — SPEC §6.9: each IN->TO must be in the RECOMPUTED set, which counts only when bindingsOk
  if (opts.requireBindings && opts.requireBindings.length) { const held = new Set(bindingsOk ? findBindings(forBindings).map((b) => JSON.stringify([b.in, b.commits_to])) : []);
    const miss = opts.requireBindings.filter((pr) => !held.has(JSON.stringify(pr))); if (miss.length) { unmet.push("require_binding"); bindingMissing = miss; } }
  // 1.10.0 — SPEC §6 step 6, §6.9: a pinned producer set implies require_producer: a block ABSENT does not meet it
  // (up to 1.9.0 only a present block was held to the set: measured 2026-11-20, the block removed → valid: true, unmet [])
  const pinAbsent = (opts.trusted ?? null) !== null && !producer.present;
  // 1.11.0 — SPEC §5, §6 step 6: a pinned set that holds an ml-dsa-65 key requires a valid ml-dsa-65 signature under a pinned
  // key (up to 1.10.0 the ml-dsa-65 entry removed and `scheme` relabelled classical-only was valid with both keys pinned)
  const pinPqMissing = (opts.trusted ?? null) !== null && Object.hasOwn(opts.trusted, "ml-dsa-65") && opts.trusted["ml-dsa-65"].length > 0
    && producer.trusted === true && !producer.pq_protected;
  const policyOk = unmet.length === 0 && !pinAbsent && !pinPqMissing;
  if ((opts.trusted ?? null) !== null && (pinAbsent || pinPqMissing || producer.trusted !== true)) unmet.push("trusted_producer_keys");
  const states = deriveStates({ digestOk, artResults, bindingSetMatch, tsBlock: ts, rfcBlock, anchorResults, tsaRequested: Boolean(opts.tsaCert),
    producer, pinned: (opts.trusted ?? null) !== null, trustAnchorGiven: false });
  if (opts.trustSetComplete && states.producer_signature.reasons.includes("key_unresolved")) unmet.push("trust_set_complete");
  // 1.8.0 — SPEC §12.3: NB1-NB3. The upper bound is a TSA-VERIFIED genTime; this verifier cannot check a TSA signature
  // (no openssl), so it never has one: NB3 is at best not_evaluated:no_verified_time_anchor here (declared, as tsa_verified)
  const nbRep = "not_before" in ev ? checkNotBefore(ev.not_before, ev, artResults, null) : null;
  return { digest_ok: digestOk, artifacts: artResults, producer_signatures: producer, pq_protected: producer.pq_protected ?? false, bindings_ok: bindingsOk, ...(notRecorded !== null && notRecorded.length ? { bindings_not_recorded: notRecorded } : {}), rfc3161: rfc, anchors: anchorResults, anchors_verified: anchorsVerified, provenance_classes: classes,
    // r10: ANY — one reconciled artifact must not clear the flag for the others; r7: a label alone never clears it,
    // a missing class is a refusal; r8: this verifier cannot validate x5c chains, so chain_verified is always null (declared)
    self_asserted_only: artResults.length === 0 || artResults.some((r) => r.self_asserted !== false), chain_verified: null, policy_ok: policyOk,
    valid: Boolean(artResults.length && digestOk && allOk && bindingsOk && rfc.verified !== false && policyOk && (nbRep === null || nbRep.state !== "failed")), honest_scope: ev.honest_scope ?? null,
    admission: "admitted", refusal_class: null, states_vocabulary: STATES_VOCABULARY, states, policy: { met: unmet.length === 0, unmet: POLICY_UNMET.filter((u) => unmet.includes(u)), ...(bindingMissing ? { require_binding_missing: bindingMissing } : {}) },
    mldsa_backend: HAVE_MLDSA, ...(nbRep === null ? {} : { not_before: nbRep }),
    ...(tsaCertBytes ? { tsa_cert_sha256: createHash("sha256").update(tsaCertBytes).digest("hex") } : {}) };   // 1.10.0 — SPEC §6.9: of the bytes the check read
}
function main(argv) {
  // 1.5.2 review: a usage line that stderr does not take (/dev/full) is 74, as in the Python CLI (console.error dropped the error and exited 2)
  const usage = () => { try { writeAllSync(2, "usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--min-anchors N] [--tsa-cert PEM] [--trust-set-complete] [--accept-integral-floats] [--require-binding IN->TO]...\n"); } catch { process.exit(EX_IOERR); } process.exit(2); };
  const a = argv.slice(2); const opts = { trusted: null }; let path = null;
  for (let i = 0; i < a.length; i++) { let tok = a[i], eqv = null; const eq = tok.indexOf("="); if (eq > 0 && tok.startsWith("--")) { eqv = tok.slice(eq + 1); tok = tok.slice(0, eq); }
    const nx = () => { const v = eqv !== null ? eqv : a[++i]; if (v === undefined || v === "" || v.startsWith("-")) usage(); return v; };
    if (tok === "--trusted-producer-key") { const v = nx(); const k = v.indexOf("="); if (k <= 0 || k === v.length - 1 || !PIN_ALGS.includes(v.slice(0, k))) usage(); opts.trusted = opts.trusted ?? Object.create(null); (opts.trusted[v.slice(0, k)] ??= []).push(v.slice(k + 1)); }   // r2: a null-prototype table, so "constructor=…" is a pin like any other
    else if (tok === "--tsa-cert") opts.tsaCert = nx();
    else if (tok === "--min-anchors") { const v = nx(); if (!/^[1-9][0-9]{0,5}$/.test(v)) usage(); opts.minAnchors = Number(v); }   // 1.5.0 — the reference's grammar
    else if (tok === "--require-binding") { const v = nx(); const k = v.indexOf("->"); if (k <= 0 || k + 2 >= v.length || v.indexOf("->", k + 2) !== -1) usage(); (opts.requireBindings ??= []).push([v.slice(0, k), v.slice(k + 2)]); }   // 1.9.0 — SPEC §6.9
    else if (tok === "--trust-anchor") { nx(); usage(); }   // 1.6.0: this verifier cannot validate x5c chains; a flag accepted that does nothing is a usage error (r8 accepted it and reported chain_verified null)
    else if (tok === "--require-producer" && eqv === null) opts.requireProducer = true; else if (tok === "--require-pq" && eqv === null) opts.requirePq = true; else if (tok === "--require-anchor" && eqv === null) opts.requireAnchor = true;
    else if (tok === "--trust-set-complete" && eqv === null) opts.trustSetComplete = true;   // 1.6.0 — SPEC §6.9
    else if (tok === "--accept-integral-floats" && eqv === null) opts.acceptIntegralFloats = true;   // 1.7.2 — SPEC §3.1
    else if (tok.startsWith("-") || path !== null) usage(); else path = tok; }
  if (!path) usage();
  try { if (statSync(path).isFile()) accessSync(path, FS.R_OK); } catch { usage(); }   // 1.10.0 — SPEC §3.1: a path that names nothing, or a regular file that cannot be read, is a usage error; a FIFO, a device, a directory stay a refusal, whatever their permissions
  // 1.6.0 review: a --tsa-cert that cannot be read is a usage error, as in the reference (it named no certificate)
  if (opts.tsaCert !== undefined) { let ok = false; try { ok = statSync(opts.tsaCert).isFile(); accessSync(opts.tsaCert, FS.R_OK); } catch { ok = false; } if (!ok) usage(); }
  // SPEC §6.10: a readable file that holds no PEM certificate names none — a usage error, the same test as the reference's _holds_pem_certificate
  if (opts.tsaCert !== undefined && pemCertificateFile(opts.tsaCert) === null) usage();
  const r = verifyEvidence(path, opts); emit(JSON.stringify(r, null, 1), r.valid ? 0 : 1);
}
// exitCode, not process.exit(): exit() right after console.log to a PIPE drops every byte of the receipt past the pipe buffer (64 KiB on Linux)
// (measured 12/10/2026: an evidence file with a 100 000-character unknown key gave 65 536 bytes of broken JSON on `| cat`).
// 1.5.2: the exit code is chosen in the write's callback. console.log + exitCode left the verdict's 0/1 when the write
// FAILED (/dev/full: ENOSPC; a reader that closed the pipe: EPIPE), with nothing on stderr (measured 12/10/2026 on 1.5.1);
// now that is 74 (EX_IOERR) and one line on stderr. Not visible from here: with stdout closed (`>&-`) Node reopens fd 1 on
// /dev/null, so the write succeeds.
const EX_IOERR = 74;
// 1.5.2: every byte to fd, synchronously. A short count continues from the next byte; EAGAIN (a non-blocking pipe that
// is full: its reader is slow, not gone) waits 1 to 50 ms and retries, as a blocking write would; a write that takes 0
// bytes is an error. Before, writeSync(2) threw EAGAIN there and the usage line was lost with exit 74 (measured
// 13/10/2026: stderr on a non-blocking pipe already full at start, read 1 s later).
const pauseMs = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
// 1.11.0: a pipe on Windows is not always a FIFO to fstat (CI run 45561704870: the 0 was still read as a short write);
// what stays an error is 0 on a regular file, where nothing else can explain it
function isRegularFile(fd) { try { return fstatSync(fd).isFile(); } catch { return true; } }
function writeAllSync(fd, data) {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data; let off = 0, pause = 1;
  while (off < buf.length) {
    let n;
    try { n = writeSync(fd, buf, off, buf.length - off); } catch (e) { if (e.code !== "EAGAIN") throw e; pauseMs(pause); pause = Math.min(pause * 2, 50); continue; }
    // 1.11.0: on Windows a full non-blocking pipe takes 0 bytes with no error (CI run 45547984550): that is EAGAIN there;
    // 0 on anything else (a regular file) is still the short write it is
    if (n === 0 && process.platform === "win32" && !isRegularFile(fd)) { pauseMs(pause); pause = Math.min(pause * 2, 50); continue; }
    if (!(n > 0)) throw new Error(`short write: ${buf.length - off} bytes not written`);
    off += n; pause = 1;
  }
}
function emit(text, code) {
  // 1.5.2 review: on a REGULAR FILE that stops growing, process.stdout.write lost the rest of the receipt with no error
  // (measured: `ulimit -f 4`, 4 096 of 84 432 bytes, exit 0, Node 22 and 24). There the receipt is written in a loop to
  // its last byte, and a failed write (EFBIG, ENOSPC) is 74.
  let st = null; try { st = fstatSync(1); } catch { st = null; }
  if (st && st.isFile()) {
    try {
      writeAllSync(1, text + "\n");
      process.exitCode = code;
    } catch (err) {
      process.exitCode = EX_IOERR;
      try { writeAllSync(2, `receipt not written: ${err.code ?? err.message ?? err}\n`); } catch { /* exit 74 anyway */ }
    }
    return;
  }
  let settled = false;
  const settle = (err) => {
    if (settled) return; settled = true;
    if (!err) { process.exitCode = code; return; }
    process.exitCode = EX_IOERR;
    try { process.stderr.write(`receipt not written: ${err.code ?? err.message ?? err}\n`); } catch { /* exit 74 anyway */ }
  };
  process.stderr.on("error", () => {});   // a failing stderr must not turn 74 into an uncaught exception
  process.stdout.on("error", settle);
  try { process.stdout.write(text + "\n", settle); } catch (e) { settle(e); }
}
if (process.argv[1] && /ap2-verify\.mjs$/.test(process.argv[1])) main(process.argv);
