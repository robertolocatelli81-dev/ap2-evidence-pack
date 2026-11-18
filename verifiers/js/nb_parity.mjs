#!/usr/bin/env node
// SPEC §12 (1.8.0): the not-before rules of this verifier called directly, for verifiers/differential_oracle.py — the
// window rule with an upper bound this verifier never has on its own (a TSA-verified genTime needs openssl), and the
// disclosures of the commitments. Input: one JSON file {pack, window: [genTime or null], disclosures: [object]}; output: one
// JSON line {window: [receipt], disclosures: [result or "refused"]}.
import { readFileSync } from "node:fs";
import { checkNotBefore, checkDisclosure } from "./ap2-verify.mjs";
const job = JSON.parse(readFileSync(process.argv[2], "utf8"));
const ev = JSON.parse(readFileSync(job.pack, "utf8"));
const arts = ev.artifacts.map(() => ({ signature_ok: true, claims_match: true }));
const out = { window: job.window.map((g) => checkNotBefore(ev.not_before, ev, arts, g)),
  disclosures: job.disclosures.map((d) => { try { return checkDisclosure(job.pack, d); } catch { return "refused"; } }) };
process.stdout.write(JSON.stringify(out) + "\n");
