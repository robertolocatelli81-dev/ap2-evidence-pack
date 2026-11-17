# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""NIST Randomness Beacon 2.0 pulse check, standard library only (SPEC_AP2_EVIDENCE §12). agent-payment-chain
nist_beacon.py (its SPEC 34) makes the same checks but reads the hex values in either case, as cryptovalid-opencore
SPEC v0.10 §19 rule 2; here they must be as the service serves them (certificateId lower case, the others upper case).

PROTOTYPE, to be replaced by the beacon pulse verifier of cryptovalid-opencore (SPEC v0.10 §19) once this package can
depend on a published release of it.

What it checks, for one pulse of the format served by https://beacon.nist.gov/beacon/2.0/ (cipherSuite 0 only):
- the pulse object is CLOSED: exactly the fifteen members the service writes, `external` exactly three, `listValues`
  exactly the five types previous, hour, day, month, year, once each; every hex value upper case of its fixed length;
- `uri` is https://beacon.nist.gov/beacon/2.0/chain/<chainIndex>/pulse/<pulseIndex>;
- the certificate (PEM, one block) hashes to `certificateId` (SHA-512 of the DER) and the certificate id is in the
  reader's pinned list, with the pulse time inside the certificate's validity;
- the RSA PKCS#1 v1.5 SHA-512 signature over the signed message, with the certificate's public key;
- outputValue = SHA-512(signed message || signature bytes).
The signed message (4-byte big-endian length prefixes, 8-byte chain and pulse index, raw signature for outputValue) is
the one MEASURED on the production service on 2026-11-16 (FONTI.md, step 3), not the one of the 2019 draft NIST IR 8213,
which gives 8-byte prefixes and reproduces 0 of 8 outputs. Written from that measure; the field order was read from
clcert/beacon-verifier (MIT) scripts/chain_consistency_version2.py.
"""
import base64
import hashlib
import re
from datetime import datetime, timezone

PROFILE = "nist-beacon-2.0"
_HEX64 = re.compile(r"[0-9A-F]{128}\Z")
_HEX64_LOWER = re.compile(r"[0-9a-f]{128}\Z")   # certificateId is served in lower case (measured 2026-11-16, chains 1 and 2)
_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.000Z\Z")
PULSE_KEYS = frozenset(("uri", "version", "cipherSuite", "period", "certificateId", "chainIndex", "pulseIndex",
                        "timeStamp", "localRandomValue", "external", "listValues", "precommitmentValue", "statusCode",
                        "signatureValue", "outputValue"))
EXTERNAL_KEYS = frozenset(("sourceId", "statusCode", "value"))
LIST_KEYS = frozenset(("uri", "type", "value"))
LIST_TYPES = ("previous", "hour", "day", "month", "year")
# The reader's pinned NIST certificates: certificateId -> (chainIndex). Measured 2026-11-16: the certificate served for
# chain 2 (CN=engine.beacon.nist.gov, valid 2026-10-21 .. 2027-03-20). A reader adds an id only after reading it from NIST.
PINNED = {"5b6386e6ac8a993bac8d99d6549deda44af82f2fa4a0e9c0025b6474ab0cbfcab67bfff264fda41aac003b0c9ee7fb77d2938dc0f286fb73cc8fa79864ec0c18": 2}
_SHA512_DIGESTINFO = bytes.fromhex("3051300d060960864801650304020305000440")


class PulseError(ValueError):
    """A pulse or certificate outside the grammar: the reason names the member."""


def _is_int(v):
    return type(v) is int


def _der(b, i):
    """(tag, start of content, end of content) of the DER element at i; strict definite lengths."""
    if i + 2 > len(b):
        raise PulseError("certificate_der_truncated")
    tag, ln = b[i], b[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or i + n > len(b) or b[i] == 0:
            raise PulseError("certificate_der_length")
        ln = int.from_bytes(b[i:i + n], "big")
        if ln < 0x80:
            raise PulseError("certificate_der_length")
        i += n
    if i + ln > len(b):
        raise PulseError("certificate_der_truncated")
    return tag, i, i + ln


def _children(b, s, e):
    out = []
    while s < e:
        t, cs, ce = _der(b, s)
        out.append((t, cs, ce))
        s = ce
    if s != e:
        raise PulseError("certificate_der_length")
    return out


def _gtime(b, t):
    s = b.decode("ascii")
    if t == 0x17:   # UTCTime YYMMDDHHMMSSZ (RFC 5280 4.1.2.5.1)
        if not re.fullmatch(r"[0-9]{12}Z", s):
            raise PulseError("certificate_time")
        y = int(s[:2])
        s = ("19" if y >= 50 else "20") + s
    elif t == 0x18:
        if not re.fullmatch(r"[0-9]{14}Z", s):
            raise PulseError("certificate_time")
    else:
        raise PulseError("certificate_time")
    return datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def read_certificate(pem):
    """DER, RSA modulus and exponent, notBefore, notAfter of a one-block PEM certificate."""
    if not isinstance(pem, str):
        raise PulseError("certificate_not_a_string")
    m = re.fullmatch(r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?", pem)
    if not m:
        raise PulseError("certificate_not_one_pem_block")
    try:
        der = base64.b64decode("".join(m.group(1).split()), validate=True)
    except ValueError:
        raise PulseError("certificate_base64")
    t, s, e = _der(der, 0)
    if t != 0x30 or e != len(der):
        raise PulseError("certificate_der_outer")
    cert = _children(der, s, e)
    if len(cert) != 3 or cert[0][0] != 0x30:
        raise PulseError("certificate_der_outer")
    tbs = _children(der, cert[0][1], cert[0][2])
    k = 1 if tbs and tbs[0][0] == 0xA0 else 0     # [0] version
    if len(tbs) < k + 6:
        raise PulseError("certificate_tbs")
    validity = _children(der, tbs[k + 3][1], tbs[k + 3][2])
    if len(validity) != 2:
        raise PulseError("certificate_validity")
    nb = _gtime(der[validity[0][1]:validity[0][2]], validity[0][0])
    na = _gtime(der[validity[1][1]:validity[1][2]], validity[1][0])
    spki = _children(der, tbs[k + 5][1], tbs[k + 5][2])
    if len(spki) != 2 or spki[1][0] != 0x03:
        raise PulseError("certificate_spki")
    alg = _children(der, spki[0][1], spki[0][2])
    if der[alg[0][1]:alg[0][2]] != bytes.fromhex("2a864886f70d010101"):   # rsaEncryption
        raise PulseError("certificate_key_not_rsa")
    bits = der[spki[1][1]:spki[1][2]]
    if not bits or bits[0] != 0:
        raise PulseError("certificate_spki")
    t2, s2, e2 = _der(bits, 1)
    if t2 != 0x30 or e2 != len(bits):
        raise PulseError("certificate_spki")
    ne = _children(bits, s2, e2)
    if len(ne) != 2 or ne[0][0] != 0x02 or ne[1][0] != 0x02:
        raise PulseError("certificate_spki")
    n = int.from_bytes(bits[ne[0][1]:ne[0][2]], "big")
    ex = int.from_bytes(bits[ne[1][1]:ne[1][2]], "big")
    return der, n, ex, nb, na


def _lp(b):
    return len(b).to_bytes(4, "big") + b


def check_grammar(p):
    """The closed grammar of one pulse; raises PulseError naming the member."""
    if not isinstance(p, dict):
        raise PulseError("pulse_not_object")
    extra = sorted(set(p) - PULSE_KEYS)
    if extra:
        raise PulseError("pulse_unknown_member:" + extra[0])
    missing = sorted(PULSE_KEYS - set(p))
    if missing:
        raise PulseError("pulse_missing_member:" + missing[0])
    for k in ("uri", "version", "timeStamp", "certificateId", "localRandomValue", "precommitmentValue",
              "signatureValue", "outputValue"):
        if not isinstance(p[k], str):
            raise PulseError("pulse_member_not_string:" + k)
    for k in ("cipherSuite", "period", "chainIndex", "pulseIndex", "statusCode"):
        if not _is_int(p[k]) or p[k] < 0:
            raise PulseError("pulse_member_not_integer:" + k)
    if p["version"] != "2.0":   # as cryptovalid-opencore SPEC §19 rule 1 (chain 1 writes "Version 2.0": refused)
        raise PulseError("pulse_version_unsupported")
    if p["cipherSuite"] != 0:
        raise PulseError("pulse_cipher_suite_unsupported")
    if not _HEX64_LOWER.match(p["certificateId"]):
        raise PulseError("pulse_hex_malformed:certificateId")
    for k in ("localRandomValue", "precommitmentValue", "outputValue"):
        if not _HEX64.match(p[k]):
            raise PulseError("pulse_hex_malformed:" + k)
    if not re.fullmatch(r"(?:[0-9A-F]{2})+\Z", p["signatureValue"]):
        raise PulseError("pulse_hex_malformed:signatureValue")
    m = _TS.match(p["timeStamp"])
    if not m:
        raise PulseError("pulse_timestamp_malformed")
    try:                                 # a real calendar time (2026-02-30 matches the pattern; datetime refuses it)
        datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
    except ValueError:
        raise PulseError("pulse_timestamp_malformed")
    if p["uri"] != "https://beacon.nist.gov/beacon/2.0/chain/%d/pulse/%d" % (p["chainIndex"], p["pulseIndex"]):
        raise PulseError("pulse_uri_not_its_index")
    ex = p["external"]
    if not isinstance(ex, dict) or set(ex) != EXTERNAL_KEYS:
        raise PulseError("pulse_external_members")
    if not (isinstance(ex["sourceId"], str) and _HEX64.match(ex["sourceId"]) and isinstance(ex["value"], str)
            and _HEX64.match(ex["value"]) and _is_int(ex["statusCode"]) and 0 <= ex["statusCode"] < 2 ** 32):
        raise PulseError("pulse_external_malformed")
    lv = p["listValues"]
    if not isinstance(lv, list) or len(lv) != 5:
        raise PulseError("pulse_list_values_not_five")
    seen = []
    for v in lv:
        if not isinstance(v, dict) or set(v) != LIST_KEYS:
            raise PulseError("pulse_list_value_members")
        if not (isinstance(v["type"], str) and isinstance(v["value"], str) and isinstance(v["uri"], str)
                and _HEX64.match(v["value"])):
            raise PulseError("pulse_list_value_malformed")
        seen.append(v["type"])
    if sorted(seen) != sorted(LIST_TYPES):
        raise PulseError("pulse_list_value_types")
    for k in ("cipherSuite", "period", "statusCode"):
        if p[k] >= 2 ** 32:
            raise PulseError("pulse_member_out_of_range:" + k)
    for k in ("chainIndex", "pulseIndex"):
        if p[k] >= 2 ** 64:
            raise PulseError("pulse_member_out_of_range:" + k)


def signed_message(p):
    lv = {v["type"]: bytes.fromhex(v["value"]) for v in p["listValues"]}
    ex = p["external"]
    out = _lp(p["uri"].encode("utf-8")) + _lp(p["version"].encode("utf-8"))
    out += p["cipherSuite"].to_bytes(4, "big") + p["period"].to_bytes(4, "big")
    out += _lp(bytes.fromhex(p["certificateId"]))
    out += p["chainIndex"].to_bytes(8, "big") + p["pulseIndex"].to_bytes(8, "big")
    out += _lp(p["timeStamp"].encode("utf-8")) + _lp(bytes.fromhex(p["localRandomValue"]))
    out += _lp(bytes.fromhex(ex["sourceId"])) + ex["statusCode"].to_bytes(4, "big") + _lp(bytes.fromhex(ex["value"]))
    for t in LIST_TYPES:
        out += _lp(lv[t])
    out += _lp(bytes.fromhex(p["precommitmentValue"])) + p["statusCode"].to_bytes(4, "big")
    return out


def rsa_pkcs1v15_sha512_ok(n, e, msg, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA512_DIGESTINFO + hashlib.sha512(msg).digest()
    if k < len(t) + 11:
        return False
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def pulse_time(p):
    m = _TS.match(p["timeStamp"])
    return datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)


def verify_pulse(p, certificate_pem, pinned):
    """Raises PulseError for a pulse or certificate outside the grammar; else returns
    {"ok": bool, "reason": None or "<why>", "output": 64 bytes, "time": datetime, "period_s": int, "chain": int,
     "pulse": int, "certificate_id": hex}. `pinned` maps a lower-case certificateId to the chainIndex it is pinned for."""
    check_grammar(p)
    der, n, e, nb, na = read_certificate(certificate_pem)
    t = pulse_time(p)
    res = {"ok": False, "reason": None, "output": bytes.fromhex(p["outputValue"]), "time": t,
           "period_s": p["period"] // 1000, "chain": p["chainIndex"], "pulse": p["pulseIndex"],
           "certificate_id": p["certificateId"]}
    if hashlib.sha512(der).hexdigest() != p["certificateId"]:
        res["reason"] = "certificate_not_the_certificate_id"
    elif not isinstance(pinned, dict) or pinned.get(p["certificateId"]) != p["chainIndex"]:
        res["reason"] = "certificate_not_pinned_for_chain"
    elif not (nb <= t <= na):
        res["reason"] = "pulse_time_outside_certificate_validity"
    else:
        msg = signed_message(p)
        sig = bytes.fromhex(p["signatureValue"])
        if not rsa_pkcs1v15_sha512_ok(n, e, msg, sig):
            res["reason"] = "pulse_signature_invalid"
        elif hashlib.sha512(msg + sig).hexdigest().upper() != p["outputValue"]:
            res["reason"] = "pulse_output_value_not_recomputed"
        else:
            res["ok"] = True
    return res


def verify_pair(p, prev, certificate_pem, pinned):
    """The named pulse and its predecessor, as cryptovalid-opencore SPEC §19 rules 2-8 (the same checks, written here):
    statusCode 0 in both, one chain and consecutive indexes, equal period and certificateId, each pulse signed and its
    outputValue recomputed (verify_pulse), the named pulse's `previous` = the predecessor's outputValue, its time = the
    predecessor's + period, and SHA-512(localRandomValue) = the predecessor's precommitmentValue. Raises PulseError for
    a pulse outside the grammar; returns verify_pulse's result for the named pulse with `ok`/`reason` of the pair."""
    check_grammar(p)
    check_grammar(prev)
    if p["statusCode"] != 0 or prev["statusCode"] != 0:
        res = verify_pulse(p, certificate_pem, pinned)
        res.update(ok=False, reason="status_not_supported")
        return res
    if p["chainIndex"] != prev["chainIndex"] or p["pulseIndex"] != prev["pulseIndex"] + 1:
        res = verify_pulse(p, certificate_pem, pinned)
        res.update(ok=False, reason="pulse_mismatch")
        return res
    if p["period"] != prev["period"] or p["certificateId"] != prev["certificateId"]:
        res = verify_pulse(p, certificate_pem, pinned)
        res.update(ok=False, reason="chain_inconsistent")
        return res
    a = verify_pulse(prev, certificate_pem, pinned)
    res = verify_pulse(p, certificate_pem, pinned)
    if not a["ok"]:
        res.update(ok=False, reason="previous_" + a["reason"])
    elif not res["ok"]:
        pass
    elif {v["type"]: v["value"] for v in p["listValues"]}["previous"] != prev["outputValue"]:
        res.update(ok=False, reason="previous_mismatch")
    elif (pulse_time(p) - pulse_time(prev)).total_seconds() * 1000 != p["period"]:
        res.update(ok=False, reason="period_mismatch")
    elif hashlib.sha512(bytes.fromhex(p["localRandomValue"])).hexdigest().upper() != prev["precommitmentValue"]:
        res.update(ok=False, reason="commitment_mismatch")
    return res
