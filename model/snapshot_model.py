#!/usr/bin/env python3
"""Executable model of ecosystem.snapshot@v0 + warrant.verification-receipt — v3.

v1: harness accepted falsy as PASS (round 4). v2: honest harness, but the
validators judged decoded Python objects, raised host exceptions on hostile
shapes, never tied the receipt to the snapshot universe, and left array
order and value domains open (round 5). v3 closes the round-5 order:

  1. raw-byte strict parsers (`parse_snapshot`, `parse_receipt`) — the ONLY
     public conformance entrypoints; canonicality `jcs(parsed) == raw`;
  2. total nested-shape validation: any parsed JSON value -> bounded
     findings, never a host exception; semantic passes short-circuit after
     structural damage;
  3. normative canonical ordering for EVERY array, strictly increasing;
  4. CAS coverage includes `unclaimed`;
  5. one composed byte-first verdict, `verify_receipt_bytes`;
  6. exact universe<->sources bijection (silent truncation is a finding);
  7. per-occurrence status->issue joins (one issue cannot cover two
     mismatches);
  8. runtime-specific reason domains (verdict enum, hex64 result, ATP
     bounds vs ceiling, ptr resolution against CAS bytes);
  9. grade-aware severity (base vs settlement) and settlement[] forbidden
     at base grade;
 10. deterministic hostile-shape fuzz over the public validators.

Stdlib only. Exit status is the verdict.  Run:  python3 snapshot_model.py
"""

import copy
import hashlib
import json
import os
import random
import re
import subprocess
import sys

SUBROOT_DOMAIN = b"ecosystem-subroot-v0:"
SNAPSHOT_DOMAIN = b"ecosystem-snapshot-v0:"
ZERO64 = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
PTR_RE = re.compile(r"^/because/(0|[1-9][0-9]*)$")
SAFE_INT_MAX = 9007199254740991
FAILURE_CODES = {"OVER_BUDGET", "MISSING_BLOB", "MALFORMED_CHECK",
                 "RUNTIME_UNAVAILABLE", "ORACLE_UNAVAILABLE"}
VERDICTS = {"pass", "fail"}
NORMATIVE_NOT_EXECUTED = {"cmd@v1"}  # warrant SPEC: verify does not re-run these
# warrant SPEC §3: the runtime registry is closed and keyed by BODY version —
# ski@v1 is available in "0.2" bodies and reserved (MUST reject) in "0.1";
# any other value makes the record invalid. execution_policy may narrow
# availability, never extend this registry.
RUNTIME_REGISTRY = {"0.1": {"cmd@v1"}, "0.2": {"cmd@v1", "ski@v1"}}
# warrant SPEC §2: a body declares its format in `warrant`, and the schema is
# closed — unknown members make the record invalid.
BODY_KEYS = {"warrant", "decision", "subject", "under", "because", "evidence",
             "actor", "prior", "ts"}
DECISIONS = {"propose", "accept", "reject", "supersede"}
REASON_REQUIRING_DECISIONS = {"reject", "supersede"}


def body_schema_findings(body) -> list:
    """Every constraint warrant's body schema states, pinned here.

    Checking a key set, a version and a `ts` type and calling that "the body
    schema" was a claim wider than the check: `subject` shape, a non-empty
    `under`, actor shape, hash arrays and `ts >= 0` were all unexamined, so
    SEV accepted committed bytes Warrant's own validator rejects (round 14).
    Mirrors `warrant/schemas/warrant-body.schema.json`.
    """
    bad = []
    if not isinstance(body, dict):
        return ["BODY_NOT_OBJECT"]
    if set(body.keys()) != BODY_KEYS:
        bad.append("BODY_SCHEMA_INVALID")
    if body.get("warrant") not in RUNTIME_REGISTRY:
        bad.append("UNKNOWN_BODY_VERSION")
    if body.get("decision") not in DECISIONS:
        bad.append("BAD_DECISION")
    subject = body.get("subject")
    if not (isinstance(subject, dict) and set(subject.keys()) <= {"hash", "note"}
            and _is_hex64(subject.get("hash"))
            and ("note" not in subject
                 or (isinstance(subject["note"], str)
                     and len(subject["note"]) <= 200))):
        bad.append("BAD_SUBJECT")
    under = body.get("under")
    if not (isinstance(under, list) and under
            and all(_is_hex64(u) for u in under)):
        bad.append("BAD_UNDER")
    actor = body.get("actor")
    if not (isinstance(actor, dict) and set(actor.keys()) == {"id"}
            and isinstance(actor.get("id"), str) and actor["id"]):
        bad.append("BAD_ACTOR")
    for field in ("evidence", "prior"):
        val = body.get(field)
        if not (isinstance(val, list) and all(_is_hex64(v) for v in val)):
            bad.append("BAD_%s" % field.upper())
    because = body.get("because")
    if not isinstance(because, list):
        bad.append("BAD_BECAUSE")
    else:
        if body.get("decision") in REASON_REQUIRING_DECISIONS and not because:
            bad.append("DECISION_WITHOUT_REASON")
        # A reason's shape and its runtime's legality FOR THIS BODY VERSION
        # are part of the body being valid — not a separate check that only
        # runs when the receipt happens to report that reason. Otherwise an
        # unknown runtime, or ski@v1 in a "0.1" body, could not be
        # represented as honest negative evidence at all (round 16).
        allowed = RUNTIME_REGISTRY.get(body.get("warrant"), set())
        for item in because:
            shape = _reason_shape(item)
            if shape is None:
                bad.append("BAD_REASON_SHAPE")
            elif shape == "check" and item.get("runtime") not in allowed:
                bad.append("REASON_RUNTIME_NOT_IN_VERSION")
    ts = body.get("ts")
    if not (_is_safe_int(ts) and ts >= 0):
        bad.append("BAD_TS")
    return sorted(set(bad))
GLOBAL_SUBJECTS = {"settlement", "store", "trust", "genesis"}
SNAPSHOT_KEYS = {"snapshot", "bundle_root", "subroots", "unclaimed", "closed"}
WRAPPER_KEYS = {"subroot", "protocol", "contract", "prefix", "universe", "digest"}
CONTRACT_KEYS = {"name", "version", "spec_digest"}
CORE_KEYS = {"subroot_descriptor_digest", "grade", "trust_config_digest",
             "execution_policy", "ok", "errors", "warnings", "global_issues", "sources"}
RUNTIME_KEYS = {"runtime", "semantics", "semantics_digest", "budget_unit", "ceiling"}
SOURCE_BASE_KEYS = {"kind", "path", "entry_digest", "loaded", "issues"}
SOURCE_RECORD_KEYS = SOURCE_BASE_KEYS | {"claimed_wid", "computed_wid", "id_sound",
                                         "settlement", "signatures", "reasons"}
SIG_KEYS = {"sig_digest", "multiplicity", "actor", "key", "valid", "binding"}
REASON_KEYS = {"ptr", "kind", "runtime", "reason_digest", "outcome"}
OUTCOME_KEYS = {"re_execution", "claimed_verdict", "observed_verdict",
                "observed_result", "atp_spent", "failure_code"}
SETTLE_KEYS = {"jurisdiction", "active", "policies"}
POLICY_KEYS = {"policy", "threshold_satisfied"}


# ---------------------------------------------------------------- JCS subset

def jcs(value, _depth=0):
    if _depth > MAX_FREEZE_DEPTH:
        raise ValueError("over depth budget")
    if isinstance(value, bool) or value is None:
        return b"true" if value is True else (b"false" if value is False else b"null")
    if isinstance(value, int):
        if abs(value) > SAFE_INT_MAX:
            raise ValueError("integer outside I-JSON safe range")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("floats are not I-JSON-safe here")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8", "surrogatepass")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(v, _depth + 1) for v in value) + b"]"
    if isinstance(value, dict):
        items = []
        for k in sorted(value.keys(), key=lambda s: s.encode("utf-16-be", "surrogatepass")):
            if not isinstance(k, str):
                raise ValueError("non-string key")
            items.append(json.dumps(k, ensure_ascii=False).encode("utf-8", "surrogatepass")
                         + b":" + jcs(value[k], _depth + 1))
        return b"{" + b",".join(items) + b"}"
    raise ValueError("unsupported type")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_sort_key(path: str) -> bytes:
    """Normative ordering everywhere: ascending UTF-16 code units."""
    return path.encode("utf-16-be", "surrogatepass")


def _is_hex64(x) -> bool:
    return isinstance(x, str) and bool(HEX64.match(x))


def _is_safe_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and abs(x) <= SAFE_INT_MAX


def _f(findings, code, at):
    findings.append({"code": code, "severity": "ERR", "at": at})


# ---------------------------------------------------------- raw-byte parsing

class _DupKey(ValueError):
    pass


def _no_dup_pairs(pairs):
    seen = set()
    for k, _v in pairs:
        if k in seen:
            raise _DupKey(k)
        seen.add(k)
    return dict(pairs)


def _scan_surrogates(value) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in value)
    if isinstance(value, list):
        return any(_scan_surrogates(v) for v in value)
    if isinstance(value, dict):
        return any(_scan_surrogates(k) or _scan_surrogates(v) for k, v in value.items())
    return False


def parse_strict(raw) -> tuple:
    """(parsed value | None, findings). The byte boundary the object layer
    cannot see: duplicate members, trailing data, non-canonical bytes,
    invalid UTF-8, NaN/Infinity, floats, lone surrogates, BOM."""
    f = []
    if not isinstance(raw, (bytes, bytearray)):
        _f(f, "NOT_BYTES", "/")
        return None, f
    raw = bytes(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        _f(f, "BOM_PRESENT", "/")
        return None, f
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _f(f, "NOT_UTF8", "/")
        return None, f

    def _bad_const(_s):
        raise ValueError("constant")

    def _bad_float(_s):
        raise ValueError("float")

    decoder = json.JSONDecoder(object_pairs_hook=_no_dup_pairs,
                               parse_constant=_bad_const, parse_float=_bad_float)
    try:
        obj, end = decoder.raw_decode(text)
    except _DupKey:
        _f(f, "DUPLICATE_MEMBER", "/")
        return None, f
    except RecursionError:
        # The byte layer needs the depth bound the freeze layer already has:
        # `[`*500 blew the stack out of the "total" composed verdict on
        # hostile evidence bytes (Kimi round 7). Nesting deeper than the
        # format admits is a refusal, not a crash.
        #
        # Unisolatable on this interpreter and labelled rather than counted:
        # CPython's C scanner does not raise here, so the later jcs depth
        # budget catches the same inputs first. Kept because a pure-Python
        # json fallback or another build DOES raise at this exact point —
        # the coincidence is a property of one interpreter, not of the
        # format.
        _f(f, "OVER_DEPTH", "/")
        return None, f
    except ValueError as exc:
        _f(f, "NOT_I_JSON" if str(exc) in ("constant", "float") else "NOT_JSON", "/")
        return None, f
    if text[end:].strip("\r\n\t "):
        _f(f, "TRAILING_DATA", "/")
        return None, f
    try:
        if _scan_surrogates(obj):
            _f(f, "LONE_SURROGATE", "/")
            return None, f
    except RecursionError:
        _f(f, "OVER_DEPTH", "/")
        return None, f
    try:
        if jcs(obj) != raw:
            _f(f, "NOT_CANONICAL", "/")
    except RecursionError:
        _f(f, "OVER_DEPTH", "/")
        return None, f
    except ValueError as exc:
        _f(f, "OVER_DEPTH" if "depth" in str(exc) else "NOT_I_JSON", "/")
        return None, f
    return obj, f


def parse_snapshot(raw, cas=None) -> tuple:
    obj, f = parse_strict(raw)
    if obj is not None and not f:
        f = validate_snapshot(obj, cas)
    return obj, f


def parse_receipt(raw, snapshot_raw=None, cas=None) -> tuple:
    """Symmetric with parse_snapshot: BYTES in, findings out.

    Both documents are bytes: taking a parsed snapshot here would reopen
    exactly the object bypass `verify_receipt_bytes` exists to close, and
    the old signature also still named a function that no longer exists
    (round 14).
    """
    obj, f = parse_strict(raw)
    if obj is not None and not f and snapshot_raw is not None:
        f = verify_receipt_bytes(snapshot_raw, raw, cas)
    return obj, f


# ------------------------------------------------------------- logical paths

class PathViolation(ValueError):
    def __init__(self, code, path):
        super().__init__("%s: %r" % (code, path))
        self.code = code


class SealViolation(ValueError):
    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail) if detail else code)
        self.code = code


def validate_logical_path(path):
    if not isinstance(path, str) or path == "":
        raise PathViolation("EMPTY_PATH", path)
    if "\x00" in path:
        raise PathViolation("NUL_IN_PATH", path)
    if "\\" in path:
        raise PathViolation("BACKSLASH_IN_PATH", path)
    if path.startswith("/"):
        raise PathViolation("ABSOLUTE_PATH", path)
    if path.endswith("/"):
        raise PathViolation("TRAILING_SLASH", path)
    for component in path.split("/"):
        if component == "":
            raise PathViolation("EMPTY_COMPONENT", path)
        if component in (".", ".."):
            raise PathViolation("DOT_COMPONENT", path)
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        raise PathViolation("LONE_SURROGATE", path)
    return path


def validate_prefix(prefix):
    if not isinstance(prefix, str) or prefix == "":
        raise PathViolation("EMPTY_PREFIX", prefix)
    if not prefix.endswith("/"):
        raise PathViolation("PREFIX_WITHOUT_SLASH", prefix)
    if prefix.endswith("//"):
        raise PathViolation("EMPTY_COMPONENT", prefix)
    validate_logical_path(prefix[:-1])
    return prefix


def path_in_prefix(path, prefix):
    return path.startswith(prefix)


def _path_ok(findings, path, at) -> bool:
    try:
        validate_logical_path(path)
        return True
    except PathViolation as exc:
        _f(findings, exc.code, at)
        return False


# ------------------------------------------------------- sealing (in-memory)

def seal_universe(files: dict) -> list:
    universe = []
    for path in sorted(files.keys(), key=path_sort_key):
        validate_logical_path(path)
        data = files[path]
        if not isinstance(data, (bytes, bytearray)):
            raise SealViolation("NOT_REGULAR_FILE_BYTES", repr(path))
        universe.append({"path": path, "sha256": sha256_hex(bytes(data))})
    return universe


def subroot_descriptor(protocol, contract, prefix, universe):
    validate_prefix(prefix)
    for entry in universe:
        if not path_in_prefix(entry["path"], prefix):
            raise SealViolation("PATH_OUTSIDE_PREFIX", entry["path"])
    return {"subroot": "ecosystem.subroot@v0", "protocol": protocol,
            "contract": contract, "prefix": prefix, "universe": universe}


def subroot_descriptor_digest(descriptor) -> str:
    return sha256_hex(SUBROOT_DOMAIN + jcs(descriptor))


def legacy_rev1_root(universe) -> str:
    return sha256_hex(jcs(universe))


def _subroot_sort_key(wrapper):
    return (path_sort_key(wrapper.get("protocol", "")),
            path_sort_key(wrapper.get("prefix", "")),
            str(wrapper.get("digest", "")))


def snapshot_object(subroots, unclaimed, closed=True):
    wrappers = sorted((dict(d, digest=subroot_descriptor_digest(d)) for d in subroots),
                      key=_subroot_sort_key)
    obj = {"snapshot": "ecosystem.snapshot@v0", "bundle_root": ZERO64,
           "subroots": wrappers,
           "unclaimed": sorted(unclaimed, key=lambda e: path_sort_key(e["path"])),
           "closed": closed}
    obj["bundle_root"] = sha256_hex(SNAPSHOT_DOMAIN + jcs(dict(obj, bundle_root=ZERO64)))
    return obj


def verify_bundle_root(obj) -> bool:
    try:
        return obj["bundle_root"] == sha256_hex(
            SNAPSHOT_DOMAIN + jcs(dict(obj, bundle_root=ZERO64)))
    except (ValueError, TypeError, KeyError):
        return False


def cas_resolve(store, digest):
    """Bounded at the CAS boundary: a resolver is external code and may fail
    in ordinary ways. A missing key stays a KeyError (callers already handle
    it); anything else — a raising resolver, a non-bytes value — becomes a
    SealViolation rather than escaping the validator as a host exception."""
    try:
        data = store[digest]
    except KeyError:
        raise
    except Exception as exc:  # noqa: BLE001 — external resolver, bounded here
        # NOT repr(exc): an attacker-supplied exception's __repr__ is code,
        # and calling it in the failure path re-executes hostile logic. The
        # class name is metadata Python already holds.
        raise SealViolation("CAS_RESOLVER_FAILED", type(exc).__name__)
    # exact built-in types only: a bytes/bytearray SUBCLASS can override
    # __bytes__, so the conversion itself would run hostile code
    if type(data) is bytearray:
        data = bytes(data)
    elif type(data) is not bytes:
        raise SealViolation("CAS_NOT_BYTES", type(data).__name__)
    if sha256_hex(data) != digest:
        raise SealViolation("CAS_DIGEST_MISMATCH", digest)
    return data


def _cas_check(findings, cas, digest, at):
    if cas is None or not isinstance(digest, str):
        return
    try:
        cas_resolve(cas, digest)
    except (KeyError, SealViolation):
        _f(findings, "CAS_UNRESOLVABLE", at)


def _ordered(findings, items, keyfn, code, at):
    prev = None
    for i, item in enumerate(items):
        try:
            key = keyfn(item)
        except Exception:  # noqa: BLE001 — hostile shapes must not raise
            continue
        if prev is not None and key <= prev:
            _f(findings, code, "%s/%d" % (at, i))
        prev = key


# ---------------------------------------------------- total snapshot validator

def validate_snapshot(snapshot, cas=None) -> list:
    """Total: any parsed JSON value -> bounded findings, no host exception."""
    f = []
    if not isinstance(snapshot, dict):
        _f(f, "NOT_OBJECT", "/")
        return f
    if snapshot.get("snapshot") != "ecosystem.snapshot@v0":
        _f(f, "BAD_TYPE_TAG", "/snapshot")
        return f
    if set(snapshot.keys()) != SNAPSHOT_KEYS:
        _f(f, "SCHEMA_KEYS", "/")
        return f
    if not isinstance(snapshot["closed"], bool):
        _f(f, "BAD_CLOSED", "/closed")
    if not _is_hex64(snapshot["bundle_root"]):
        _f(f, "BAD_DIGEST_SHAPE", "/bundle_root")

    claims = {}
    prefixes = []
    protocols = set()
    subroots = snapshot["subroots"]
    if not isinstance(subroots, list):
        _f(f, "SUBROOTS_NOT_LIST", "/subroots")
        subroots = []
    valid_wrappers = []
    for i, wrapper in enumerate(subroots):
        at = "/subroots/%d" % i
        if not isinstance(wrapper, dict):
            _f(f, "BAD_SUBROOT_SHAPE", at)
            continue
        if set(wrapper.keys()) != WRAPPER_KEYS or wrapper.get("subroot") != "ecosystem.subroot@v0":
            _f(f, "BAD_DESCRIPTOR_SCHEMA", at)
            continue
        if not _is_hex64(wrapper["digest"]):
            _f(f, "BAD_DIGEST_SHAPE", at + "/digest")
            continue
        contract = wrapper["contract"]
        ok_shape = True
        if not (isinstance(contract, dict) and set(contract.keys()) == CONTRACT_KEYS
                and isinstance(contract["name"], str) and contract["name"]
                and isinstance(contract["version"], str) and contract["version"]
                and (contract["spec_digest"] is None or _is_hex64(contract["spec_digest"]))):
            _f(f, "BAD_CONTRACT", at + "/contract")
            ok_shape = False
        if not (isinstance(wrapper["protocol"], str) and wrapper["protocol"]):
            _f(f, "BAD_PROTOCOL", at + "/protocol")
            ok_shape = False
        elif isinstance(contract, dict) and wrapper["protocol"] != contract.get("name"):
            _f(f, "PROTOCOL_CONTRACT_MISMATCH", at)
        if isinstance(wrapper["protocol"], str):
            if wrapper["protocol"] in protocols:
                _f(f, "DUPLICATE_PROTOCOL_SLOT", at)
            protocols.add(wrapper["protocol"])
        try:
            validate_prefix(wrapper["prefix"])
        except PathViolation as exc:
            _f(f, exc.code, at + "/prefix")
            ok_shape = False
        universe = wrapper["universe"]
        if not isinstance(universe, list):
            _f(f, "UNIVERSE_NOT_LIST", at + "/universe")
            continue
        entries_ok = True
        for j, entry in enumerate(universe):
            eat = "%s/universe/%d" % (at, j)
            if not (isinstance(entry, dict) and set(entry.keys()) == {"path", "sha256"}):
                _f(f, "BAD_UNIVERSE_ENTRY", eat)
                entries_ok = False
                continue
            if not _path_ok(f, entry["path"], eat):
                entries_ok = False
                continue
            if not _is_hex64(entry["sha256"]):
                _f(f, "BAD_DIGEST_SHAPE", eat)
                entries_ok = False
            if ok_shape and not path_in_prefix(entry["path"], wrapper["prefix"]):
                _f(f, "PATH_OUTSIDE_PREFIX", eat)
            claims.setdefault(entry["path"], []).append(at)
            _cas_check(f, cas, entry.get("sha256"), eat)
        _ordered(f, [e for e in universe if isinstance(e, dict) and isinstance(e.get("path"), str)],
                 lambda e: path_sort_key(e["path"]), "UNIVERSE_NOT_UTF16_SORTED", at + "/universe")
        if ok_shape and entries_ok:
            descriptor = {k: v for k, v in wrapper.items() if k != "digest"}
            try:
                if subroot_descriptor_digest(descriptor) != wrapper["digest"]:
                    _f(f, "STALE_SUBROOT_DIGEST", at + "/digest")
            except ValueError:
                _f(f, "BAD_DESCRIPTOR_SCHEMA", at)
        if ok_shape:
            prefixes.append((wrapper["prefix"], at))
            valid_wrappers.append(wrapper)

    _ordered(f, valid_wrappers, _subroot_sort_key, "SUBROOTS_NOT_SORTED", "/subroots")

    unclaimed = snapshot["unclaimed"]
    if not isinstance(unclaimed, list):
        _f(f, "UNCLAIMED_NOT_LIST", "/unclaimed")
        unclaimed = []
    for i, entry in enumerate(unclaimed):
        at = "/unclaimed/%d" % i
        if not (isinstance(entry, dict) and set(entry.keys()) == {"path", "sha256"}):
            _f(f, "BAD_UNIVERSE_ENTRY", at)
            continue
        if not _path_ok(f, entry["path"], at):
            continue
        if not _is_hex64(entry["sha256"]):
            _f(f, "BAD_DIGEST_SHAPE", at)
        for prefix, _sat in prefixes:
            if path_in_prefix(entry["path"], prefix):
                _f(f, "UNCLAIMED_INSIDE_PREFIX", at)
        claims.setdefault(entry["path"], []).append("/unclaimed")
        _cas_check(f, cas, entry.get("sha256"), at)
    _ordered(f, [e for e in unclaimed if isinstance(e, dict) and isinstance(e.get("path"), str)],
             lambda e: path_sort_key(e["path"]), "UNCLAIMED_NOT_SORTED", "/unclaimed")

    for path, owners in claims.items():
        if len(owners) > 1:
            _f(f, "PARTITION_VIOLATION", " & ".join(owners) + " -> " + path)
    for i, (a, aat) in enumerate(prefixes):
        for b, _bat in prefixes[i + 1:]:
            if a.startswith(b) or b.startswith(a):
                _f(f, "OVERLAPPING_PREFIXES", aat)
    if not verify_bundle_root(snapshot):
        _f(f, "BUNDLE_ROOT_MISMATCH", "/bundle_root")
    return f


def validate_warrant_descriptor_role(descriptor, expected_version) -> list:
    f = []
    if not isinstance(descriptor, dict):
        _f(f, "BAD_DESCRIPTOR_SCHEMA", "/")
        return f
    contract = descriptor.get("contract")
    contract = contract if isinstance(contract, dict) else {}
    if descriptor.get("protocol") != "warrant":
        _f(f, "WRONG_PROTOCOL_SLOT", "/protocol")
    if contract.get("name") != "warrant":
        _f(f, "WRONG_CONTRACT_NAME", "/contract/name")
    if contract.get("version") != expected_version:
        _f(f, "WRONG_CONTRACT_VERSION", "/contract/version")
    if not _is_hex64(contract.get("spec_digest")):
        _f(f, "SPEC_DIGEST_REQUIRED", "/contract/spec_digest")
    return f


# ------------------------------------------------------------ locator union

def validate_locator(at_obj) -> bool:
    if not isinstance(at_obj, dict):
        return False
    kind = at_obj.get("kind")
    keys = set(at_obj.keys()) - {"occurrence"}
    if "occurrence" in at_obj and not (_is_safe_int(at_obj["occurrence"])
                                       and at_obj["occurrence"] >= 0):
        return False
    if kind == "json-pointer":
        return keys == {"kind", "value"} and isinstance(at_obj["value"], str) \
            and (at_obj["value"] == "" or at_obj["value"].startswith("/"))
    if kind == "byte-range":
        return keys == {"kind", "start", "end"} and _is_safe_int(at_obj.get("start")) \
            and _is_safe_int(at_obj.get("end")) and 0 <= at_obj["start"] < at_obj["end"]
    if kind == "path":
        if keys != {"kind", "value"}:
            return False
        try:
            validate_logical_path(at_obj["value"])
            return True
        except PathViolation:
            return False
    if kind == "global":
        return keys == {"kind", "value"} and at_obj.get("value") in GLOBAL_SUBJECTS
    return False


def _valid_issues(findings, issues, at) -> list:
    """Shape-check an issue array; returns the well-formed subset."""
    if not isinstance(issues, list):
        _f(findings, "ISSUES_NOT_LIST", at)
        return []
    good = []
    for i, issue in enumerate(issues):
        iat = "%s/%d" % (at, i)
        if not (isinstance(issue, dict) and set(issue.keys()) == {"code", "severity", "at"}
                and isinstance(issue.get("code"), str)
                and issue.get("severity") in ("ERR", "WARN")
                and validate_locator(issue.get("at"))):
            _f(findings, "BAD_ISSUE_SHAPE", iat)
            continue
        good.append(issue)
    _ordered(findings, good, lambda x: jcs(x), "ISSUES_NOT_SORTED", at)
    return good


def _join_issue(issues, code, severity, ptr):
    """Exact per-occurrence join: an issue of this code+severity whose locator
    is precisely this JSON pointer."""
    return any(x["code"] == code and x["severity"] == severity
               and x["at"].get("kind") == "json-pointer" and x["at"].get("value") == ptr
               for x in issues)


# --------------------------------------------- receipt core (internal layer)

def validate_receipt_core(core, descriptor=None, cas=None, view=None) -> list:
    """Total over any parsed JSON value. Judges internal consistency and,
    when descriptor/cas are supplied by the composed verdict, byte-level
    reason resolution. Public entry is verify_receipt_bytes()."""
    f = []
    if not isinstance(core, dict):
        _f(f, "NOT_OBJECT", "/core")
        return f
    if set(core.keys()) != CORE_KEYS:
        _f(f, "SCHEMA_KEYS", "/core")
        return f
    grade = core["grade"]
    if grade not in ("base", "settlement"):
        _f(f, "BAD_GRADE", "/core/grade")
        grade = None
    if grade == "base" and core["trust_config_digest"] is not None:
        _f(f, "TRUST_AT_BASE", "/core/trust_config_digest")
    if grade == "settlement" and not _is_hex64(core["trust_config_digest"]):
        _f(f, "TRUST_DIGEST_REQUIRED", "/core/trust_config_digest")
    if not _is_hex64(core["subroot_descriptor_digest"]):
        _f(f, "BAD_DIGEST_SHAPE", "/core/subroot_descriptor_digest")

    runtimes = {}
    policy = core["execution_policy"]
    if not (isinstance(policy, dict) and set(policy.keys()) == {"runtimes"}
            and isinstance(policy["runtimes"], list)):
        _f(f, "BAD_EXECUTION_POLICY", "/core/execution_policy")
    else:
        good_rt = []
        for i, rt in enumerate(policy["runtimes"]):
            at = "/core/execution_policy/runtimes/%d" % i
            if not (isinstance(rt, dict) and set(rt.keys()) == RUNTIME_KEYS
                    and isinstance(rt["runtime"], str) and rt["runtime"]
                    and isinstance(rt["semantics"], str)
                    and _is_hex64(rt["semantics_digest"])
                    and isinstance(rt["budget_unit"], str)
                    and _is_safe_int(rt["ceiling"]) and rt["ceiling"] >= 0):
                _f(f, "BAD_RUNTIME_ENTRY", at)
                continue
            if rt["runtime"] in NORMATIVE_NOT_EXECUTED:
                # warrant SPEC §3/§6(7): the container is cmd@v1's trust
                # model, and `verify` does not re-run it. Declaring it in an
                # execution policy asserts a capability the contract says a
                # verifier does not have (round 13).
                _f(f, "NON_EXECUTABLE_RUNTIME_DECLARED", at)
            good_rt.append(rt)
            runtimes[rt["runtime"]] = rt
        # Uniqueness is by RUNTIME, not by (runtime, semantics_digest): two
        # ski@v1 entries with different anchors sorted "correctly" while the
        # lookup silently kept the last, so the receipt held two answers to
        # "under which semantics was this executed" (re-gate P1-2).
        seen_rt = set()
        for i, rt in enumerate(good_rt):
            if rt["runtime"] in seen_rt:
                _f(f, "DUPLICATE_RUNTIME",
                   "/core/execution_policy/runtimes/%d" % i)
            seen_rt.add(rt["runtime"])
        _ordered(f, good_rt, lambda r: r["runtime"],
                 "RUNTIMES_NOT_SORTED", "/core/execution_policy/runtimes")

    all_issues = list(_valid_issues(f, core["global_issues"], "/core/global_issues"))

    sources = core["sources"]
    if not isinstance(sources, list):
        _f(f, "SOURCES_NOT_LIST", "/core/sources")
        sources = []
    good_sources = []
    for i, src in enumerate(sources):
        at = "/core/sources/%d" % i
        if not isinstance(src, dict):
            _f(f, "BAD_SOURCE_SHAPE", at)
            continue
        kind = src.get("kind")
        if kind not in ("record", "blob", "genesis", "other"):
            _f(f, "BAD_SOURCE_KIND", at)
            continue
        expected = SOURCE_RECORD_KEYS if kind == "record" else SOURCE_BASE_KEYS
        if set(src.keys()) != expected:
            _f(f, "RECORD_FIELDS_ON_NONRECORD" if kind != "record"
               and set(src.keys()) & (SOURCE_RECORD_KEYS - SOURCE_BASE_KEYS)
               else "SCHEMA_KEYS", at)
            continue
        if not _path_ok(f, src["path"], at + "/path"):
            continue
        if not _is_hex64(src["entry_digest"]):
            _f(f, "BAD_DIGEST_SHAPE", at + "/entry_digest")
            continue
        if not isinstance(src["loaded"], bool):
            _f(f, "BAD_LOADED", at + "/loaded")
            continue
        issues = _valid_issues(f, src["issues"], at + "/issues")
        # A source's issues are LOCAL to that source. Without this, an ERR
        # whose locator names another member still excluded THIS one: a
        # healthy record vanished from the graph while `exclusions[]` paired
        # its path with an issue about a different file (round 12). Fixing
        # the acknowledgement join alone was not enough, because exclusion
        # keys on "any ERR here", not on what the ERR is about.
        for _i, _x in enumerate(issues):
            _kind = _x["at"].get("kind")
            _iat = "%s/issues/%d" % (at, _i)
            if _kind == "path" and _x["at"].get("value") != src["path"]:
                _f(f, "ISSUE_OUT_OF_SCOPE", _iat)
            elif _kind == "global":
                # store-wide subjects belong to global_issues[], where they
                # are not attached to any member
                _f(f, "GLOBAL_ISSUE_ON_SOURCE", _iat)
        all_issues.extend(issues)
        good_sources.append(src)
        err_here = any(x["severity"] == "ERR" for x in issues)
        if src["loaded"] is False and not err_here:
            _f(f, "UNLOADED_WITHOUT_ERR", at)

        # `loaded` is DERIVED, not chosen. It means exactly: the consumer
        # obtained this member's bytes and their digest matched. Parse and
        # schema failures are issues, not un-loadedness. Treating the
        # producer's field as permission to skip byte derivation let a
        # fabricated "unreadable" record — bytes present, digest correct,
        # strict parse clean — validate and vanish from the graph.
        if cas is not None:
            try:
                cas_resolve(cas, src["entry_digest"])
                derived_loaded = True
            except (KeyError, SealViolation):
                derived_loaded = False
            if src["loaded"] is not derived_loaded:
                _f(f, "LOADED_MISREPORTED", at)
            # Gating on the DERIVED value, not the reported one. Unisolatable
            # by a vector today — a misreport already fires
            # LOADED_MISREPORTED above, so both gates refuse the same inputs —
            # and labelled rather than counted. It is kept so that byte
            # derivation follows the bytes even if that finding is ever
            # softened.
            if kind != "record" or not derived_loaded:
                continue
        elif kind != "record" or not src["loaded"]:
            continue

        c, w = src["claimed_wid"], src["computed_wid"]
        if not ((c is None or _is_hex64(c)) and (w is None or _is_hex64(w))
                and isinstance(src["id_sound"], bool)):
            _f(f, "BAD_WID_FIELDS", at)
            continue
        if src["id_sound"] != (c == w and w is not None):
            _f(f, "ID_SOUND_INCONSISTENT", at)
        if src["id_sound"] is False and not err_here:
            _f(f, "ID_UNSOUND_WITHOUT_ERR", at)

        # Resolve the record ONCE per source and re-derive the WarrantID from
        # the committed body. Internal equality of claimed/computed only
        # proves the receipt agrees with itself: a stale `computed_wid` over
        # an edited body kept the graph asserting an identity the bytes no
        # longer have (re-gate P1-1).
        parsed = None
        body_invalid_ack = False
        if cas is not None:
            parsed = _resolve_record(f, cas, src, at, issues)
            if parsed is not None:
                # Every record's body is version- and schema-checked, whether
                # or not it carries a check reason. Validating the version
                # only inside the reason loop meant a record with no checks —
                # or with prose only — never had its declared format looked
                # at at all (round 13).
                _bad = body_schema_findings(parsed.get("body"))
                if _bad:
                    # derived body defects join with acknowledgement exactly
                    # like a parse failure, so honestly-reported invalid
                    # evidence can still be a valid receipt
                    if _acknowledges(issues, "BODY_SCHEMA_INVALID", src["path"]):
                        # ...and an invalid body owes no account of its
                        # reasons: demanding a reason entry (and with it a
                        # run outcome) for a reason the body cannot legally
                        # contain would require inventing evidence about
                        # evidence already declared invalid
                        body_invalid_ack = True
                        if src.get("reasons"):
                            _f(f, "REASONS_OVER_INVALID_BODY", at)
                    else:
                        for _code in _bad:
                            _f(f, _code, at)
                elif _acknowledges(issues, "BODY_SCHEMA_INVALID", src["path"]):
                    _f(f, "SPURIOUS_BODY_SCHEMA_INVALID", at)
            if parsed is not None and view is not None:
                # the validated view: what the verdict was actually rendered
                # over, handed to consumers so nothing re-reads the CAS and
                # judges one snapshot while asserting over another
                body_obj = parsed.get("body")
                because = body_obj.get("because") if isinstance(body_obj, dict) else None
                view.setdefault("committed", {})[src["path"]] = (
                    json.loads(json.dumps(because)) if isinstance(because, list) else [])
                # The whole committed body, for the same reason and under the
                # same rule: a consumer mapping §4.1 (actor, under, subject,
                # evidence, prior) must read the bytes THIS verdict was
                # rendered over, never the store again. Deep-copied, so a
                # consumer cannot reach back through the view and edit what
                # was judged. This is an output channel only — the verdict
                # never reads it, which `selftest` asserts by running every
                # vector with and without a view and comparing findings.
                view.setdefault("body", {})[src["path"]] = (
                    json.loads(json.dumps(body_obj))
                    if isinstance(body_obj, dict) else None)
            if parsed is not None and w is not None:
                body = parsed.get("body")
                try:
                    actual = sha256_hex(jcs(body)) if isinstance(body, dict) else None
                except ValueError:
                    actual = None
                if actual is None:
                    _f(f, "RECORD_BODY_UNREADABLE", at)
                elif actual != w:
                    _f(f, "COMPUTED_WID_MISMATCH", at)

        settlement = src["settlement"] if isinstance(src["settlement"], list) else []
        if not isinstance(src["settlement"], list):
            _f(f, "SETTLEMENT_NOT_LIST", at + "/settlement")
        good_settle = []
        for j, s in enumerate(settlement):
            sat = "%s/settlement/%d" % (at, j)
            if not (isinstance(s, dict) and set(s.keys()) == SETTLE_KEYS
                    and _is_hex64(s["jurisdiction"]) and isinstance(s["active"], bool)
                    and isinstance(s["policies"], list)):
                _f(f, "BAD_SETTLEMENT_ENTRY", sat)
                continue
            good_pol = []
            for k, p in enumerate(s["policies"]):
                if not (isinstance(p, dict) and set(p.keys()) == POLICY_KEYS
                        and _is_hex64(p["policy"])
                        and isinstance(p["threshold_satisfied"], bool)):
                    _f(f, "BAD_POLICY_ENTRY", "%s/policies/%d" % (sat, k))
                    continue
                good_pol.append(p)
            _ordered(f, good_pol, lambda p: p["policy"], "POLICIES_NOT_SORTED",
                     sat + "/policies")
            good_settle.append(s)
        _ordered(f, good_settle, lambda s: s["jurisdiction"], "SETTLEMENT_NOT_SORTED",
                 at + "/settlement")
        if grade == "base" and settlement:
            _f(f, "SETTLEMENT_IN_BASE", at + "/settlement")
        settlement_active = any(s.get("active") is True for s in good_settle)

        sigs = src["signatures"] if isinstance(src["signatures"], list) else []
        if not isinstance(src["signatures"], list):
            _f(f, "SIGNATURES_NOT_LIST", at + "/signatures")
        good_sigs = []
        for j, s in enumerate(sigs):
            sat = "%s/signatures/%d" % (at, j)
            if not (isinstance(s, dict) and set(s.keys()) == SIG_KEYS
                    and _is_hex64(s["sig_digest"])
                    and _is_safe_int(s["multiplicity"]) and s["multiplicity"] >= 0
                    and isinstance(s["actor"], str) and _is_hex64(s["key"])
                    and isinstance(s["valid"], bool)
                    and s["binding"] in ("bound", "unbound", "unverified")):
                _f(f, "BAD_SIGNATURE_ENTRY", sat)
                continue
            good_sigs.append(s)
            if s["valid"] is False and s["binding"] == "bound":
                _f(f, "BINDING_WITHOUT_VALIDITY", sat)
        _ordered(f, good_sigs, lambda s: (s["sig_digest"], s["multiplicity"]),
                 "SIGNATURES_NOT_SORTED", at + "/signatures")
        # One-way internal-consistency rule, no cryptography involved: if the
        # receipt itself reports no valid signature by the committed
        # body.actor.id, it may not simultaneously report ok/errors as if the
        # record were soundly signed. This does not make `valid: true`
        # trustworthy — it only forbids a receipt from contradicting its own
        # NEGATIVE claims (warrant SPEC §5 requires a valid actor signature).
        body_obj = parsed.get("body") if isinstance(parsed, dict) else None
        actor_id = (body_obj.get("actor", {}) or {}).get("id") \
            if isinstance(body_obj, dict) and isinstance(body_obj.get("actor"), dict) \
            else None
        if parsed is not None:
            has_valid_actor_sig = any(
                s.get("valid") is True and s.get("actor") == actor_id
                for s in good_sigs) and actor_id is not None
            if not has_valid_actor_sig and not any(
                    x["code"] == "NO_VALID_ACTOR_SIGNATURE"
                    and x["severity"] == "ERR" for x in issues):
                _f(f, "NO_VALID_ACTOR_SIGNATURE_UNREPORTED", at)

        # Each invalid signature must be acknowledged AT ITS OWN INDEX.
        # Counting occurrences only proved "as many issues as failures";
        # it never checked that an issue names the signature it is about,
        # so a WARN at /sigs/0 covered a failure at /sigs/3 (round 13).
        env_index = {}
        if parsed is not None:
            for _d, _m, _a, _k, _idx in envelope_signature_entries(parsed)[0]:
                env_index[(_d, _m)] = _idx
        sig_issues = [x for x in issues if x["code"] == "INVALID_SIGNATURE"
                      and x["severity"] == "WARN"]
        wanted = set()
        for sig in good_sigs:
            if sig["valid"] is not False:
                continue
            idx = env_index.get((sig["sig_digest"], sig["multiplicity"]))
            if idx is None:
                continue                       # already reported as not-in-envelope
            wanted.add("/sigs/%d" % idx)
        present = {x["at"].get("value") for x in sig_issues
                   if x["at"].get("kind") == "json-pointer"}
        for ptr in sorted(wanted - present):
            _f(f, "INVALID_SIG_UNREPORTED_AT", "%s%s" % (at, ptr))
        for ptr in sorted(present - wanted):
            _f(f, "INVALID_SIG_REPORTED_AT_SOUND", "%s%s" % (at, ptr))
        if len(present) != len(sig_issues):
            _f(f, "INVALID_SIG_OCCURRENCE_MISMATCH", at)

        reasons = src["reasons"] if isinstance(src["reasons"], list) else []
        if not isinstance(src["reasons"], list):
            _f(f, "REASONS_NOT_LIST", at + "/reasons")
        good_reasons = []
        for j, reason in enumerate(reasons):
            rat = "%s/reasons/%d" % (at, j)
            if not (isinstance(reason, dict) and set(reason.keys()) == REASON_KEYS
                    and isinstance(reason["ptr"], str) and PTR_RE.match(reason["ptr"])
                    and isinstance(reason["kind"], str)
                    and isinstance(reason["runtime"], str)
                    and _is_hex64(reason["reason_digest"])
                    and isinstance(reason["outcome"], dict)
                    and set(reason["outcome"].keys()) == OUTCOME_KEYS):
                _f(f, "BAD_REASON_ENTRY", rat)
                continue
            good_reasons.append(reason)
            o = reason["outcome"]
            re_ex = o["re_execution"]
            observed = (o["observed_verdict"], o["observed_result"], o["atp_spent"])
            fc = o["failure_code"]
            rt = reason["runtime"]
            if o["claimed_verdict"] not in VERDICTS:
                _f(f, "BAD_VERDICT", rat)
                continue
            if re_ex in ("matched", "mismatched"):
                if any(v is None for v in observed) or fc is not None:
                    _f(f, "OUTCOME_NOT_TOTAL", rat)
                    continue
                if o["observed_verdict"] not in VERDICTS:
                    _f(f, "BAD_VERDICT", rat)
                    continue
                # A re-execution result only means something under declared
                # semantics: an undeclared runtime has no semantics_digest and
                # no ceiling, so "matched" would grant authority to a runtime
                # the verifier never claimed it could run (re-gate P1-1).
                if rt in NORMATIVE_NOT_EXECUTED:
                    # a verifier that reports having re-run cmd@v1 is
                    # reporting something the contract says it does not do
                    _f(f, "NON_EXECUTABLE_RUNTIME_EXECUTED", rat)
                elif rt not in runtimes:
                    _f(f, "RUNTIME_NOT_DECLARED", rat)
                    # deliberately not `continue`: the role-binding check
                    # below must still run, so a swapped runtime reports both
                    # what it lied about and what it was never licensed to do
                if rt == "ski@v1" and not _is_hex64(o["observed_result"]):
                    _f(f, "BAD_RESULT_SHAPE", rat)
                if not (_is_safe_int(o["atp_spent"]) and o["atp_spent"] >= 0):
                    _f(f, "BAD_ATP", rat)
                elif rt in runtimes and o["atp_spent"] > runtimes[rt]["ceiling"]:
                    _f(f, "ATP_OVER_CEILING", rat)
                if re_ex == "matched" and o["observed_verdict"] != o["claimed_verdict"]:
                    _f(f, "MATCHED_BUT_DIFFERS", rat)
                if re_ex == "mismatched":
                    if o["observed_verdict"] == o["claimed_verdict"]:
                        _f(f, "MISMATCH_BUT_EQUAL", rat)
                    if not _join_issue(issues, "REASON_MISMATCH", "WARN", reason["ptr"]):
                        _f(f, "MISMATCH_WITHOUT_WARN", rat)
            elif re_ex == "unverified":
                if rt in NORMATIVE_NOT_EXECUTED:
                    # a runtime this verifier never runs cannot have failed
                    # to run for a reason: `not-applicable` is its only
                    # honest outcome (round 14)
                    _f(f, "NON_EXECUTABLE_RUNTIME_EXECUTED", rat)
                if any(v is not None for v in observed) or fc not in FAILURE_CODES:
                    _f(f, "OUTCOME_NOT_TOTAL", rat)
                    continue
                if fc == "RUNTIME_UNAVAILABLE" and rt in runtimes:
                    _f(f, "FAILURE_CODE_VS_POLICY", rat)
                if fc == "MISSING_BLOB" and parsed is not None:
                    # "the blob was missing" is refutable from the store the
                    # verdict already holds: if the committed check resolves
                    # to an available blob, that failure did not happen
                    _idx = int(reason["ptr"].rsplit("/", 1)[1])
                    _because = (parsed.get("body") or {}).get("because")
                    _committed = (_because[_idx] if isinstance(_because, list)
                                  and _idx < len(_because) else None)
                    if isinstance(_committed, dict) and _committed.get(
                            "check") in available_blob_digests(core):
                        _f(f, "MISSING_BLOB_BUT_PRESENT", rat)
                if fc == "OVER_BUDGET" and rt not in runtimes:
                    _f(f, "FAILURE_CODE_VS_POLICY", rat)
                need = "ERR" if (grade == "settlement" and settlement_active) else "WARN"
                if not _join_issue(issues, "REASON_UNVERIFIED", need, reason["ptr"]):
                    _f(f, "UNVERIFIED_WITHOUT_" + need, rat)
            elif re_ex == "not-applicable":
                if any(v is not None for v in observed) or fc is not None:
                    _f(f, "OUTCOME_NOT_TOTAL", rat)
                elif rt not in NORMATIVE_NOT_EXECUTED:
                    _f(f, "NOT_APPLICABLE_BUT_EXECUTABLE", rat)
                elif rt in runtimes:
                    # "not applicable" and "declared as available" are
                    # contradictory statements about the same runtime
                    _f(f, "NOT_APPLICABLE_BUT_DECLARED", rat)
            else:
                _f(f, "BAD_RE_EXECUTION", rat)
            if cas is not None:
                _resolve_reason(f, parsed, reason, rat)
        _ordered(f, good_reasons, lambda r: r["ptr"], "REASONS_NOT_SORTED",
                 at + "/reasons")

        # Completeness against the committed bytes. Without it, "the receipt
        # reports X" was the whole contract: a receipt could omit an
        # envelope signature, omit a committed check reason, or invent a
        # bound signature that exists nowhere — all with zero findings, and
        # dataset-relative coverage would faithfully describe whatever the
        # receipt chose to disclose.
        if parsed is not None:
            summary = _bind_to_envelope(f, parsed, src, good_sigs,
                                        good_reasons, at, issues,
                                        skip_reasons=body_invalid_ack)
            if view is not None:
                # evidence PRESENCE is derived from the total derivation, so
                # a malformed occurrence still counts as evidence the input
                # held — coverage must not read it as absence
                view.setdefault("evidence", {})[src["path"]] = summary

    _ordered(f, good_sources, lambda s: (path_sort_key(s["path"]), s["entry_digest"]),
             "SOURCES_NOT_SORTED", "/core/sources")

    errs = sum(1 for x in all_issues if x["severity"] == "ERR")
    warns = sum(1 for x in all_issues if x["severity"] == "WARN")
    if core["errors"] != errs:
        _f(f, "ERRORS_UNBOUND", "/core/errors")
    if core["warnings"] != warns:
        _f(f, "WARNINGS_UNBOUND", "/core/warnings")
    if core["ok"] != (errs == 0):
        _f(f, "OK_UNBOUND", "/core/ok")
    return f


def _is_hex128(x) -> bool:
    return isinstance(x, str) and bool(HEX128.match(x))


def envelope_signature_entries(envelope):
    """(entries, malformed_pointers) over the WHOLE committed `sigs[]`.

    Returning only what parsed cleanly made the "exact bijection" a bijection
    with a silently filtered subset: `{"sigs": [7]}` derived an empty
    expected multiset, so a receipt reporting no signatures matched it
    exactly and the dataset honestly claimed to hold no signature evidence.
    Malformed occurrences are now returned, and must be accounted for.
    """
    # Entries carry their ORIGINAL envelope index. Numbering a filtered list
    # made `/sigs/1` become `/sigs/0` whenever an earlier entry was
    # malformed, so an acknowledgement pointing at the malformed slot
    # legalised a different signature's failure (round 14).
    entries, malformed, seen = [], [], {}
    sigs = envelope.get("sigs") if isinstance(envelope, dict) else None
    if not isinstance(sigs, list):
        return entries, ["/sigs"]
    for i, entry in enumerate(sigs):
        at = "/sigs/%d" % i
        if not (isinstance(entry, dict) and set(entry.keys()) == {"actor", "key", "sig"}
                and isinstance(entry.get("actor"), str) and entry["actor"]
                and _is_hex64(entry.get("key")) and _is_hex128(entry.get("sig"))):
            malformed.append(at)
            continue
        try:
            digest = sha256_hex(jcs({k: entry[k] for k in ("actor", "key", "sig")}))
        except ValueError:
            malformed.append(at)
            continue
        mult = seen.get(digest, 0)
        seen[digest] = mult + 1
        entries.append((digest, mult, entry["actor"], entry["key"], i))
    return entries, malformed


def _reason_shape(item):
    """'check' | 'prose' | None — None means malformed, per warrant SPEC §3."""
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    keys = set(item.keys())
    if kind == "prose":
        return "prose" if keys == {"kind", "text"} and isinstance(
            item.get("text"), str) else None
    if kind == "check":
        # the runtime enum is CLOSED in Warrant's body schema; accepting any
        # non-empty string made an unknown runtime a well-formed reason here
        # while Warrant rejects the record outright (round 16)
        known = set()
        for _allowed in RUNTIME_REGISTRY.values():
            known |= _allowed
        ok = (keys <= {"kind", "check", "runtime", "verdict", "transcript"}
              and {"kind", "check", "runtime", "verdict"} <= keys
              and _is_hex64(item.get("check"))
              and item.get("runtime") in known
              and item.get("verdict") in VERDICTS
              and ("transcript" not in keys or _is_hex64(item["transcript"])))
        return "check" if ok else None
    return None


def reportable_reason_pointers(envelope):
    """(reportable_check_pointers, malformed_pointers) over the WHOLE
    committed `because[]`. Only a **well-formed prose** reason is
    intentionally non-reportable; anything unrecognised is malformed, not
    quietly absent."""
    body = envelope.get("body") if isinstance(envelope, dict) else None
    because = body.get("because") if isinstance(body, dict) else None
    if not isinstance(because, list):
        return set(), ["/body/because"]
    reportable, malformed = set(), []
    for i, item in enumerate(because):
        shape = _reason_shape(item)
        if shape is None:
            malformed.append("/body/because/%d" % i)
        elif shape == "check":
            reportable.add("/because/%d" % i)
    return reportable, malformed


# Normative code/severity matrix for malformed committed occurrences.
# Not one universal severity: warrant SPEC §5 lets a malformed EXTRA
# co-signature be a WARN while a valid actor-signature survives, but a body
# or reason whose schema is invalid, and an envelope with no valid
# actor-signature left, are ERR.
MALFORMED_SIG_CODE = "MALFORMED_SIGNATURE"
MALFORMED_ENVELOPE_CODE = "MALFORMED_ENVELOPE"
MALFORMED_REASON_CODE = "MALFORMED_REASON"
MALFORMED_BODY_CODE = "MALFORMED_BODY_SCHEMA"


def _expected_malformed_issues(envelope, expected_sigs, sig_malformed,
                               reason_malformed, good_sigs):
    """[(pointer, code, {allowed severities})] the receipt MUST report.

    **Malformed signatures are always ERR.** Warrant SPEC §5 does let a
    malformed EXTRA co-signature be survivable while a valid signature by
    `body.actor.id` remains — but deciding that requires knowing the actor
    signature is *cryptographically* valid, and the only thing SEV has is
    the receipt's own `valid` field. Letting a producer-asserted claim
    relax a rule applied to the same receipt is self-authorisation: the
    shipped fixture already claimed `valid: true` for a key/signature pair
    that fails `warrant-sig-v1` verification, and thereby bought its
    malformed extra signature a WARN.

    SEV also must not re-implement Warrant's cryptography to settle this —
    that is the ownership boundary this repository exists to hold: each
    protocol judges its own bytes. So the survivable path is **not
    available** to SEV, and this matrix is deliberately *not* called
    Warrant-consistent: it is strictly stronger, and fails closed. If a
    future receipt carries an independently verifiable validity judgement
    (a signed receipt, or Warrant's own verifier output bound to it), the
    WARN path can be reinstated on that basis, never on this one.
    """
    out = []
    for ptr in sig_malformed:
        out.append((ptr, MALFORMED_ENVELOPE_CODE if ptr == "/sigs"
                    else MALFORMED_SIG_CODE, {"ERR"}))
    for ptr in reason_malformed:
        out.append((ptr, MALFORMED_BODY_CODE if ptr == "/body/because"
                    else MALFORMED_REASON_CODE, {"ERR"}))
    return out


def _bind_to_envelope(f, envelope, src, good_sigs, good_reasons, at, issues,
                      skip_reasons=False):
    expected_sigs, sig_malformed = envelope_signature_entries(envelope)
    expected_keyed = {(d, m): (a, k) for d, m, a, k, _i in expected_sigs}
    reported = {}
    for s in good_sigs:
        key = (s["sig_digest"], s["multiplicity"])
        if key in reported:
            _f(f, "DUPLICATE_SIGNATURE_ENTRY", at)
        reported[key] = s
    for key in sorted(set(expected_keyed) - set(reported)):
        _f(f, "SIGNATURE_MISSING", "%s [%s:%d]" % (at, key[0], key[1]))
    for key in sorted(set(reported) - set(expected_keyed)):
        _f(f, "SIGNATURE_NOT_IN_ENVELOPE", "%s [%s:%d]" % (at, key[0], key[1]))
    for key in sorted(set(expected_keyed) & set(reported)):
        actor, pubkey = expected_keyed[key]
        s = reported[key]
        if s.get("actor") != actor or s.get("key") != pubkey:
            _f(f, "SIGNATURE_FIELD_MISMATCH", "%s [%s:%d]" % (at, key[0], key[1]))

    expected_ptrs, reason_malformed = reportable_reason_pointers(envelope)
    if skip_reasons:
        # the body is declared invalid and acknowledged: its reasons are not
        # reportable evidence, so neither their bijection nor their
        # malformed occurrences are demanded
        expected_ptrs, reason_malformed = set(), []
    reported_ptrs = {}
    for r in good_reasons:
        if r["ptr"] in reported_ptrs:
            _f(f, "DUPLICATE_REASON_POINTER", "%s%s" % (at, r["ptr"]))
        reported_ptrs[r["ptr"]] = r
    for ptr in sorted(expected_ptrs - set(reported_ptrs)):
        _f(f, "REASON_MISSING", "%s%s" % (at, ptr))
    for ptr in sorted(set(reported_ptrs) - expected_ptrs):
        _f(f, "REASON_NOT_COMMITTED", "%s%s" % (at, ptr))

    # A malformed committed occurrence must be acknowledged SEMANTICALLY:
    # matching on the JSON pointer alone let any unrelated WARN at the same
    # address legalise it — leaving ok:true, no exclusion, and coverage free
    # to call a malformed signature "no signature evidence".
    present = {(x["code"], x["severity"], x["at"].get("value"))
               for x in issues if isinstance(x.get("at"), dict)
               and x["at"].get("kind") == "json-pointer"}
    for ptr, code, severities in _expected_malformed_issues(
            envelope, expected_sigs, sig_malformed, reason_malformed, good_sigs):
        if not any((code, sev, ptr) in present for sev in severities):
            _f(f, "MALFORMED_ENVELOPE_UNREPORTED",
               "%s%s [%s %s]" % (at, ptr, code, "|".join(sorted(severities))))

    return {"signature_occurrences": len(expected_sigs) + len(sig_malformed),
            "check_occurrences": len(expected_ptrs) + len(reason_malformed)}


def _acknowledges(issues, code, path) -> bool:
    """An acknowledgement is `(this source's path, code, ERR)`.

    The locator is not decoration: an issue naming another member describes
    that member, and letting it stand in for this one turns the exclusion
    record into a false coordinate.
    """
    return any(x["code"] == code and x["severity"] == "ERR"
               and isinstance(x.get("at"), dict)
               and x["at"].get("kind") == "path"
               and x["at"].get("value") == path
               for x in issues)


def _resolve_record(f, cas, src, at, issues):
    """Resolve and parse a record's committed bytes ONCE per source.

    Returns the parsed envelope, or None when the bytes do not parse. A
    parse failure is **derived evidence about the input**, not a defect of
    the receipt: emitting it as a fatal finding made an honestly-reported
    malformed record impossible to represent, contradicting the whole point
    of a source-oriented receipt (round 8). So the derived outcome is joined
    against the receipt's own acknowledgement:

      acknowledged correctly  -> receipt valid; the ERR carries the record
                                 into exclusions, exactly like ID_UNSOUND
      missing or wrong        -> RECORD_UNREADABLE_UNREPORTED
      claimed but bytes parse -> SPURIOUS_RECORD_UNREADABLE

    `loaded` stays true throughout: the bytes were obtained.
    """
    try:
        raw = cas_resolve(cas, src["entry_digest"])
    except (KeyError, SealViolation):
        _f(f, "RECORD_UNRESOLVABLE", at)
        return None
    obj, _pf = parse_strict(raw)
    # `parse_strict` can hand back a decoded object TOGETHER with a finding,
    # so testing `obj` alone laundered rejected bytes into a projected
    # evidence node (round 9). Readability therefore requires an empty
    # finding list — with exactly one documented exception.
    #
    # NOT_CANONICAL is not fatal for a Warrant record envelope, because
    # Warrant does not require one: `WarrantID = SHA-256(canonical_json(body))`
    # and "the envelope is not hashed" (warrant SPEC §4, §5.1 migration note),
    # and that store's only writer emits `json.dumps(env, indent=2,
    # sort_keys=True)` — every real record file on disk is pretty-printed,
    # including the vendored upstream example. Treating envelope
    # canonicality as mandatory would not harden SEV; it would make it unable
    # to read any genuine Warrant store. Canonicality still binds where the
    # format binds it: the body is re-canonicalized when the WarrantID is
    # re-derived, and each reason when its digest is checked.
    # Structural, and labelled unisolatable: today NOT_CANONICAL is the ONLY
    # code `parse_strict` returns beside a decoded object, so with it exempt
    # no vector can distinguish this list from the old `obj is not None`
    # test. It is written as a list anyway, because the laundering was a
    # property of the shape of the check, not of the code that happened to
    # take that path.
    fatal = [x for x in _pf if x["code"] != "NOT_CANONICAL"]
    parsed_ok = isinstance(obj, dict) and not fatal
    # Warrant's own verifier enforces the top-level shape outright —
    # `if set(env) != {"body", "sigs"}: ERR envelope must be {body, sigs}`
    # (impl/warrant.py:1271). Deriving readability from decodability alone
    # let a pretty-printed envelope carrying an attacker-controlled extra
    # member become an evidence node here while that verifier rejects it
    # (round 10). The shape is derived, then joined with acknowledgement
    # exactly like a parse failure.
    envelope_ok = parsed_ok and set(obj.keys()) == {"body", "sigs"}
    # One join for both branches, and it must match the LOCATOR too: keying
    # on code+severity alone let an issue pointing at `.warrants/blobs/p`
    # acknowledge a defect in a different record — the receipt validated,
    # the projection emitted, and `exclusions[]` carried the wrong
    # coordinate as evidence (round 11).
    acknowledged = _acknowledges(issues, "RECORD_UNREADABLE", src["path"])
    envelope_acked = _acknowledges(issues, "MALFORMED_ENVELOPE", src["path"])
    if parsed_ok and not envelope_ok:
        if not envelope_acked:
            _f(f, "MALFORMED_ENVELOPE_UNREPORTED", at)
        elif src.get("computed_wid") is not None or src.get("id_sound") is not False:
            _f(f, "UNREADABLE_WITH_IDENTITY_CLAIM", at)
        return None
    if envelope_ok and envelope_acked:
        _f(f, "SPURIOUS_MALFORMED_ENVELOPE", at)
    if not parsed_ok:
        if not acknowledged:
            _f(f, "RECORD_UNREADABLE_UNREPORTED", at)
        else:
            # An unparseable body has no derivable identity; leaving a WID
            # behind would be an unverifiable residue over bytes nobody can
            # read. Exclusion makes it harmless today, but the rule is
            # cheaper than the exception.
            if src.get("computed_wid") is not None or src.get("id_sound") is not False:
                _f(f, "UNREADABLE_WITH_IDENTITY_CLAIM", at)
        return None
    if acknowledged:
        _f(f, "SPURIOUS_RECORD_UNREADABLE", at)
    return obj


def _resolve_reason(f, obj, reason, rat):
    """ptr must resolve inside the committed record bytes and hash to
    reason_digest — the byte-level half of the reason contract. `obj` is the
    envelope already parsed by _resolve_record (one CAS read per source)."""
    if not isinstance(obj, dict):
        _f(f, "REASON_PTR_UNRESOLVABLE", rat)
        return
    body = obj.get("body")
    because = body.get("because") if isinstance(body, dict) else None
    idx = int(reason["ptr"].rsplit("/", 1)[1])
    if not (isinstance(because, list) and idx < len(because)):
        _f(f, "REASON_PTR_UNRESOLVABLE", rat)
        return
    committed = because[idx]
    try:
        if sha256_hex(jcs(committed)) != reason["reason_digest"]:
            _f(f, "REASON_DIGEST_MISMATCH", rat)
            return
    except ValueError:
        _f(f, "REASON_DIGEST_MISMATCH", rat)
        return
    # The digest alone proves the bytes, not that the receipt's role fields
    # describe them: a receipt could carry runtime "evil@v1" over a committed
    # ski@v1 reason and the graph would assert the swap (round-6 PR review).
    if not isinstance(committed, dict):
        _f(f, "REASON_ROLE_MISMATCH", rat)
        return
    if (committed.get("kind") != reason["kind"]
            or committed.get("runtime") != reason["runtime"]):
        _f(f, "REASON_ROLE_MISMATCH", rat)
        return
    if committed.get("verdict") != reason["outcome"].get("claimed_verdict"):
        _f(f, "REASON_CLAIM_MISMATCH", rat)
    # Matching the bytes is not the same as being NORMATIVELY ALLOWED to be a
    # check: `kind` and `runtime` were only string-compared, so a committed
    # prose reason — or a committed check under an attacker-named runtime the
    # receipt also declared in execution_policy — became a sigma:CheckRun.
    # warrant SPEC §3 closes both: only `check` reasons carry a runtime, and
    # the runtime registry is keyed by BODY version.
    if committed.get("kind") != "check":
        _f(f, "REASON_NOT_A_CHECK", rat)
        return
    version = body.get("warrant") if isinstance(body, dict) else None
    allowed = RUNTIME_REGISTRY.get(version)
    if allowed is None:
        _f(f, "UNKNOWN_BODY_VERSION", rat)
    elif committed.get("runtime") not in allowed:
        _f(f, "RUNTIME_NOT_IN_REGISTRY", rat)


# ------------------------------------------------- composed public verdict

def available_blob_digests(core) -> set:
    """Digests a check reference may legitimately resolve to.

    Not "some source has this digest": the source must BE a blob, be loaded,
    and carry no ERR judgement — otherwise a check could resolve to a README
    (`other`), to a record, or to a blob the manifest simultaneously reports
    as excluded, with the run claiming it used exactly that (re-gate P1-2).
    One definition, used by both the verdict and the projection."""
    out = set()
    if not isinstance(core, dict) or not isinstance(core.get("sources"), list):
        return out
    for s in core["sources"]:
        if not isinstance(s, dict) or s.get("kind") != "blob":
            continue
        if s.get("loaded") is not True:
            # Defense in depth, and honestly labelled as such: no vector can
            # isolate this clause today, because `loaded:false` already
            # requires an ERR issue (UNLOADED_WITHOUT_ERR) and the clause
            # below fires first. Removing it currently changes nothing —
            # mutation-tested and stated rather than counted as covered.
            continue
        issues = s.get("issues")
        if isinstance(issues, list) and any(
                isinstance(x, dict) and x.get("severity") == "ERR" for x in issues):
            continue
        if isinstance(s.get("entry_digest"), str):
            out.add(s["entry_digest"])
    return out


class _NotFreezable(Exception):
    """Raised instead of silently sharing an object with the caller."""


MAX_FREEZE_DEPTH = 64          # these contracts are shallow by construction
MAX_FREEZE_NODES = 1000000     # every visited value AND every key is a node
MAX_FREEZE_BYTES = 67108864    # 64 MiB of string payload; node count alone
                               # bounds shape, not memory


def _freeze(value, _depth=0, _active=None, _budget=None):
    """A private detached copy, built from exact JSON built-ins only.

    Never returns the original: the earlier version fell back to the input
    when `deepcopy` raised, so isolation opened for exactly the hostile
    inputs it exists for. Exact `type(x) is …` checks (not `isinstance`)
    reject subclasses, the usual carrier of read-dependent behaviour.

    Total by construction: exact `dict`/`list` values can still be cyclic or
    deeper than the interpreter's recursion limit, and a `RecursionError`
    escaping `project()` is a crash where the contract promises bounded
    findings. Cycles are detected on the active path and depth/node budgets
    are explicit; every refusal becomes `INPUT_NOT_FREEZABLE`.
    """
    if _active is None:
        _active, _budget = set(), [MAX_FREEZE_NODES, MAX_FREEZE_BYTES]
    # Charge BEFORE the primitive return: charging only containers made a
    # million-element scalar list cost one node, so the declared ceiling
    # never fired. Nodes bound shape; the byte budget bounds payload, which
    # a node count alone cannot.
    _budget[0] -= 1
    if _budget[0] < 0:
        raise _NotFreezable("over node budget")
    t = type(value)
    if t is str:
        _budget[1] -= len(value.encode("utf-8", "surrogatepass"))
        if _budget[1] < 0:
            raise _NotFreezable("over byte budget")
        return value
    if value is None or t is bool or t is int:
        return value
    if t is not list and t is not dict:
        raise _NotFreezable(repr(t))
    if _depth >= MAX_FREEZE_DEPTH:
        raise _NotFreezable("over depth budget")
    ident = id(value)
    if ident in _active:
        # Defense in depth, labelled as unisolatable: with this clause removed
        # a cycle still terminates on the depth budget above, so no vector can
        # distinguish the two today. It is kept because it gives the precise
        # reason and because it stays load-bearing if the depth budget is ever
        # raised. Mutation-tested and stated, not counted as covered.
        raise _NotFreezable("cyclic container")
    _active.add(ident)
    try:
        if t is list:
            return [_freeze(v, _depth + 1, _active, _budget) for v in value]
        out = {}
        for k, v in value.items():
            if type(k) is not str:
                raise _NotFreezable("non-string key")
            # Keys are nodes and their bytes count too. Unisolatable by a
            # vector today: any object wide enough to exhaust the budget
            # through keys alone exhausts it through values first, since a
            # dict entry always carries both. Kept so the accounting rule is
            # complete and stated, not counted as covered.
            _freeze(k, _depth + 1, _active, _budget)
            out[k] = _freeze(v, _depth + 1, _active, _budget)
        return out
    finally:
        _active.discard(ident)


def verify_receipt_bytes(snapshot_raw, receipt_raw, cas, expected_version="0.4",
                         view=None) -> list:
    """THE public verdict. Takes **bytes**, not objects.

    An object-taking entry point cannot see byte-level facts at all: by the
    time a caller holds a dict, duplicate member names are already collapsed,
    trailing data is gone, a BOM is gone, non-canonical spacing is gone. A
    public verdict that accepts objects therefore lets a caller obtain a
    clean result over bytes the format rejects — not by lying, but by never
    having been shown them. So the bytes are the interface, and the object
    path below is internal (round 13).
    """
    if view is not None and type(view) is not dict:
        # before anything else, and never `isinstance`: a dict subclass can
        # override .clear()/.update(), so touching a wrong sink on the
        # refusal path executed caller code inside the verdict (round 14)
        return [{"code": "BAD_VIEW_SINK", "severity": "ERR", "at": "/"}]
    findings = []
    snap, sf = parse_strict(snapshot_raw)
    for x in sf:
        findings.append({"code": x["code"], "severity": "ERR", "at": "/snapshot"})
    rec, rf = parse_strict(receipt_raw)
    for x in rf:
        findings.append({"code": x["code"], "severity": "ERR", "at": "/receipt"})
    if findings:
        if view is not None:
            view.clear()
        return findings
    return _verdict_over_objects(snap, rec, cas, expected_version, view)


def validate_structure_only(snapshot, receipt, expected_version="0.4") -> list:
    """Shape-only inspection with NO evidence bytes. Deliberately named so it
    can never be mistaken for verification: record identity, envelope
    completeness and reason binding are all byte-derived and are simply not
    performed here. Its clean result means "nothing structurally wrong",
    never "verified"."""
    return _verdict(snapshot, receipt, None, expected_version, {},
                    structural_only=True)


def _verdict_over_objects(snapshot, receipt, cas, expected_version="0.4",
                          view=None) -> list:
    """THE public verdict tying receipt to snapshot: descriptor lookup, role
    check, exact universe<->sources bijection, per-source digests, then the
    internal core invariants. Total over any parsed JSON values.

    `view` is an OUTPUT SINK ONLY. It receives a copy of the validated view
    after the verdict and is never read during it: making the freeze and the
    committed-reason derivation conditional on it let a caller change the
    verdict by asking (or not asking) for diagnostics — with `view=None` an
    impossible `matched` over a missing check blob was accepted, and the
    input isolation was skipped entirely (core re-gate P1).
    """
    if view is not None and type(view) is not dict:
        # a sink of the wrong type is a caller error, and guessing at it
        # (duck-typing `.clear`/`.update`) would run caller code inside the
        # verdict — fail closed instead (round 13)
        return [{"code": "BAD_VIEW_SINK", "severity": "ERR", "at": "/"}]
    internal = {}
    findings = _verdict(snapshot, receipt, cas, expected_version, internal)
    if view is not None:
        # A REFUSED verdict publishes nothing. Publishing a partial view
        # beside findings invites a consumer to read state the verdict did
        # not stand behind; clearing also stops a reused sink keeping keys
        # from an earlier, successful run.
        view.clear()
        if not findings:
            view.update(internal)
    return findings


def _verdict(snapshot, receipt, cas, expected_version, view,
             structural_only=False) -> list:
    # Absence of evidence bytes is not evidence of correctness. Every
    # byte-derived check — WarrantID re-derivation, envelope signature and
    # reason completeness, the semantic reason binding — is skipped without a
    # store, so a clean result would mean "nothing could be checked" while
    # reading as "verified" (core re-gate P1).
    if cas is None and not structural_only:
        view.clear()
        return [{"code": "CAS_REQUIRED", "severity": "ERR", "at": "/"}]
    # Freeze the inputs BEFORE judging them, unconditionally.
    try:
        snapshot = _freeze(snapshot)
        receipt = _freeze(receipt)
    except (_NotFreezable, RecursionError):
        # Fail closed: an input that cannot be detached is refused, never
        # judged-then-shared. The view stays empty, so no consumer can
        # mistake a partial freeze for a validated one.
        view.clear()
        return [{"code": "INPUT_NOT_FREEZABLE", "severity": "ERR", "at": "/"}]
    view["snapshot"] = snapshot
    view["receipt"] = receipt

    f = list(validate_snapshot(snapshot, cas))
    if not isinstance(receipt, dict):
        _f(f, "NOT_OBJECT", "/receipt")
        return f
    if receipt.get("receipt") != "warrant.verification-receipt@v0":
        _f(f, "BAD_TYPE_TAG", "/receipt")
        return f
    if set(receipt.keys()) != {"receipt", "core", "producer"}:
        _f(f, "SCHEMA_KEYS", "/receipt")
        return f
    # `producer` is host-local — it carries no cross-implementation
    # agreement — but "host-local" means "outside consensus identity", not
    # "without a wire contract". A closed schema is claimed, so it is
    # enforced (P2).
    producer = receipt["producer"]
    if not (isinstance(producer, dict)
            and set(producer.keys()) == {"impl", "artifact_digest", "spec",
                                         "report_digest", "local_notes"}
            and isinstance(producer["impl"], str) and producer["impl"]
            and (producer["artifact_digest"] is None
                 or _is_hex64(producer["artifact_digest"]))
            and isinstance(producer["spec"], str) and producer["spec"]
            and _is_hex64(producer["report_digest"])
            and isinstance(producer["local_notes"], list)
            and all(isinstance(n, str) for n in producer["local_notes"])):
        _f(f, "BAD_PRODUCER_SCHEMA", "/producer")

    core = receipt["core"]
    core_f = validate_receipt_core(core, cas=cas, view=view)
    f.extend(core_f)
    if not isinstance(core, dict) or not isinstance(snapshot, dict):
        return f

    wrapper = None
    for w in snapshot.get("subroots", []) if isinstance(snapshot.get("subroots"), list) else []:
        if isinstance(w, dict) and w.get("digest") == core.get("subroot_descriptor_digest"):
            wrapper = w
            break
    if wrapper is None:
        _f(f, "RECEIPT_DESCRIPTOR_MISSING", "/core/subroot_descriptor_digest")
        return f
    descriptor = {k: v for k, v in wrapper.items() if k != "digest"}
    view["descriptor"] = descriptor
    view["core"] = core
    f.extend(validate_warrant_descriptor_role(descriptor, expected_version))

    universe = descriptor.get("universe")
    if not isinstance(universe, list):
        return f
    # Bijection over PAIRS, not a dict keyed by path: building `want`/`have`
    # as dicts made a duplicate path last-wins, so a receipt could carry a
    # forged source beside the real one and still look bijective — the graph
    # then asserted a blob absent from the snapshot (re-gate P1-1).
    want = set()
    for e in universe:
        if isinstance(e, dict) and isinstance(e.get("path"), str):
            want.add((e["path"], e.get("sha256")))
    have = set()
    seen_paths = set()
    for s in core.get("sources", []) if isinstance(core.get("sources"), list) else []:
        if not (isinstance(s, dict) and isinstance(s.get("path"), str)):
            continue
        if s["path"] in seen_paths:
            _f(f, "DUPLICATE_SOURCE_PATH", s["path"])
        seen_paths.add(s["path"])
        have.add((s["path"], s.get("entry_digest")))
    want_paths = {p for p, _d in want}
    have_paths = {p for p, _d in have}
    for path in sorted(want_paths - have_paths, key=path_sort_key):
        _f(f, "SOURCE_MISSING_FOR_MEMBER", path)
    for path in sorted(have_paths - want_paths, key=path_sort_key):
        _f(f, "SOURCE_NOT_IN_UNIVERSE", path)
    for path, digest in sorted(have - want, key=lambda pd: path_sort_key(pd[0])):
        if path in want_paths:
            _f(f, "SOURCE_DIGEST_MISMATCH", path)

    # Role classification: `kind` was only enum-checked, so a receipt could
    # relabel a committed record as "other" (record vanishes, graph asserts a
    # generic entity) or a blob as "genesis" — the receipt choosing what the
    # graph asserts or omits. The store layout DERIVES the role; the receipt
    # only reports it, and disagreement is a finding.
    prefix = descriptor.get("prefix")
    if not isinstance(prefix, str):
        return f
    for s in core.get("sources", []) if isinstance(core.get("sources"), list) else []:
        if not (isinstance(s, dict) and isinstance(s.get("path"), str)):
            continue
        path = s["path"]
        if path not in want_paths:
            continue  # already reported as SOURCE_NOT_IN_UNIVERSE
        derived_kind, derived_wid = classify_warrant_source(path, prefix)
        if s.get("kind") != derived_kind:
            _f(f, "SOURCE_KIND_MISMATCH", path)
        elif derived_kind == "record" and s.get("claimed_wid") != derived_wid:
            # claimed_wid is a *claim read off the filename*, not free text
            _f(f, "CLAIMED_WID_NOT_PATH", path)

    # A re-execution that RAN must have had its check blob to run: warrant
    # SPEC §6 resolves the check as a blob, and §6(7) keeps "re-ran" and
    # "could not run" observationally distinct. Claiming matched/mismatched
    # over a blob absent from this subroot is an impossible verdict.
    present = available_blob_digests(core)
    committed_by_path = view.get("committed", {})
    for s in core.get("sources", []) if isinstance(core.get("sources"), list) else []:
        if not (isinstance(s, dict) and s.get("kind") == "record"):
            continue
        because = committed_by_path.get(s.get("path"), [])
        for reason in s.get("reasons", []) if isinstance(s.get("reasons"), list) else []:
            if not isinstance(reason, dict):
                continue
            outcome = reason.get("outcome")
            if not isinstance(outcome, dict) or outcome.get("re_execution") not in (
                    "matched", "mismatched"):
                continue
            try:
                idx = int(str(reason.get("ptr", "")).rsplit("/", 1)[1])
            except (ValueError, IndexError):
                continue
            committed = because[idx] if idx < len(because) else None
            if isinstance(committed, dict) and committed.get("check") not in present:
                _f(f, "CHECK_BLOB_ABSENT", "%s%s" % (s.get("path"), reason.get("ptr")))
    return f


def classify_warrant_source(path, prefix):
    """(kind, claimed_wid) derived from the Warrant store layout alone.

    `records/<hex64>.json` → record with that WarrantID claim; a non-wid-shaped
    name in `records/` is still a record, with a null claim. `blobs/*` → blob,
    `genesis.json` → genesis, anything else under the prefix → other.
    """
    if not path.startswith(prefix):
        return "other", None
    rest = path[len(prefix):]
    if rest == "genesis.json":
        return "genesis", None
    if rest.startswith("records/"):
        name = rest[len("records/"):]
        stem = name[:-len(".json")] if name.endswith(".json") else None
        return "record", (stem if _is_hex64(stem) else None)
    if rest.startswith("blobs/"):
        return "blob", None
    return "other", None


# ------------------------------------------------------------------ harness

FAILURES = []


def _record(name, ok, detail=""):
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  (%s)" % detail) if detail else ""))
    if not ok:
        FAILURES.append(name)


def check_true(name, fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        _record(name, False, "unexpected %r" % exc)
        return
    _record(name, result is True, "" if result is True else "returned %r" % (result,))


def check_equal(name, got, expected):
    _record(name, got == expected, "" if got == expected else "%r != %r" % (got, expected))


def check_raises(name, exc_type, code, fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        ok = isinstance(exc, exc_type) and getattr(exc, "code", None) == code
        _record(name, ok, "refused: %s" % exc if ok else "wrong refusal %r" % exc)
        return
    _record(name, False, "accepted what must be refused")


def check_codes(name, findings, expected_codes):
    got = sorted(x["code"] for x in findings)
    check_equal(name, got, sorted(expected_codes))


def check_has(name, findings, *codes):
    got = {x["code"] for x in findings}
    missing = [c for c in codes if c not in got]
    _record(name, not missing, "" if not missing else "missing %s in %s" % (missing, sorted(got)))


# ------------------------------------------------------------------ fixtures

def signature_issues(entries):
    """The WARN occurrences an honest receipt owes for signatures it reports
    as not verifying. Fixture signatures here are synthetic placeholders, so
    claiming they verified would assert what this repo cannot back."""
    return [{"code": "INVALID_SIGNATURE", "severity": "WARN",
             "at": {"kind": "json-pointer", "value": "/sigs/%d" % e[4]}}
            for e in entries]


def _fixture():
    """A fully valid (snapshot, receipt, cas) triple the mutation vectors edit."""
    check_bytes = b"policy"           # the blob sealed at .warrants/blobs/p
    reason_obj = {"kind": "check", "runtime": "ski@v1",
                  "check": sha256_hex(check_bytes),
                  "verdict": "pass", "transcript": "b" * 64}
    # body "warrant": "0.2" is the BODY-FORMAT version (ski@v1 era), while the
    # contract version "0.4" below is the SPEC document revision — warrant
    # versions bodies and the document independently (SPEC "Versioning").
    record = {"body": {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64},
                       "under": ["b" * 64], "because": [reason_obj], "evidence": [],
                       "actor": {"id": "x"}, "prior": [], "ts": 1},
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    record_bytes = jcs(record)
    blob_bytes = b"policy"
    note_bytes = b"note"
    files = {".warrants/records/r.json": record_bytes, ".warrants/blobs/p": blob_bytes}
    cas = {sha256_hex(v): v for v in list(files.values()) + [note_bytes]}
    uni = seal_universe(files)
    contract = {"name": "warrant", "version": "0.4", "spec_digest": sha256_hex(b"spec")}
    d = subroot_descriptor("warrant", contract, ".warrants/", uni)
    snap = snapshot_object([d], [{"path": "notes.txt", "sha256": sha256_hex(note_bytes)}])
    dig = subroot_descriptor_digest(d)
    by_path = {e["path"]: e["sha256"] for e in uni}
    reason_digest = sha256_hex(jcs(reason_obj))
    sources = [
        {"kind": "blob", "path": ".warrants/blobs/p",
         "entry_digest": by_path[".warrants/blobs/p"], "loaded": True, "issues": []},
        {"kind": "record", "path": ".warrants/records/r.json",
         "entry_digest": by_path[".warrants/records/r.json"], "loaded": True,
         "claimed_wid": None, "computed_wid": sha256_hex(jcs(record["body"])),
         "id_sound": False, "settlement": [],
         # the receipt must account for every signature the envelope carries
         "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                         "key": k, "valid": False, "binding": "unverified"}
                        for d, m, a, k, _i in envelope_signature_entries(record)[0]],
         "issues": sorted(
             [{"code": "ID_UNSOUND", "severity": "ERR",
               "at": {"kind": "path", "value": ".warrants/records/r.json"}},
              {"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
               "at": {"kind": "path", "value": ".warrants/records/r.json"}}]
             + signature_issues(envelope_signature_entries(record)[0]),
             key=lambda x: jcs(x)),
         "reasons": [{"ptr": "/because/0", "kind": "check", "runtime": "ski@v1",
                      "reason_digest": reason_digest,
                      "outcome": {"re_execution": "matched", "claimed_verdict": "pass",
                                  "observed_verdict": "pass",
                                  "observed_result": "e" * 64, "atp_spent": 7,
                                  "failure_code": None}}]},
    ]
    core = {"subroot_descriptor_digest": dig, "grade": "base",
            "trust_config_digest": None,
            "execution_policy": {"runtimes": [
                {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                 "semantics_digest": sha256_hex(b"book1"), "budget_unit": "atp",
                 "ceiling": 1000}]},
            "ok": False, "errors": 2,
            "warnings": len(envelope_signature_entries(record)[0]),
            "global_issues": [],
            "sources": sources}
    receipt = {"receipt": "warrant.verification-receipt@v0", "core": core,
               "producer": {"impl": "model", "artifact_digest": None, "spec": "0.4",
                            "report_digest": "f" * 64, "local_notes": []}}
    return snap, receipt, cas


def _mutate(receipt, fn):
    r = json.loads(json.dumps(receipt))
    fn(r)
    return r


def _verify_objects(snapshot, receipt, cas=None, expected_version="0.4", view=None):
    """Vector-side helper: serialize to canonical bytes and go through the
    public byte verdict, so no vector can exercise a path a caller cannot."""
    try:
        raw_s, raw_r = jcs(snapshot), jcs(receipt)
    except (ValueError, RecursionError):
        # unserializable inputs are exactly what the freeze layer refuses
        return _verdict_over_objects(snapshot, receipt, cas, expected_version, view)
    return verify_receipt_bytes(raw_s, raw_r, cas, expected_version, view)


# ------------------------------------------------------------------ vectors

def run_vectors():
    # --- paths & prefixes (kept)
    for bad, code in [("/e", "ABSOLUTE_PATH"), ("a/../b", "DOT_COMPONENT"),
                      ("a//b", "EMPTY_COMPONENT"), ("a\\b", "BACKSLASH_IN_PATH"),
                      ("a\x00b", "NUL_IN_PATH"), ("", "EMPTY_PATH")]:
        check_raises("path refuses %r as %s" % (bad, code), PathViolation, code,
                     lambda bad=bad: validate_logical_path(bad))
    check_raises("prefix refuses empty", PathViolation, "EMPTY_PREFIX",
                 lambda: validate_prefix(""))
    check_raises("prefix refuses '.x'", PathViolation, "PREFIX_WITHOUT_SLASH",
                 lambda: validate_prefix(".x"))
    check_true("'.x/' does not capture '.xyz/a'", lambda: not path_in_prefix(".xyz/a", ".x/"))
    import unicodedata
    nfc = unicodedata.normalize("NFC", "café.txt")
    nfd = unicodedata.normalize("NFD", nfc)
    check_true("NFC/NFD are distinct valid paths",
               lambda: validate_logical_path(nfc) == nfc
               and validate_logical_path(nfd) == nfd and nfc != nfd)
    bmp, astral = "/x", "\U00010000/x"
    check_true("UTF-16 order: U+10000 before U+E000; codepoint order disagrees",
               lambda: path_sort_key(astral) < path_sort_key(bmp) and bmp < astral)

    # --- raw-byte parsers
    good = jcs({"a": 1})
    check_true("parse_strict accepts canonical bytes",
               lambda: parse_strict(good) == ({"a": 1}, []))
    for raw, code in [(b'{"a":1,"a":2}', "DUPLICATE_MEMBER"),
                      (b'{"a":1} trailing', "TRAILING_DATA"),
                      (b'{"a":NaN}', "NOT_I_JSON"),
                      (b'{"a":1.5}', "NOT_I_JSON"),
                      (b'{"a": 1}', "NOT_CANONICAL"),
                      (b'\xff\xfe', "NOT_UTF8"),
                      (b'\xef\xbb\xbf{}', "BOM_PRESENT"),
                      (b'{"a":"\\ud800"}', "LONE_SURROGATE")]:
        obj, f = parse_strict(raw)
        check_has("parse_strict refuses %s" % code, f, code)

    # the byte layer is depth-bounded, like the freeze layer
    check_equal("deeply nested JSON refuses instead of crashing",
                [x["code"] for x in parse_strict(b"[" * 500 + b"]" * 500)[1]],
                ["OVER_DEPTH"])
    check_equal("...and so does a deep object",
                [x["code"] for x in parse_strict(
                    b'{"a":' * 300 + b"1" + b"}" * 300)[1]],
                ["OVER_DEPTH"])
    check_true("jcs itself refuses over-deep values",
               lambda: _ve(lambda: jcs(_deep_list(MAX_FREEZE_DEPTH + 5))))

    # --- total validators on hostile shapes (Codex round-5 crashers)
    hostile = [None, 7, "x", [], [7],
               {"snapshot": "ecosystem.snapshot@v0", "bundle_root": None,
                "subroots": None, "unclaimed": None, "closed": None},
               {"snapshot": "ecosystem.snapshot@v0", "bundle_root": ZERO64,
                "subroots": [7], "unclaimed": [7], "closed": True},
               {"snapshot": "ecosystem.snapshot@v0", "bundle_root": ZERO64,
                "subroots": [{"subroot": "ecosystem.subroot@v0", "protocol": 7,
                              "contract": 7, "prefix": 7, "universe": 7,
                              "digest": "a" * 64}],
                "unclaimed": [], "closed": True}]

    def _no_crash():
        for v in hostile:
            validate_snapshot(v)
            validate_snapshot(v, {})
            validate_receipt_core(v)
            _verify_objects(v, v, {})
            _verify_objects({}, {"receipt": "warrant.verification-receipt@v0",
                                          "core": v, "producer": {}}, {})
        return True
    check_true("hostile shapes -> findings, never exceptions", _no_crash)

    # --- fixture is fully green end-to-end
    snap, receipt, cas = _fixture()
    check_codes("fixture snapshot valid", validate_snapshot(snap, cas), [])
    # round 13 (1): the public verdict takes BYTES; duplicate members cannot
    # be laundered by handing the validator an already-parsed object
    _raw_s, _raw_r = jcs(snap), jcs(receipt)
    check_equal("the byte verdict accepts the fixture",
                verify_receipt_bytes(_raw_s, _raw_r, cas), [])
    check_equal("a duplicate member in the receipt bytes is refused",
                [x["code"] for x in verify_receipt_bytes(
                    _raw_s, _raw_r[:-1] + b',"core":1}', cas)],
                ["DUPLICATE_MEMBER"])
    check_equal("...and in the snapshot bytes",
                [x["code"] for x in verify_receipt_bytes(
                    _raw_s[:-1] + b',"closed":false}', _raw_r, cas)],
                ["DUPLICATE_MEMBER"])
    check_true("trailing data and a BOM are refused at the same boundary",
               lambda: [x["code"] for x in verify_receipt_bytes(
                   _raw_s, _raw_r + b" x", cas)] == ["TRAILING_DATA"]
               and [x["code"] for x in verify_receipt_bytes(
                   b"\xef\xbb\xbf" + _raw_s, _raw_r, cas)] == ["BOM_PRESENT"])

    # round 13 (6): a refused verdict publishes nothing; a wrong sink fails closed
    _sink = {}
    verify_receipt_bytes(_raw_s, _raw_r[:-1] + b',"core":1}', cas, view=_sink)
    check_equal("a refused byte verdict publishes no view", _sink, {})
    check_equal("a sink of the wrong type fails closed",
                [x["code"] for x in _verdict_over_objects(snap, receipt, cas,
                                                          view=[])],
                ["BAD_VIEW_SINK"])

    check_codes("fixture composed verdict valid",
                _verify_objects(snap, receipt, cas), [])
    check_true("fixture snapshot bytes canonical round-trip",
               lambda: parse_snapshot(jcs(snap), cas)[1] == [])

    # --- role confusion & stale digest (kept, via total validator)
    files = {".x/a": b"1"}
    uni = seal_universe(files)
    cw = {"name": "warrant", "version": "0.4", "spec_digest": sha256_hex(b"s")}
    d_w = subroot_descriptor("warrant", cw, ".x/", uni)
    d_o = subroot_descriptor("oaip", {"name": "oaip", "version": "0.1",
                                      "spec_digest": None}, ".x/", uni)
    check_true("rev1 bare roots collide; rev2 descriptor digests differ",
               lambda: legacy_rev1_root(uni) == legacy_rev1_root(list(uni))
               and subroot_descriptor_digest(d_w) != subroot_descriptor_digest(d_o))
    stale = json.loads(json.dumps(snap))
    stale["subroots"][0]["digest"] = "f" * 64
    stale["bundle_root"] = sha256_hex(SNAPSHOT_DOMAIN + jcs(dict(stale, bundle_root=ZERO64)))
    check_true("stale digest passes outer hash; validator reports it",
               lambda: verify_bundle_root(stale)
               and any(x["code"] == "STALE_SUBROOT_DIGEST" for x in validate_snapshot(stale)))

    # --- ordering of snapshot arrays: reversed subroots
    d_b = subroot_descriptor("bos", {"name": "bos", "version": "0.4",
                                     "spec_digest": None}, ".b/",
                             seal_universe({".b/z": b"z"}))
    two = snapshot_object([d_w, d_b], [])
    rev = json.loads(json.dumps(two))
    rev["subroots"] = rev["subroots"][::-1]
    rev["bundle_root"] = sha256_hex(SNAPSHOT_DOMAIN + jcs(dict(rev, bundle_root=ZERO64)))
    check_codes("sorted subroots valid", validate_snapshot(two), [])
    check_has("reversed subroots -> SUBROOTS_NOT_SORTED",
              validate_snapshot(rev), "SUBROOTS_NOT_SORTED")

    # --- CAS covers unclaimed
    no_note_cas = {k: v for k, v in cas.items() if v != b"note"}
    check_has("missing unclaimed bytes -> CAS_UNRESOLVABLE",
              validate_snapshot(snap, no_note_cas), "CAS_UNRESOLVABLE")

    # --- partition (kept)
    p = snapshot_object([d_w], [{"path": ".x/a", "sha256": uni[0]["sha256"]}])
    check_has("partition violation found", validate_snapshot(p),
              "PARTITION_VIOLATION", "UNCLAIMED_INSIDE_PREFIX")

    # --- bijection: silent truncation is now a finding
    empty = _mutate(receipt, lambda r: r["core"].update(
        sources=[], errors=0, ok=True))
    check_has("empty sources vs populated universe -> truncation caught",
              _verify_objects(snap, empty, cas),
              "SOURCE_MISSING_FOR_MEMBER")
    extra = _mutate(receipt, lambda r: r["core"]["sources"].append(
        {"kind": "other", "path": "zzz", "entry_digest": "a" * 64,
         "loaded": True, "issues": []}))
    check_has("source outside universe -> SOURCE_NOT_IN_UNIVERSE",
              _verify_objects(snap, extra, cas), "SOURCE_NOT_IN_UNIVERSE")
    wrongd = _mutate(receipt, lambda r: r["core"]["sources"][0].update(
        entry_digest="9" * 64))
    check_has("wrong entry digest -> SOURCE_DIGEST_MISMATCH",
              _verify_objects(snap, wrongd, cas), "SOURCE_DIGEST_MISMATCH")

    # --- composed role check: null spec_digest refused IN the verdict
    d_null = subroot_descriptor("warrant", dict(cw, spec_digest=None), ".x/", uni)
    snap_null = snapshot_object([d_null], [])
    rec_null = _mutate(receipt, lambda r: r["core"].update(
        subroot_descriptor_digest=subroot_descriptor_digest(d_null), sources=[],
        errors=0, ok=True))
    check_has("composed verdict refuses null spec_digest",
              _verify_objects(snap_null, rec_null,
                                       {sha256_hex(b"1"): b"1"}),
              "SPEC_DIGEST_REQUIRED")

    # --- per-occurrence joins: two mismatches need two matching issues
    def _two_mismatch(r):
        src = r["core"]["sources"][1]
        m1 = json.loads(json.dumps(src["reasons"][0]))
        m1["outcome"].update(re_execution="mismatched", observed_verdict="fail")
        m2 = json.loads(json.dumps(m1))
        m2["ptr"] = "/because/1"
        src["reasons"] = [m1, m2]
        src["issues"].append({"code": "REASON_MISMATCH", "severity": "WARN",
                              "at": {"kind": "json-pointer", "value": "/because/0"}})
        src["issues"].sort(key=lambda x: jcs(x))
        r["core"].update(warnings=1)
    two_mm = _mutate(receipt, _two_mismatch)
    found = _verify_objects(snap, two_mm, cas)
    check_true("one issue cannot cover two mismatches",
               lambda: any(x["code"] == "MISMATCH_WITHOUT_WARN" for x in found))

    # --- domains: potato verdict, negative atp, over-ceiling
    potato = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(claimed_verdict="potato",
                                        observed_verdict="potato"))
    check_has("verdict outside enum -> BAD_VERDICT",
              _verify_objects(snap, potato, cas), "BAD_VERDICT")
    negatp = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(atp_spent=-999))
    check_has("negative atp -> BAD_ATP",
              _verify_objects(snap, negatp, cas), "BAD_ATP")
    overc = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                    ["outcome"].update(atp_spent=99999))
    check_has("atp above declared ceiling -> ATP_OVER_CEILING",
              _verify_objects(snap, overc, cas), "ATP_OVER_CEILING")
    badres = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(observed_result="x"))
    check_has("ski@v1 result not hex64 -> BAD_RESULT_SHAPE",
              _verify_objects(snap, badres, cas), "BAD_RESULT_SHAPE")

    # --- ptr resolution against CAS bytes
    badptr = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     .update(ptr="/because/7"))
    check_has("dangling ptr -> REASON_PTR_UNRESOLVABLE",
              _verify_objects(snap, badptr, cas), "REASON_PTR_UNRESOLVABLE")
    baddig = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     .update(reason_digest="9" * 64))
    check_has("wrong reason digest -> REASON_DIGEST_MISMATCH",
              _verify_objects(snap, baddig, cas), "REASON_DIGEST_MISMATCH")
    # the output sink must never change the verdict
    def _sinks_agree(sn, rc, cs):
        a = [x["code"] for x in _verify_objects(sn, rc, cs)]
        b = [x["code"] for x in _verify_objects(sn, rc, cs, view={})]
        sink = {}
        c = [x["code"] for x in _verify_objects(sn, rc, cs, view=sink)]
        return a == b == c
    check_true("view=None, view={} and a populated sink agree",
               lambda: _sinks_agree(snap, receipt, cas))
    # the case that actually exposed the defect: a matched reason whose
    # check blob is absent — decided only by the committed-reason derivation
    no_blob = _mutate(receipt, lambda r: r["core"]["sources"].pop(0))
    check_true("...including where the check-blob binding decides the verdict",
               lambda: _sinks_agree(snap, no_blob, cas)
               and any(x["code"] == "CHECK_BLOB_ABSENT"
                       for x in _verify_objects(snap, no_blob, cas)))

    # `loaded` is derived from the store, not chosen by the producer
    fake_unread = _mutate(receipt, lambda r: (
        r["core"]["sources"][1].update(loaded=False),
        r["core"]["sources"][1].__setitem__("issues", sorted(
            r["core"]["sources"][1]["issues"] + [
                {"code": "RECORD_UNREADABLE", "severity": "ERR",
                 "at": {"kind": "path", "value": r["core"]["sources"][1]["path"]}}],
            key=lambda x: jcs(x))),
        r["core"].update(ok=False, errors=r["core"]["errors"] + 1)))
    check_true("a fabricated 'unreadable' record over readable bytes is caught",
               lambda: any(x["code"] == "LOADED_MISREPORTED"
                           for x in _verify_objects(snap, fake_unread, cas)))

    # an honest inaccessible member: the store really lacks it
    partial_cas = {k: v for k, v in cas.items()
                   if k != receipt["core"]["sources"][1]["entry_digest"]}
    honest_absent = _mutate(receipt, lambda r: (
        r["core"]["sources"][1].update(loaded=False),
        r["core"]["sources"][1].__setitem__("issues", sorted(
            r["core"]["sources"][1]["issues"] + [
                {"code": "RECORD_UNREADABLE", "severity": "ERR",
                 "at": {"kind": "path", "value": r["core"]["sources"][1]["path"]}}],
            key=lambda x: jcs(x))),
        r["core"].update(ok=False, errors=r["core"]["errors"] + 1)))
    codes_absent = [x["code"] for x in
                    _verify_objects(snap, honest_absent, partial_cas)]
    check_true("a genuinely inaccessible member is accepted as unloaded",
               lambda: "LOADED_MISREPORTED" not in codes_absent)
    check_true("...and its absence is still reported",
               lambda: any(c in ("CAS_UNRESOLVABLE",) for c in codes_absent))

    # the mirror: claiming loaded over bytes the store does not have
    claim_loaded = _mutate(receipt, lambda r: None)
    check_true("claiming loaded over missing bytes is caught",
               lambda: any(x["code"] == "LOADED_MISREPORTED"
                           for x in _verify_objects(snap, claim_loaded,
                                                             partial_cas)))

    # a blob member gets the same treatment, not only records
    blob_lie = _mutate(receipt, lambda r: (
        r["core"]["sources"][0].update(loaded=False),
        r["core"]["sources"][0].__setitem__("issues", [
            {"code": "BLOB_UNREADABLE", "severity": "ERR",
             "at": {"kind": "path", "value": r["core"]["sources"][0]["path"]}}]),
        r["core"].update(ok=False, errors=r["core"]["errors"] + 1)))
    check_true("the rule covers blob/genesis/other members too",
               lambda: any(x["code"] == "LOADED_MISREPORTED"
                           for x in _verify_objects(snap, blob_lie, cas)))

    # producer is host-local but still has a wire contract
    for label, mutate in [
            ("a non-object producer", lambda r: r.update(producer=7)),
            ("an empty producer", lambda r: r.update(producer={})),
            ("an unknown producer member",
             lambda r: r["producer"].update(extra="x")),
            ("a malformed report digest",
             lambda r: r["producer"].update(report_digest="nope"))]:
        bad_prod = _mutate(receipt, mutate)
        check_true("producer schema: %s is refused" % label,
                   lambda bad_prod=bad_prod: any(
                       x["code"] == "BAD_PRODUCER_SCHEMA"
                       for x in _verify_objects(snap, bad_prod, cas)))

    # absence of evidence bytes is never a clean verdict
    resealed = _mutate(receipt, lambda r: None)
    reason2 = {"kind": "check", "runtime": "ski@v1",
               "check": sha256_hex(b"policy"), "verdict": "pass",
               "transcript": "b" * 64}
    body2 = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64}, "under": ["b" * 64],
             "because": [reason2], "evidence": [], "actor": {"id": "x"},
             "prior": [], "ts": 2}                      # ts 1 -> 2
    rec2 = {"body": body2,
            "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    files2 = {".warrants/records/r.json": jcs(rec2),
              ".warrants/blobs/p": b"policy"}
    cas2 = {sha256_hex(v): v for v in files2.values()}
    uni2 = seal_universe(files2)
    d2 = subroot_descriptor("warrant",
                            {"name": "warrant", "version": "0.4",
                             "spec_digest": sha256_hex(b"spec")},
                            ".warrants/", uni2)
    snap2 = snapshot_object([d2], [])
    resealed["core"]["subroot_descriptor_digest"] = subroot_descriptor_digest(d2)
    bp2 = {e["path"]: e["sha256"] for e in uni2}
    for src in resealed["core"]["sources"]:
        src["entry_digest"] = bp2[src["path"]]      # resealed, but the receipt
                                                    # keeps the OLD WarrantID
    check_equal("a resealed changed body is caught WITH evidence bytes",
                [x["code"] for x in
                 _verify_objects(snap2, resealed, cas2)
                 if x["code"] == "COMPUTED_WID_MISMATCH"],
                ["COMPUTED_WID_MISMATCH"])
    check_equal("...and omitting the store is refused, not accepted",
                [x["code"] for x in
                 _verify_objects(snap2, resealed, None)],
                ["CAS_REQUIRED"])
    check_true("...while an empty store reports the missing bytes",
               lambda: any(x["code"] in ("CAS_UNRESOLVABLE", "RECORD_UNRESOLVABLE")
                           for x in _verify_objects(snap2, resealed, {})))
    check_true("structural-only inspection is separately named",
               lambda: "CAS_REQUIRED" not in
               [x["code"] for x in validate_structure_only(snap2, resealed)])

    # a reused sink must not keep a previous successful view
    sink = {}
    _verify_objects(snap, receipt, cas, view=sink)
    check_true("a successful verdict populates the sink", lambda: "core" in sink)
    _verify_objects(snap, {"receipt": "nope"}, cas, view=sink)
    check_equal("a refused verdict leaves no stale view behind (byte path)",
                sink, {})

    class Uncopyable2(dict):
        def __deepcopy__(self, memo):
            raise RuntimeError("nope")
    _verdict_over_objects(snap, Uncopyable2(receipt), cas, view=sink)
    check_equal("a refused verdict leaves no stale view behind (object path)",
                sink, {})

    # the CAS failure path must not re-execute hostile code
    class HostileRepr(Exception):
        def __repr__(self):
            raise RuntimeError("repr is code")

    class ReprCAS(dict):
        def __getitem__(self, k):
            raise HostileRepr()

    class HostileBytes(bytes):
        def __bytes__(self):
            raise RuntimeError("__bytes__ is code")

    class SubclassCAS(dict):
        def __getitem__(self, k):
            return HostileBytes(b"x")

    for label, store in [("an exception with a hostile __repr__", ReprCAS(cas)),
                         ("a bytes subclass with a hostile __bytes__",
                          SubclassCAS(cas))]:
        check_true("CAS failure path is bounded: %s" % label,
                   lambda store=store: all(
                       isinstance(x, dict)
                       for x in _verify_objects(snap, receipt, store)))

    # the freeze is unconditional — the model suite must prove it too, not
    # only the projector's TOCTOU vectors
    class UncopyableReceipt(dict):
        def __deepcopy__(self, memo):
            raise RuntimeError("refuses to be copied")
    # the freeze guards the INTERNAL object path; the public byte path is
    # detached by construction, since bytes carry no caller objects at all
    check_equal("an uncopyable receipt is refused with no sink at all",
                [x["code"] for x in
                 _verdict_over_objects(snap, UncopyableReceipt(receipt), cas)],
                ["INPUT_NOT_FREEZABLE"])
    check_equal("...and identically with a sink",
                [x["code"] for x in
                 _verdict_over_objects(snap, UncopyableReceipt(receipt), cas,
                                       view={})],
                ["INPUT_NOT_FREEZABLE"])
    check_equal("...and the public byte path never sees a caller object",
                [x["code"] for x in
                 verify_receipt_bytes(jcs(snap), jcs(receipt), cas)],
                [])

    # the CAS boundary is bounded: a hostile resolver yields findings, not
    # host exceptions
    class RaisingCAS(dict):
        def __getitem__(self, k):
            raise RuntimeError("resolver failed")

    class StringCAS(dict):
        def __getitem__(self, k):
            return "not bytes"

    for label, store in [("a raising resolver", RaisingCAS(cas)),
                         ("a non-bytes value", StringCAS(cas))]:
        check_true("CAS boundary bounded: %s" % label,
                   lambda store=store: all(
                       isinstance(x, dict) for x in
                       _verify_objects(snap, receipt, store)))

    swapped = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                      .update(runtime="evil@v1"))
    check_has("runtime swapped over committed ski@v1 reason -> REASON_ROLE_MISMATCH",
              _verify_objects(snap, swapped, cas), "REASON_ROLE_MISMATCH")
    lied = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                   ["outcome"].update(claimed_verdict="fail", observed_verdict="fail"))
    check_has("claimed verdict differs from committed reason -> REASON_CLAIM_MISMATCH",
              _verify_objects(snap, lied, cas), "REASON_CLAIM_MISMATCH")

    # role derived from the store layout, not reported by the receipt
    check_equal("classifier: records/<wid>.json",
                classify_warrant_source(".w/records/%s.json" % ("a" * 64), ".w/"),
                ("record", "a" * 64))
    check_equal("classifier: non-wid record name claims nothing",
                classify_warrant_source(".w/records/notes.json", ".w/"),
                ("record", None))
    check_equal("classifier: blobs/genesis/other",
                [classify_warrant_source(".w/blobs/x", ".w/")[0],
                 classify_warrant_source(".w/genesis.json", ".w/")[0],
                 classify_warrant_source(".w/README", ".w/")[0]],
                ["blob", "genesis", "other"])

    def _relabel(r, idx, kind):
        s = r["core"]["sources"][idx]
        for k in list(s):
            if k not in SOURCE_BASE_KEYS:
                del s[k]
        s["kind"] = kind
    rec_as_other = _mutate(receipt, lambda r: _relabel(r, 1, "other"))
    check_has("committed record relabelled 'other' -> SOURCE_KIND_MISMATCH",
              _verify_objects(snap, rec_as_other, cas),
              "SOURCE_KIND_MISMATCH")
    blob_as_genesis = _mutate(receipt, lambda r: _relabel(r, 0, "genesis"))
    check_has("blob relabelled 'genesis' -> SOURCE_KIND_MISMATCH",
              _verify_objects(snap, blob_as_genesis, cas),
              "SOURCE_KIND_MISMATCH")
    wid_lie = _mutate(receipt, lambda r: r["core"]["sources"][1].update(
        claimed_wid="b" * 64, id_sound=False))
    check_has("claimed_wid not derived from the filename -> CLAIMED_WID_NOT_PATH",
              _verify_objects(snap, wid_lie, cas), "CLAIMED_WID_NOT_PATH")

    # --- grade-aware severity + settlement at base
    setl = [{"jurisdiction": "a" * 64, "active": True,
             "policies": [{"policy": "b" * 64, "threshold_satisfied": True}]}]
    at_base = _mutate(receipt, lambda r: r["core"]["sources"][1].update(settlement=setl))
    check_has("settlement[] at base grade -> SETTLEMENT_IN_BASE",
              _verify_objects(snap, at_base, cas), "SETTLEMENT_IN_BASE")

    def _unv(r, grade, active):
        src = r["core"]["sources"][1]
        src["reasons"][0]["outcome"].update(
            re_execution="unverified", observed_verdict=None, observed_result=None,
            atp_spent=None, failure_code="MISSING_BLOB")
        src["settlement"] = setl if active else []
        src["issues"].append({"code": "REASON_UNVERIFIED", "severity": "WARN",
                              "at": {"kind": "json-pointer", "value": "/because/0"}})
        src["issues"].sort(key=lambda x: jcs(x))
        r["core"].update(grade=grade, warnings=1,
                         trust_config_digest="c" * 64 if grade == "settlement" else None)
    base_unv = _mutate(receipt, lambda r: _unv(r, "base", False))
    check_true("base grade: unverified satisfied by WARN",
               lambda: not any(x["code"].startswith("UNVERIFIED_WITHOUT")
                               for x in _verify_objects(snap, base_unv, cas)))
    settle_unv = _mutate(receipt, lambda r: _unv(r, "settlement", True))
    check_has("settlement grade + active + WARN-only -> needs ERR",
              _verify_objects(snap, settle_unv, cas), "UNVERIFIED_WITHOUT_ERR")

    # --- locator union strictness
    for loc in [{"kind": "byte-range"}, {"kind": "json-pointer", "start": 7},
                {"kind": "path", "value": 5}, {"kind": "global", "value": "weird"},
                {"kind": "byte-range", "start": 9, "end": 3},
                {"kind": "json-pointer", "value": "/x", "extra": 1}]:
        check_true("locator refused: %s" % json.dumps(loc),
                   lambda loc=loc: validate_locator(loc) is False)
    check_true("locator accepts occurrence ordinal",
               lambda: validate_locator({"kind": "json-pointer", "value": "/sigs/3",
                                         "occurrence": 1}))

    # --- issue ordering + counts stay bound (kept)
    dup = _mutate(receipt, lambda r: r["core"]["sources"][1]["issues"].append(
        {"code": "ZZZ", "severity": "WARN",
         "at": {"kind": "global", "value": "store"}}))  # sorts BEFORE the existing issue
    check_has("unsorted issues -> ISSUES_NOT_SORTED; counts unbound",
              _verify_objects(snap, dup, cas),
              "ISSUES_NOT_SORTED", "WARNINGS_UNBOUND")

    # --- JCS bounds (kept)
    check_true("jcs refuses 10**100 and floats",
               lambda: _ve(lambda: jcs({"n": 10 ** 100})) and _ve(lambda: jcs({"x": 1.5})))

    # --- deterministic hostile fuzz over public validators
    rng = random.Random(0xC0DE)

    def gen(depth=0):
        r = rng.random()
        if depth > 3 or r < 0.25:
            return rng.choice([None, True, False, 0, -1, 7, "x", "", "a" * 64,
                               ZERO64, "ecosystem.snapshot@v0", 1.5, 10 ** 20])
        if r < 0.55:
            return [gen(depth + 1) for _ in range(rng.randrange(3))]
        keys = ["snapshot", "bundle_root", "subroots", "unclaimed", "closed",
                "receipt", "core", "producer", "sources", "issues", "kind",
                "path", "universe", "prefix", "contract", "digest", "x"]
        return {rng.choice(keys): gen(depth + 1) for _ in range(rng.randrange(4))}

    def _fuzz():
        for _ in range(300):
            a, b = gen(), gen()
            validate_snapshot(a, {})
            validate_receipt_core(a, cas={})
            _verify_objects(a, b, {})
        for _ in range(100):
            parse_strict(bytes(rng.randrange(256) for _ in range(rng.randrange(40))))
        return True
    check_true("fuzz: 300 hostile shapes + 100 random byte strings, no exceptions", _fuzz)


def _deep_list(depth):
    out = []
    cur = out
    for _ in range(depth):
        nxt = []
        cur.append(nxt)
        cur = nxt
    return out


def _ve(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def view_is_output_only():
    """The verdict must not depend on whether a view was requested.

    The view exists so consumers read the bytes the verdict was rendered
    over instead of the store. That makes it an OUTPUT, and the distinction
    is load-bearing: if any finding ever varied with `view`, the channel
    would have become an input, and every future extension of it (this round
    added the committed body for the §4.1 mapping) would be a silent change
    to a frozen contract. Asserted over a corpus rather than argued.
    """
    snap, receipt, cas = _fixture()
    raw_s, raw_r = jcs(snap), jcs(receipt)
    corpus = [
        ("valid", raw_s, raw_r),
        ("trailing data", raw_s, raw_r + b" x"),
        ("BOM", b"\xef\xbb\xbf" + raw_s, raw_r),
        ("truncated receipt", raw_s, raw_r[:-1]),
        ("receipt is not an object", raw_s, b"[]"),
        ("duplicate member", raw_s, raw_r[:-1] + b',"core":1}'),
        ("empty receipt", raw_s, b""),
        ("snapshot is a scalar", b"7", raw_r),
        ("lone surrogate", raw_s, raw_r[:-1] + b',"x":"\\ud800"}'),
    ]
    # Byte-boundary refusals return before the deep validator ever runs, and
    # they yield one finding each — so a corpus of only those tests almost
    # nothing about view-independence where it matters, and cannot observe
    # ORDER at all. These are structurally valid documents with semantic
    # defects: they reach `_verdict_over_objects` and produce several
    # findings apiece.
    def _semantic(mutate):
        obj = json.loads(raw_r.decode("utf-8"))
        mutate(obj)
        return jcs(obj)

    def _break_counts(o):
        o["core"]["errors"] = 99
        o["core"]["warnings"] = 99

    def _break_source(o):
        src = [s for s in o["core"]["sources"] if s["kind"] == "record"][0]
        src["id_sound"] = False
        src["loaded"] = False

    def _break_reason(o):
        src = [s for s in o["core"]["sources"] if s.get("reasons")][0]
        src["reasons"][0]["outcome"]["re_execution"] = "not-a-state"
        src["reasons"][0]["runtime"] = "nowhere@v9"

    def _break_all(o):
        _break_counts(o)
        _break_source(o)

    for label, mutate in (("bad counts", _break_counts),
                          ("unsound source", _break_source),
                          ("bad reason", _break_reason),
                          ("several at once", _break_all)):
        corpus.append(("semantic: " + label, raw_s, _semantic(mutate)))
    # Compared as JCS BYTES over the ordered finding list, not as a list of
    # codes. A finding is `code`, `severity` and `at`, and comparing only the
    # first would let ERR→WARN or one locator→another pass unnoticed — a
    # guard covering less than it claims, which is the exact defect it exists
    # to prevent (round 15 P1). Order is part of the verdict too, so the
    # lists are not sorted before comparison.
    for label, s_raw, r_raw in corpus:
        blind = jcs(verify_receipt_bytes(s_raw, r_raw, cas))
        sink = {}
        seeing = jcs(verify_receipt_bytes(s_raw, r_raw, cas, view=sink))
        check_equal("verdict is view-independent: %s" % label, blind, seeing)
    # and the channel really does carry the body the mapping needs
    sink = {}
    verify_receipt_bytes(raw_s, raw_r, cas, view=sink)
    bodies = sink.get("body", {})
    check_true("the view carries the committed body, deep-copied",
               lambda: any(isinstance(b, dict) and "because" in b
                           for b in bodies.values()))
    # The deep copy on that channel is defense in depth, and labelled rather
    # than counted: the parsed envelope is local to the verdict and discarded
    # when it returns, so no second reader exists for a caller to corrupt,
    # and removing the copy changes no test result. A vector asserting "a
    # later run is unaffected" was written first and DELETED as vacuous — it
    # passed with the copy and without it, because every run re-parses from
    # bytes anyway. It guards a future caller that keeps a view alive across
    # calls, and says so here instead of pretending to be covered.


# ------------------------------------------ harness selftest (subprocess)

def harness_selftest():
    injected = (
        "import snapshot_model as m, sys\n"
        "m.check_true('injected: false predicate', lambda: False)\n"
        "m.check_raises('injected: wrong code', m.PathViolation, 'ABSOLUTE_PATH',\n"
        "               lambda: m.validate_logical_path(''))\n"
        "sys.exit(1 if len(m.FAILURES) == 2 else 0)\n")
    proc = subprocess.run([sys.executable, "-c", injected],
                          cwd=os.path.dirname(os.path.abspath(__file__)),
                          capture_output=True, text=True)
    check_equal("harness selftest: 2 injected defects -> exit 1", proc.returncode, 1)
    fail_lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("FAIL")]
    check_equal("harness selftest: both printed as FAIL", len(fail_lines), 2)


def main():
    run_vectors()
    view_is_output_only()
    harness_selftest()
    print()
    if FAILURES:
        print("FAILED: %d vector(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("ALL PASS (model v3: raw-byte boundary + composed receipt verdict)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
