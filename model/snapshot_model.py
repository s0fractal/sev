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
  5. one composed `validate_warrant_receipt(snapshot, receipt, cas)`;
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

def jcs(value):
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
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = []
        for k in sorted(value.keys(), key=lambda s: s.encode("utf-16-be", "surrogatepass")):
            if not isinstance(k, str):
                raise ValueError("non-string key")
            items.append(json.dumps(k, ensure_ascii=False).encode("utf-8", "surrogatepass")
                         + b":" + jcs(value[k]))
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
    except ValueError as exc:
        _f(f, "NOT_I_JSON" if str(exc) in ("constant", "float") else "NOT_JSON", "/")
        return None, f
    if text[end:].strip("\r\n\t "):
        _f(f, "TRAILING_DATA", "/")
        return None, f
    if _scan_surrogates(obj):
        _f(f, "LONE_SURROGATE", "/")
        return None, f
    try:
        if jcs(obj) != raw:
            _f(f, "NOT_CANONICAL", "/")
    except ValueError:
        _f(f, "NOT_I_JSON", "/")
    return obj, f


def parse_snapshot(raw, cas=None) -> tuple:
    obj, f = parse_strict(raw)
    if obj is not None and not f:
        f = validate_snapshot(obj, cas)
    return obj, f


def parse_receipt(raw, snapshot=None, cas=None) -> tuple:
    """Symmetric with parse_snapshot: bytes in, findings out. With a
    snapshot supplied, runs the full composed verdict; without one, only the
    byte boundary (a receipt cannot be semantically judged in isolation)."""
    obj, f = parse_strict(raw)
    if obj is not None and not f and snapshot is not None:
        f = validate_warrant_receipt(snapshot, obj, cas)
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
    data = store[digest]
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
    reason resolution. Public entry is validate_warrant_receipt()."""
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
        all_issues.extend(issues)
        good_sources.append(src)
        err_here = any(x["severity"] == "ERR" for x in issues)
        if src["loaded"] is False and not err_here:
            _f(f, "UNLOADED_WITHOUT_ERR", at)
        if kind != "record" or not src["loaded"]:
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
        if cas is not None:
            parsed = _resolve_record(f, cas, src, at)
            if parsed is not None and view is not None:
                # the validated view: what the verdict was actually rendered
                # over, handed to consumers so nothing re-reads the CAS and
                # judges one snapshot while asserting over another
                body_obj = parsed.get("body")
                because = body_obj.get("because") if isinstance(body_obj, dict) else None
                view.setdefault("committed", {})[src["path"]] = (
                    json.loads(json.dumps(because)) if isinstance(because, list) else [])
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
        invalid_count = sum(1 for s in good_sigs if s["valid"] is False)
        sig_issues = [x for x in issues if x["code"] == "INVALID_SIGNATURE"
                      and x["severity"] == "WARN"]
        distinct_locs = {jcs(x["at"]) for x in sig_issues}
        if invalid_count != len(sig_issues) or len(distinct_locs) != len(sig_issues):
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
                if rt not in runtimes:
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
                if any(v is not None for v in observed) or fc not in FAILURE_CODES:
                    _f(f, "OUTCOME_NOT_TOTAL", rat)
                    continue
                if fc == "RUNTIME_UNAVAILABLE" and rt in runtimes:
                    _f(f, "FAILURE_CODE_VS_POLICY", rat)
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
            else:
                _f(f, "BAD_RE_EXECUTION", rat)
            if cas is not None:
                _resolve_reason(f, parsed, reason, rat)
        _ordered(f, good_reasons, lambda r: r["ptr"], "REASONS_NOT_SORTED",
                 at + "/reasons")

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


def _resolve_record(f, cas, src, at):
    """Resolve and parse a record's committed bytes ONCE per source.
    Returns the parsed envelope or None (with a finding)."""
    try:
        raw = cas_resolve(cas, src["entry_digest"])
    except (KeyError, SealViolation):
        _f(f, "RECORD_UNRESOLVABLE", at)
        return None
    obj, _pf = parse_strict(raw)
    if obj is None or not isinstance(obj, dict):
        _f(f, "RECORD_UNREADABLE", at)
        return None
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


def _freeze(value):
    """A private detached copy; hostile shapes fall back to the original."""
    try:
        return copy.deepcopy(value)
    except Exception:  # noqa: BLE001
        return value


def validate_warrant_receipt(snapshot, receipt, cas=None, expected_version="0.4",
                             view=None) -> list:
    """THE public verdict tying receipt to snapshot: descriptor lookup, role
    check, exact universe<->sources bijection, per-source digests, then the
    internal core invariants. Total over any parsed JSON values."""
    # Freeze the inputs BEFORE judging them. A caller whose objects change
    # between reads could otherwise show the validator a clean core and the
    # projector another one — the CAS TOCTOU was closed one round earlier,
    # this is the same seam on receipt and snapshot (re-gate P1-1).
    if view is not None:
        snapshot = _freeze(snapshot)
        receipt = _freeze(receipt)
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
    if view is not None:
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
    committed_by_path = (view or {}).get("committed", {})
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

def _fixture():
    """A fully valid (snapshot, receipt, cas) triple the mutation vectors edit."""
    check_bytes = b"policy"           # the blob sealed at .warrants/blobs/p
    reason_obj = {"kind": "check", "runtime": "ski@v1",
                  "check": sha256_hex(check_bytes),
                  "verdict": "pass", "transcript": "b" * 64}
    # body "warrant": "0.2" is the BODY-FORMAT version (ski@v1 era), while the
    # contract version "0.4" below is the SPEC document revision — warrant
    # versions bodies and the document independently (SPEC "Versioning").
    record = {"body": {"warrant": "0.2", "decision": "accept", "subject": {},
                       "under": [], "because": [reason_obj], "evidence": [],
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
         "id_sound": False, "settlement": [], "signatures": [],
         "issues": [{"code": "ID_UNSOUND", "severity": "ERR",
                     "at": {"kind": "path", "value": ".warrants/records/r.json"}}],
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
            "ok": False, "errors": 1, "warnings": 0, "global_issues": [],
            "sources": sources}
    receipt = {"receipt": "warrant.verification-receipt@v0", "core": core,
               "producer": {"impl": "model", "artifact_digest": None, "spec": "0.4",
                            "report_digest": "f" * 64, "local_notes": []}}
    return snap, receipt, cas


def _mutate(receipt, fn):
    r = json.loads(json.dumps(receipt))
    fn(r)
    return r


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
            validate_warrant_receipt(v, v)
            validate_warrant_receipt({}, {"receipt": "warrant.verification-receipt@v0",
                                          "core": v, "producer": {}})
        return True
    check_true("hostile shapes -> findings, never exceptions", _no_crash)

    # --- fixture is fully green end-to-end
    snap, receipt, cas = _fixture()
    check_codes("fixture snapshot valid", validate_snapshot(snap, cas), [])
    check_codes("fixture composed verdict valid",
                validate_warrant_receipt(snap, receipt, cas), [])
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
              validate_warrant_receipt(snap, empty, cas),
              "SOURCE_MISSING_FOR_MEMBER")
    extra = _mutate(receipt, lambda r: r["core"]["sources"].append(
        {"kind": "other", "path": "zzz", "entry_digest": "a" * 64,
         "loaded": True, "issues": []}))
    check_has("source outside universe -> SOURCE_NOT_IN_UNIVERSE",
              validate_warrant_receipt(snap, extra, cas), "SOURCE_NOT_IN_UNIVERSE")
    wrongd = _mutate(receipt, lambda r: r["core"]["sources"][0].update(
        entry_digest="9" * 64))
    check_has("wrong entry digest -> SOURCE_DIGEST_MISMATCH",
              validate_warrant_receipt(snap, wrongd, cas), "SOURCE_DIGEST_MISMATCH")

    # --- composed role check: null spec_digest refused IN the verdict
    d_null = subroot_descriptor("warrant", dict(cw, spec_digest=None), ".x/", uni)
    snap_null = snapshot_object([d_null], [])
    rec_null = _mutate(receipt, lambda r: r["core"].update(
        subroot_descriptor_digest=subroot_descriptor_digest(d_null), sources=[],
        errors=0, ok=True))
    check_has("composed verdict refuses null spec_digest",
              validate_warrant_receipt(snap_null, rec_null,
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
    found = validate_warrant_receipt(snap, two_mm, cas)
    check_true("one issue cannot cover two mismatches",
               lambda: any(x["code"] == "MISMATCH_WITHOUT_WARN" for x in found))

    # --- domains: potato verdict, negative atp, over-ceiling
    potato = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(claimed_verdict="potato",
                                        observed_verdict="potato"))
    check_has("verdict outside enum -> BAD_VERDICT",
              validate_warrant_receipt(snap, potato, cas), "BAD_VERDICT")
    negatp = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(atp_spent=-999))
    check_has("negative atp -> BAD_ATP",
              validate_warrant_receipt(snap, negatp, cas), "BAD_ATP")
    overc = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                    ["outcome"].update(atp_spent=99999))
    check_has("atp above declared ceiling -> ATP_OVER_CEILING",
              validate_warrant_receipt(snap, overc, cas), "ATP_OVER_CEILING")
    badres = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     ["outcome"].update(observed_result="x"))
    check_has("ski@v1 result not hex64 -> BAD_RESULT_SHAPE",
              validate_warrant_receipt(snap, badres, cas), "BAD_RESULT_SHAPE")

    # --- ptr resolution against CAS bytes
    badptr = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     .update(ptr="/because/7"))
    check_has("dangling ptr -> REASON_PTR_UNRESOLVABLE",
              validate_warrant_receipt(snap, badptr, cas), "REASON_PTR_UNRESOLVABLE")
    baddig = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                     .update(reason_digest="9" * 64))
    check_has("wrong reason digest -> REASON_DIGEST_MISMATCH",
              validate_warrant_receipt(snap, baddig, cas), "REASON_DIGEST_MISMATCH")
    swapped = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                      .update(runtime="evil@v1"))
    check_has("runtime swapped over committed ski@v1 reason -> REASON_ROLE_MISMATCH",
              validate_warrant_receipt(snap, swapped, cas), "REASON_ROLE_MISMATCH")
    lied = _mutate(receipt, lambda r: r["core"]["sources"][1]["reasons"][0]
                   ["outcome"].update(claimed_verdict="fail", observed_verdict="fail"))
    check_has("claimed verdict differs from committed reason -> REASON_CLAIM_MISMATCH",
              validate_warrant_receipt(snap, lied, cas), "REASON_CLAIM_MISMATCH")

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
              validate_warrant_receipt(snap, rec_as_other, cas),
              "SOURCE_KIND_MISMATCH")
    blob_as_genesis = _mutate(receipt, lambda r: _relabel(r, 0, "genesis"))
    check_has("blob relabelled 'genesis' -> SOURCE_KIND_MISMATCH",
              validate_warrant_receipt(snap, blob_as_genesis, cas),
              "SOURCE_KIND_MISMATCH")
    wid_lie = _mutate(receipt, lambda r: r["core"]["sources"][1].update(
        claimed_wid="b" * 64, id_sound=False))
    check_has("claimed_wid not derived from the filename -> CLAIMED_WID_NOT_PATH",
              validate_warrant_receipt(snap, wid_lie, cas), "CLAIMED_WID_NOT_PATH")

    # --- grade-aware severity + settlement at base
    setl = [{"jurisdiction": "a" * 64, "active": True,
             "policies": [{"policy": "b" * 64, "threshold_satisfied": True}]}]
    at_base = _mutate(receipt, lambda r: r["core"]["sources"][1].update(settlement=setl))
    check_has("settlement[] at base grade -> SETTLEMENT_IN_BASE",
              validate_warrant_receipt(snap, at_base, cas), "SETTLEMENT_IN_BASE")

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
                               for x in validate_warrant_receipt(snap, base_unv, cas)))
    settle_unv = _mutate(receipt, lambda r: _unv(r, "settlement", True))
    check_has("settlement grade + active + WARN-only -> needs ERR",
              validate_warrant_receipt(snap, settle_unv, cas), "UNVERIFIED_WITHOUT_ERR")

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
              validate_warrant_receipt(snap, dup, cas),
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
            validate_warrant_receipt(a, b, {})
        for _ in range(100):
            parse_strict(bytes(rng.randrange(256) for _ in range(rng.randrange(40))))
        return True
    check_true("fuzz: 300 hostile shapes + 100 random byte strings, no exceptions", _fuzz)


def _ve(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


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
    harness_selftest()
    print()
    if FAILURES:
        print("FAILED: %d vector(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("ALL PASS (model v3: raw-byte boundary + composed receipt verdict)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
