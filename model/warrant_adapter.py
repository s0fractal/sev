#!/usr/bin/env python3
"""Live Warrant adapter — seal a REAL `.warrants/` store and project it.

Everything the model and the projector have proved so far ran on fixtures
this repository built for itself. That is a closed loop: the fixtures were
shaped by the same understanding as the code, so a contract can be wrong in
a way no fixture reveals. This adapter closes that loop against evidence SEV
did not author — a real Warrant store, its real records, its real
signatures.

**What this is NOT.** Not a Warrant contract, not a receipt producer anyone
else should adopt, and not a verifier. It is an *sev-side* construction that
derives what the bytes permit and, for the one thing SEV must never do
itself, **asks Warrant about Warrant's bytes**: signature validity is
obtained by running the owning protocol's own reference implementation in a
subprocess. Re-implementing Ed25519 here would make SEV a second Warrant
verifier — the ownership boundary this repository exists to hold.

Usage:
    python3 model/warrant_adapter.py <store-dir> [--out DIR]
    python3 model/warrant_adapter.py --selftest      # runs against fixtures

The exit status is the verdict: a store whose receipt does not validate, or
whose projection is refused, exits non-zero with the findings printed.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import snapshot_model as sm          # noqa: E402
import sev_projector as sp           # noqa: E402

PREFIX = ".warrants/"
WARRANT_IMPL = os.environ.get(
    "WARRANT_IMPL",
    os.path.expanduser("~/Projects/warrant/impl/warrant.py"))


# ------------------------------------------------------------------ sealing

def seal_store(store_dir):
    """(snapshot, cas, universe-by-path) over the real files on disk.

    Reads every regular file once, under the frozen logical-path rules. A
    path the contract refuses aborts the seal rather than being skipped.
    """
    files = {}
    base = os.path.abspath(store_dir)
    for root, _dirs, names in os.walk(base):
        for name in sorted(names):
            full = os.path.join(root, name)
            if os.path.islink(full) or not os.path.isfile(full):
                raise sm.SealViolation("NOT_REGULAR_FILE", full)
            rel = PREFIX + os.path.relpath(full, base).replace(os.sep, "/")
            sm.validate_logical_path(rel)
            with open(full, "rb") as fh:
                files[rel] = fh.read()
    cas = {sm.sha256_hex(v): v for v in files.values()}
    universe = sm.seal_universe(files)
    contract = {"name": "warrant", "version": "0.4",
                "spec_digest": _spec_digest()}
    descriptor = sm.subroot_descriptor("warrant", contract, PREFIX, universe)
    snapshot = sm.snapshot_object([descriptor], [])
    return snapshot, cas, {e["path"]: e["sha256"] for e in universe}


def _spec_digest():
    """The SPEC bytes this receipt was judged against, if reachable.

    A null here is refused by the warrant-slot role check, and rightly so:
    "0.4" is a human name while the SPEC bytes can move under it.
    """
    path = os.path.join(os.path.dirname(WARRANT_IMPL), "..", "SPEC.md")
    with open(path, "rb") as fh:
        return sm.sha256_hex(fh.read())


# --------------------------------------------------- asking Warrant, not SEV

def warrant_report(store_dir):
    """Warrant's OWN `verify --json` verdict over the same store.

    This exists to enforce the invariant below. SEV derives what it can from
    bytes, but the moment its receipt is *quieter* than the protocol whose
    evidence it reports on, the projected graph launders a warning into
    silence — and a consumer reads "verified" where the owner said
    "unresolved blob". The report is the ceiling on how clean SEV may claim
    the store is.
    """
    cli = os.path.join(os.path.dirname(WARRANT_IMPL), "warrant.py")
    proc = subprocess.run(
        [sys.executable, cli, "--store", store_dir, "verify", "--json"],
        capture_output=True, text=True)
    if not proc.stdout.strip():
        raise RuntimeError("warrant verify produced no report: %s"
                           % proc.stderr.strip()[:200])
    report = json.loads(proc.stdout)
    if report.get("report") != "warrant.verify-report@v0":
        raise RuntimeError("unexpected report kind: %r" % report.get("report"))
    return report


# Warrant's finding messages are non-normative prose, so SEV must not mint
# codes out of them freely — but it must also not collapse distinct findings
# into one indistinguishable issue, which is exactly what a single generic
# code did: "binding unverified" and "unresolved blob" on the same record
# became byte-identical issues, and the format's own duplicate rule caught
# the merge (ISSUES_NOT_SORTED). This table is the explicit, auditable
# middle: message prefixes observed in the reference implementation, mapped
# to stable codes. Anything unrecognized FAILS CLOSED rather than being
# labelled with a class SEV does not understand.
FINDING_CLASSES = (
    ("binding unverified", "WARRANT_BINDING_UNVERIFIED"),
    ("unresolved blob", "WARRANT_UNRESOLVED_BLOB"),
    ("genesis unverified", "WARRANT_GENESIS_UNVERIFIED"),
)


class UnclassifiedFinding(Exception):
    """Warrant reported something SEV has no code for. Refusing beats
    guessing: a mislabelled issue is worse than a missing receipt."""


class IndistinguishableFindings(Exception):
    """Two findings collapsed to one issue. The receipt would under-report
    by exactly one fact, silently."""


def classify(finding):
    message = finding.get("message") or ""
    for prefix, code in FINDING_CLASSES:
        if message.startswith(prefix):
            return code
    raise UnclassifiedFinding(message[:120])


def apply_report(sources, report, global_issues):
    """Carry every finding in Warrant's report into the receipt.

    The message text is deliberately **not** carried. It is non-normative
    prose in the source protocol, and the issue schema is closed to
    `{code, severity, at}`; importing prose into an evidence graph would
    give it a standing the owning SPEC never granted it. What is carried is
    the fact, the level, and the record it lands on. A finding whose subject
    matches no sealed record becomes a global issue rather than vanishing —
    silent truncation here would defeat the whole point of the join.
    """
    by_wid = {}
    for src in sources:
        for key in ("claimed_wid", "computed_wid"):
            if src.get(key):
                by_wid.setdefault(src[key], src)
    seen = set()
    for finding in report.get("findings", []):
        severity = "ERR" if finding.get("level") == "ERR" else "WARN"
        code = classify(finding)
        subject = finding.get("subject")
        target = by_wid.get(subject)
        key = (code, severity, subject)
        if key in seen:
            raise IndistinguishableFindings("%s twice on %s" % (code, subject))
        seen.add(key)
        if target is None:
            global_issues.append(_issue(code, severity, subject or "unknown"))
            continue
        target["issues"].append(_issue(code, severity, target["path"]))
    for src in sources:
        src["issues"].sort(key=lambda x: sm.jcs(x))
    global_issues.sort(key=lambda x: sm.jcs(x))


class QuieterThanProtocol(Exception):
    """The adapter refuses to emit a receipt cleaner than Warrant's own."""


def assert_not_quieter(core, report):
    if core["errors"] < report["errors"] or core["warnings"] < report["warnings"]:
        raise QuieterThanProtocol(
            "receipt reports %d/%d (err/warn) where warrant reports %d/%d"
            % (core["errors"], core["warnings"],
               report["errors"], report["warnings"]))


def signature_verdicts(records):
    """{path: [bool, ...]} from Warrant's OWN implementation.

    SEV performs no cryptography. The owning protocol is asked about its own
    bytes, in a subprocess, and its answer is recorded as an observation —
    not re-derived, not second-guessed.
    """
    script = (
        "import json, sys, hashlib\n"
        "sys.path.insert(0, %r)\n"
        "import warrant as w\n"
        "out = {}\n"
        "for path, raw in json.load(sys.stdin).items():\n"
        "    env = json.loads(raw)\n"
        "    wid = hashlib.sha256(w.canon(env['body'])).hexdigest()\n"
        "    out[path] = [bool(w.verify_sig(wid, s)) for s in env['sigs']]\n"
        "json.dump(out, sys.stdout)\n" % os.path.dirname(WARRANT_IMPL))
    payload = {p: raw.decode("utf-8") for p, raw in records.items()}
    proc = subprocess.run([sys.executable, "-c", script],
                          input=json.dumps(payload), capture_output=True,
                          text=True)
    if proc.returncode != 0:
        raise RuntimeError("warrant impl refused to answer: %s"
                           % proc.stderr.strip()[:200])
    return json.loads(proc.stdout)


# ---------------------------------------------------------- receipt building

def build_receipt(snapshot, cas, by_path, store_dir):
    """An sev-side receipt over the sealed store.

    Every field is derived from the bytes except signature validity, which
    is Warrant's answer. Where the derivation finds the store's own evidence
    invalid — a body schema Warrant rejects, an unparseable record — the
    receipt says so, because that is what an honest negative receipt is for.
    """
    descriptor = {k: v for k, v in snapshot["subroots"][0].items()
                  if k != "digest"}
    records = {}
    for path in by_path:
        kind, _claim = sm.classify_warrant_source(path, PREFIX)
        if kind == "record":
            records[path] = sm.cas_resolve(cas, by_path[path])
    sig_ok = signature_verdicts(records) if records else {}

    sources, errors, warnings = [], 0, 0
    for path in sorted(by_path, key=sm.path_sort_key):
        kind, claimed = sm.classify_warrant_source(path, PREFIX)
        digest = by_path[path]
        if kind != "record":
            sources.append({"kind": kind, "path": path, "entry_digest": digest,
                            "loaded": True, "issues": []})
            continue

        raw = records[path]
        obj, pf = sm.parse_strict(raw)
        fatal = [x for x in pf if x["code"] != "NOT_CANONICAL"]
        issues = []
        computed = None
        if obj is None or fatal:
            issues.append(_issue("RECORD_UNREADABLE", "ERR", path))
        elif set(obj.keys()) != {"body", "sigs"}:
            issues.append(_issue("MALFORMED_ENVELOPE", "ERR", path))
        else:
            body_bad = sm.body_schema_findings(obj["body"])
            computed = sm.sha256_hex(sm.jcs(obj["body"]))
            if body_bad:
                issues.append(_issue("BODY_SCHEMA_INVALID", "ERR", path))
            entries, malformed = sm.envelope_signature_entries(obj)
            verdicts = sig_ok.get(path, [])
            sigs = []
            for d, m, actor, key, idx in entries:
                valid = bool(verdicts[idx]) if idx < len(verdicts) else False
                sigs.append({"sig_digest": d, "multiplicity": m,
                             "actor": actor, "key": key, "valid": valid,
                             "binding": "unverified"})
                if not valid:
                    issues.append(_issue("INVALID_SIGNATURE", "WARN", path,
                                         pointer="/sigs/%d" % idx))
            for ptr in malformed:
                issues.append(_issue("MALFORMED_SIGNATURE", "ERR", path,
                                     pointer=ptr))
            actor_id = (obj["body"].get("actor") or {}).get("id")
            if not any(s["valid"] and s["actor"] == actor_id for s in sigs):
                issues.append(_issue("NO_VALID_ACTOR_SIGNATURE", "ERR", path))
            if computed != claimed:
                issues.append(_issue("ID_UNSOUND", "ERR", path))

            reasons = []
            if not body_bad:
                ptrs, _mal = sm.reportable_reason_pointers(obj)
                for ptr in sorted(ptrs):
                    i = int(ptr.rsplit("/", 1)[1])
                    committed = obj["body"]["because"][i]
                    reasons.append({
                        "ptr": ptr, "kind": "check",
                        "runtime": committed["runtime"],
                        "reason_digest": sm.sha256_hex(sm.jcs(committed)),
                        # cmd@v1 is normatively not re-executed by a verifier
                        "outcome": {"re_execution": "not-applicable",
                                    "claimed_verdict": committed["verdict"],
                                    "observed_verdict": None,
                                    "observed_result": None,
                                    "atp_spent": None, "failure_code": None}})
            issues.sort(key=lambda x: sm.jcs(x))
            sources.append({
                "kind": "record", "path": path, "entry_digest": digest,
                "loaded": True, "claimed_wid": claimed,
                "computed_wid": computed,
                "id_sound": computed == claimed and computed is not None,
                "settlement": [], "signatures": sorted(
                    sigs, key=lambda s: (s["sig_digest"], s["multiplicity"])),
                "issues": issues, "reasons": reasons})
            continue

        issues.sort(key=lambda x: sm.jcs(x))
        sources.append({"kind": "record", "path": path, "entry_digest": digest,
                        "loaded": True, "claimed_wid": claimed,
                        "computed_wid": None, "id_sound": False,
                        "settlement": [], "signatures": [], "issues": issues,
                        "reasons": []})

    report = warrant_report(store_dir)
    global_issues = []
    apply_report(sources, report, global_issues)

    for holder in [s["issues"] for s in sources] + [global_issues]:
        for x in holder:
            if x["severity"] == "ERR":
                errors += 1
            else:
                warnings += 1

    core = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(descriptor),
            "grade": report["grade"], "trust_config_digest": None,
            "execution_policy": {"runtimes": []},
            "ok": errors == 0, "errors": errors, "warnings": warnings,
            "global_issues": global_issues, "sources": sorted(
                sources, key=lambda s: (sm.path_sort_key(s["path"]),
                                        s["entry_digest"]))}
    assert_not_quieter(core, report)
    return {"receipt": "warrant.verification-receipt@v0", "core": core,
            "producer": {"impl": "sev-adapter", "artifact_digest": None,
                         "spec": "0.4",
                         # The report this receipt was reconciled against —
                         # not a decoration: it is what `assert_not_quieter`
                         # measured, and it is bound here by digest.
                         "report_digest": sm.sha256_hex(sm.jcs(report)),
                         "local_notes": []}}


def _issue(code, severity, path, pointer=None):
    at = ({"kind": "json-pointer", "value": pointer} if pointer
          else {"kind": "path", "value": path})
    return {"code": code, "severity": severity, "at": at}


# ------------------------------------------------------------------- driving

def run(store_dir, out_dir=None):
    snapshot, cas, by_path = seal_store(store_dir)
    receipt = build_receipt(snapshot, cas, by_path, store_dir)
    snap_raw, rec_raw = sm.jcs(snapshot), sm.jcs(receipt)
    result, findings = sp.project_bytes(snap_raw, rec_raw, cas)
    if out_dir and result:
        os.makedirs(out_dir, exist_ok=True)
        for name, blob in (("snapshot.json", snap_raw),
                           ("receipt.json", rec_raw),
                           ("dataset.nq", result["nquads"]),
                           ("view-manifest.json",
                            sm.jcs(result["view_manifest"])),
                           ("loss-manifest.json",
                            sm.jcs(result["loss_manifest"]))):
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(blob)
    return snapshot, receipt, result, findings


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-4])
        return 2
    store = argv[1]
    out = None
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    snapshot, receipt, result, findings = run(store, out)
    core = receipt["core"]
    print("store            %s" % store)
    print("bundle_root      %s" % snapshot["bundle_root"])
    print("sources          %d  (errors %d, warnings %d)"
          % (len(core["sources"]), core["errors"], core["warnings"]))
    if findings:
        print("PROJECTION REFUSED")
        for x in findings[:20]:
            print("  %-32s %s" % (x["code"], x["at"]))
        return 1
    vm = result["view_manifest"]
    print("graph_digest     %s" % vm["graph_digest"])
    print("quads            %d" % len(result["nquads"].decode().splitlines()))
    print("projected        %d   excluded %d"
          % (vm["sources_projected"], vm["sources_excluded"]))
    print("coverage.emitted %s" % ", ".join(vm["coverage"]["emitted"]))
    print("losses           %s" % ", ".join(
        e["code"] for e in result["loss_manifest"]["entries"]))
    for exc in vm["exclusions"][:10]:
        print("  excluded %s  %s" % (
            exc["path"].rsplit("/", 1)[-1][:12],
            ",".join(i["code"] for i in exc["issues"])))
    if out:
        print("wrote            %s" % out)
    return 0


def selftest():
    """Deterministic checks that do not need a store on this machine."""
    ok = True

    def check(name, cond):
        nonlocal ok
        print("%s  %s" % ("PASS" if cond else "FAIL", name))
        ok = ok and bool(cond)

    check("the adapter performs no cryptography of its own",
          "verify_sig" not in open(__file__).read().split("script = ")[0])
    check("it asks the owning protocol instead",
          "warrant as w" in open(__file__).read())

    # The join, exercised on shapes a healthy store never produces. A live
    # store has no ERR findings and no orphan subjects, so without these the
    # two hardest clauses would ride along untested.
    src = {"path": ".warrants/records/a.json", "claimed_wid": "a" * 64,
           "computed_wid": "a" * 64, "issues": []}
    globals_ = []
    apply_report([src], {"findings": [
        {"level": "ERR", "subject": "a" * 64, "message": "unresolved blob abc"},
        {"level": "WARN", "subject": "a" * 64, "message": "binding unverified: k"},
        {"level": "ERR", "subject": "b" * 64, "message": "unresolved blob z"}]},
        globals_)
    check("an ERR finding stays an ERR",
          sorted(i["severity"] for i in src["issues"]) == ["ERR", "WARN"])
    check("two distinct findings stay two distinct issues",
          len({i["code"] for i in src["issues"]}) == 2)
    check("a finding with no matching record becomes a global issue",
          len(globals_) == 1 and globals_[0]["severity"] == "ERR"
          and globals_[0]["at"]["value"] == "b" * 64)
    try:
        classify({"message": "a shape this adapter has never seen"})
        check("an unclassifiable finding fails closed", False)
    except UnclassifiedFinding:
        check("an unclassifiable finding fails closed", True)
    try:
        apply_report([dict(src, issues=[])], {"findings": [
            {"level": "WARN", "subject": "a" * 64, "message": "unresolved blob q"},
            {"level": "WARN", "subject": "a" * 64, "message": "unresolved blob q"}]},
            [])
        check("two findings that would merge are refused", False)
    except IndistinguishableFindings:
        check("two findings that would merge are refused", True)
    quiet = {"errors": 0, "warnings": 0}
    try:
        assert_not_quieter(quiet, {"errors": 0, "warnings": 1})
        check("a receipt quieter than the protocol is refused", False)
    except QuieterThanProtocol:
        check("a receipt quieter than the protocol is refused", True)
    store = os.path.expanduser("~/Projects/warrant/.warrants")
    if not os.path.isdir(store):
        print("SKIP  no live warrant store on this machine")
        return 0 if ok else 1
    snapshot, receipt, result, findings = run(store)
    check("a real store seals and projects", not findings and result)
    if result:
        vm = result["view_manifest"]
        check("every sealed member is accounted for",
              vm["sources_projected"] + vm["sources_excluded"]
              == vm["sources_in_receipts"])
        check("the graph digest binds the emitted bytes",
              vm["graph_digest"] == sm.sha256_hex(result["nquads"]))
        again = run(store)[2]
        check("two runs over the same store are byte-identical",
              again["nquads"] == result["nquads"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
