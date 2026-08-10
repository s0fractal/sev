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

import glob
import json
import os
import shutil
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
# Enumerated from every `out(level, wid, msg)` call site in the reference
# implementation rather than from the two shapes a healthy store happens to
# produce — the first table covered exactly what this machine's store
# emitted, so four ordinary corruptions (truncated record, UTF-16 bytes,
# empty file, wrong top-level shape) all hit the fail-closed path.
FINDING_CLASSES = (
    # unreadable / unloadable
    ("unloadable record", "WARRANT_RECORD_UNLOADABLE"),
    ("envelope must be {body, sigs}", "WARRANT_MALFORMED_ENVELOPE"),
    ("WarrantID uncomputable", "WARRANT_WID_UNCOMPUTABLE"),
    ("WarrantID mismatch", "WARRANT_WID_MISMATCH"),
    ("schema:", "WARRANT_SCHEMA"),
    # signatures
    ("no signatures", "WARRANT_NO_SIGNATURES"),
    ("no valid signature by body.actor.id", "WARRANT_NO_ACTOR_SIGNATURE"),
    ("sigs must be a list", "WARRANT_SIGS_NOT_LIST"),
    ("signature entry is not an object", "WARRANT_MALFORMED_SIGNATURE"),
    # the legacy-construction message is itself a "signature does not verify"
    # prefix, so it MUST be tested before the generic one
    ("signature does not verify (excluded): LEGACY", "WARRANT_LEGACY_SIGNATURE"),
    ("signature does not verify", "WARRANT_SIGNATURE_INVALID"),
    ("signature unbound", "WARRANT_SIGNATURE_UNBOUND"),
    ("binding unverified", "WARRANT_BINDING_UNVERIFIED"),
    # evidence / blobs
    ("unresolved blob", "WARRANT_UNRESOLVED_BLOB"),
    ("blob ", "WARRANT_BLOB_ADDRESS_MISMATCH"),
    ("subject blob ", "WARRANT_SUBJECT_BLOB_MISMATCH"),
    # graph / lineage
    ("prior ", "WARRANT_PRIOR_MISSING"),
    ("ts decreases along prior edge", "WARRANT_TS_DECREASES"),
    ("supersede subject MUST be", "WARRANT_BAD_SUPERSEDE_SUBJECT"),
    ("re-litigation cites nothing new", "WARRANT_RELITIGATION"),
    ("unadopted root", "WARRANT_UNADOPTED_ROOT"),
    ("genesis.json unverified", "WARRANT_GENESIS_UNVERIFIED"),
    # runtimes / policy / settlement
    ("runtime ", "WARRANT_RUNTIME_FAIL_CLOSED"),
    ("ski@v1 verdict mismatch", "WARRANT_SKI_VERDICT_MISMATCH"),
    # emitted from the runtime-handler boundary rather than the core
    # reporter, which is why the first sweep of `out(...)` call sites missed
    # it and the fail-closed path caught it instead
    ("ski@v1 unverified", "WARRANT_SKI_UNVERIFIED"),
    ("UNVERIFIABLE: reject with prose-only reasons", "WARRANT_UNVERIFIABLE"),
    ("invalid threshold policy", "WARRANT_INVALID_THRESHOLD"),
    ("key-state conflict", "WARRANT_KEY_CONFLICT"),
    ("settlement trust config unavailable", "WARRANT_SETTLEMENT_TRUST"),
)


class UnclassifiedFinding(Exception):
    """Warrant reported something SEV has no code for. Refusing beats
    guessing: a mislabelled issue is worse than a missing receipt."""


class UnknownFindingLevel(Exception):
    """Warrant reported a level SEV has no mapping for. Refusing beats
    quietly choosing the milder of the two."""


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
    ordinal = {}
    for finding in report.get("findings", []):
        level = finding.get("level")
        if level not in ("ERR", "WARN"):
            # Silently calling an unknown level WARN is the same defect as
            # guessing a code from prose: it invents a judgement the owning
            # protocol did not make, in the safer-looking direction (round 14
            # P2). Refusing is the honest answer.
            raise UnknownFindingLevel(repr(level)[:80])
        code = classify(finding)
        subject = finding.get("subject")
        target = by_wid.get(subject)
        # Two findings of the same class on one record is a LEGITIMATE state
        # — a record can commit to two unresolved blobs. The locator union
        # carries an optional `occurrence`, so the receipt can represent it;
        # the earlier refusal was a defect of this adapter, not a limit of
        # the format (round 14 P2, reviewer correct).
        key = (code, level, subject)
        n = ordinal.get(key, 0)
        ordinal[key] = n + 1
        if target is None:
            # `store`/`settlement`/`genesis`/`trust` are the protocol's own
            # global subjects and the locator union has a `global` kind for
            # exactly them. Anything else unmatched is a statement about a
            # record this bundle does not contain, which is still a statement
            # about the store — recorded there rather than dropped.
            value = subject if subject in sm.GLOBAL_SUBJECTS else "store"
            at = {"kind": "global", "value": value}
            if n:
                at["occurrence"] = n
            global_issues.append({"code": code, "severity": level, "at": at})
            continue
        target["issues"].append(_issue(code, level, target["path"],
                                       occurrence=n))
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


# Defense in depth, and honestly labelled as such: no vector can isolate
# either the timeout or the child's per-signature `None`. Warrant's
# `verify_sig` is total on every hostile signature shape tried (bad hex,
# short key, non-string, missing field — all return False, none raise), and
# nothing in this repository can make a subprocess hang on demand. Removing
# them changes no test result today. They guard a DIFFERENT implementation
# or a future one, and per AGENTS.md rule 7 they are stated here rather than
# counted as covered. What IS covered is the parent's refusal to treat a
# non-boolean answer as `False` — the clause that would otherwise let SEV
# assert a verdict Warrant never gave.
ASK_TIMEOUT = 120


def signature_verdicts(envelopes):
    """{path: [bool, ...] | None} from Warrant's OWN implementation.

    SEV performs no cryptography. The owning protocol is asked about its own
    bytes, in a subprocess, and its answer is recorded as an observation —
    not re-derived, not second-guessed.

    **Only well-formed envelopes may be passed.** Handing raw store bytes to
    this function crashed the adapter on exactly the evidence the frozen
    receipt core exists to represent: `b"{"` killed the child process and
    `b"\\xff\\xfe"` never survived `.decode("utf-8")`, so the first real
    producer of receipts could not emit the honest negative receipt the
    contract accepts (round 14 P1). Parsing now happens first, and this is
    asked only about envelopes that parsed.

    A record the child cannot answer for yields `None` — never `False`. The
    difference matters: `False` asserts "the owning protocol judged this
    signature invalid", which would be SEV inventing a verdict it never got.
    """
    script = (
        "import json, sys, hashlib\n"
        "sys.path.insert(0, %r)\n"
        "import warrant as w\n"
        "out = {}\n"
        "for path, env in json.load(sys.stdin).items():\n"
        "    try:\n"
        "        wid = hashlib.sha256(w.canon(env['body'])).hexdigest()\n"
        "    except Exception:\n"
        "        out[path] = None\n"   # one hostile record must not blind the rest
        "        continue\n"
        "    row = []\n"
        "    for s in env['sigs']:\n"
        "        try:\n"
        "            row.append(bool(w.verify_sig(wid, s)))\n"
        "        except Exception:\n"
        "            row.append(None)\n"   # unjudged, which is not the same as invalid
        "    out[path] = row\n"
        "json.dump(out, sys.stdout)\n" % os.path.dirname(WARRANT_IMPL))
    try:
        proc = subprocess.run([sys.executable, "-c", script],
                              input=json.dumps(envelopes), capture_output=True,
                              text=True, timeout=ASK_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ProtocolUnavailable("warrant impl did not answer within %ds"
                                  % ASK_TIMEOUT)
    if proc.returncode != 0:
        raise ProtocolUnavailable("warrant impl refused to answer: %s"
                                  % proc.stderr.strip()[:200])
    return json.loads(proc.stdout)


class ProtocolUnavailable(Exception):
    """The owning protocol could not be asked at all. No receipt is emitted:
    a receipt built on assumed signature verdicts is worse than none."""


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
    # PASS 1 — parse. Nothing is asked of the owning protocol until the
    # bytes have survived the format's own reader, because a malformed
    # record must become an honest ERR in the receipt, not a crash.
    parsed = {}
    for path in by_path:
        kind, _claim = sm.classify_warrant_source(path, PREFIX)
        if kind != "record":
            continue
        raw = sm.cas_resolve(cas, by_path[path])
        obj, pf = sm.parse_strict(raw)
        fatal = [x for x in pf if x["code"] != "NOT_CANONICAL"]
        well_formed = (obj is not None and not fatal and isinstance(obj, dict)
                       and set(obj.keys()) == {"body", "sigs"}
                       and isinstance(obj.get("sigs"), list))
        parsed[path] = (obj, fatal, well_formed)

    askable = {p: parsed[p][0] for p in parsed if parsed[p][2]}
    sig_ok = signature_verdicts(askable) if askable else {}

    sources, errors, warnings = [], 0, 0
    for path in sorted(by_path, key=sm.path_sort_key):
        kind, claimed = sm.classify_warrant_source(path, PREFIX)
        digest = by_path[path]
        if kind != "record":
            sources.append({"kind": kind, "path": path, "entry_digest": digest,
                            "loaded": True, "issues": []})
            continue

        obj, fatal, _well = parsed[path]
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
            verdicts = sig_ok.get(path) or []
            sigs = []
            for d, m, actor, key, idx in entries:
                answer = verdicts[idx] if idx < len(verdicts) else None
                if not isinstance(answer, bool):
                    # `valid` is a required boolean in the frozen core, so
                    # there is no "unknown" to fall back to — and defaulting
                    # to False would have SEV assert a verdict the owning
                    # protocol never gave. Refusing is the only honest move.
                    raise ProtocolUnavailable(
                        "warrant did not judge %s/sigs/%d" % (path, idx))
                valid = answer
                sigs.append({"sig_digest": d, "multiplicity": m,
                             "actor": actor, "key": key, "valid": valid,
                             "binding": "unverified"})
                if not valid:
                    issues.append(_issue("INVALID_SIGNATURE", "WARN", path,
                                         pointer="/sigs/%d" % idx))
            for ptr in malformed:
                # `/sigs` (the container itself is not a list) and `/sigs/N`
                # (one entry is not an object) are different defects and the
                # model demands different codes; emitting one code for both
                # left `sigs: 5` unreportable (MALFORMED_ENVELOPE_UNREPORTED)
                issues.append(_issue(
                    "MALFORMED_ENVELOPE" if ptr == "/sigs"
                    else "MALFORMED_SIGNATURE", "ERR", path, pointer=ptr))
            actor_id = (obj["body"].get("actor") or {}).get("id")
            if not any(s["valid"] and s["actor"] == actor_id for s in sigs):
                issues.append(_issue("NO_VALID_ACTOR_SIGNATURE", "ERR", path))
            if computed != claimed:
                issues.append(_issue("ID_UNSOUND", "ERR", path))

            reasons = []
            if not body_bad:
                # The malformed-reason pointers are deliberately NOT turned
                # into issues here, and this is reachability, not laziness:
                # every shape that yields `reason_malformed` also yields
                # `body_schema_findings`, so this block only runs when there
                # are none. A first attempt did emit them and was dead code —
                # unreachable guards that look like coverage are exactly what
                # AGENTS.md rule 7 forbids counting. The subsumption itself
                # is vectored in `selftest`, so if it ever stops holding the
                # suite says so instead of this comment quietly rotting.
                ptrs, _subsumed_by_body_schema = sm.reportable_reason_pointers(obj)
                for ptr in sorted(ptrs):
                    i = int(ptr.rsplit("/", 1)[1])
                    committed = obj["body"]["because"][i]
                    runtime = committed["runtime"]
                    # `not-applicable` is legal ONLY for a runtime the
                    # contract says a verifier does not re-run. Hardcoding it
                    # happened to be true of this store (every check is
                    # cmd@v1) and would have been a lie the first time a
                    # ski@v1 reason appeared — the model rejects it as
                    # NOT_APPLICABLE_BUT_EXECUTABLE (round 14 P2). This
                    # adapter re-executes nothing, so an executable runtime
                    # it never ran is `unverified`, not `not-applicable`.
                    if runtime in sm.NORMATIVE_NOT_EXECUTED:
                        outcome = {"re_execution": "not-applicable",
                                   "claimed_verdict": committed["verdict"],
                                   "observed_verdict": None,
                                   "observed_result": None,
                                   "atp_spent": None, "failure_code": None}
                    else:
                        outcome = {"re_execution": "unverified",
                                   "claimed_verdict": committed["verdict"],
                                   "observed_verdict": None,
                                   "observed_result": None, "atp_spent": None,
                                   "failure_code": "RUNTIME_UNAVAILABLE"}
                        # the model requires the WARN to be joined at this
                        # exact pointer, or the receipt is unverified in
                        # name only
                        issues.append(_issue("REASON_UNVERIFIED", "WARN",
                                             path, pointer=ptr))
                    reasons.append({
                        "ptr": ptr, "kind": "check", "runtime": runtime,
                        "reason_digest": sm.sha256_hex(sm.jcs(committed)),
                        "outcome": outcome})
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


def _issue(code, severity, path, pointer=None, occurrence=None):
    at = ({"kind": "json-pointer", "value": pointer} if pointer
          else {"kind": "path", "value": path})
    if occurrence:
        at["occurrence"] = occurrence
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
    try:
        snapshot, receipt, result, findings = run(store, out)
    except (ProtocolUnavailable, UnclassifiedFinding, UnknownFindingLevel,
            QuieterThanProtocol, sm.SealViolation, sm.PathViolation) as exc:
        # A refusal is a result, not a crash: it gets a code and a line, not
        # a traceback the caller has to read Python to interpret.
        print("REFUSED  %s: %s" % (type(exc).__name__, exc))
        return 1
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


def reportable_or_empty(envelope):
    """`reportable_reason_pointers`, total over hostile bodies."""
    try:
        return sm.reportable_reason_pointers(envelope)
    except (TypeError, KeyError, AttributeError, IndexError):
        return set(), []


def selftest():
    """Deterministic checks that do not need a store on this machine."""
    ok = True

    def check(name, cond):
        nonlocal ok
        print("%s  %s" % ("PASS" if cond else "FAIL", name))
        ok = ok and bool(cond)

    # The ownership boundary, checked over the PARSE rather than the text.
    # A substring scan of the source called this file a crypto
    # implementation the moment a comment mentioned `verify_sig` — the guard
    # was reading prose, not code. What matters is that this module imports
    # no signature machinery and calls none: the only `verify_sig` here lives
    # inside a string handed to the owning protocol's own interpreter.
    import ast
    tree = ast.parse(open(__file__).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    check("the adapter imports no signature machinery",
          not imported & {"warrant", "nacl", "cryptography", "ed25519"})
    calls = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    calls |= {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    check("...and calls no verifier of its own",
          not calls & {"verify_sig", "verify", "sign"})
    check("it asks the owning protocol instead",
          "import warrant as w" in open(__file__).read())

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
    check("a finding about no sealed record lands on the store, not nowhere",
          len(globals_) == 1 and globals_[0]["severity"] == "ERR"
          and globals_[0]["at"] == {"kind": "global", "value": "store"})
    check("...and every issue the join builds is a valid locator",
          all(sm.validate_locator(i["at"])
              for i in src["issues"] + globals_))
    try:
        classify({"message": "a shape this adapter has never seen"})
        check("an unclassifiable finding fails closed", False)
    except UnclassifiedFinding:
        check("an unclassifiable finding fails closed", True)
    try:
        apply_report([src], {"findings": [
            {"level": "NOTE", "subject": "a" * 64, "message": "unresolved blob"}]},
            [])
        check("an unknown level fails closed instead of becoming WARN", False)
    except UnknownFindingLevel:
        check("an unknown level fails closed instead of becoming WARN", True)

    # Two findings of one class on one record is a legitimate state — a
    # record can commit to two unresolved blobs. The earlier build refused
    # it; the locator union carries `occurrence` precisely for this.
    twin = dict(src, issues=[])
    apply_report([twin], {"findings": [
        {"level": "WARN", "subject": "a" * 64, "message": "unresolved blob q"},
        {"level": "WARN", "subject": "a" * 64, "message": "unresolved blob r"}]},
        [])
    check("two findings of one class survive as two distinguishable issues",
          len(twin["issues"]) == 2
          and {i["at"].get("occurrence", 0) for i in twin["issues"]} == {0, 1}
          and all(sm.validate_locator(i["at"]) for i in twin["issues"]))

    # Every message the reference implementation can emit must classify. The
    # first table covered the two shapes a healthy store produces, so four
    # ordinary corruptions all hit the fail-closed path (round 14 P1).
    check("every enumerated warrant message class is recognized",
          all(classify({"message": prefix + " ..."}) == code
              for prefix, code in FINDING_CLASSES))
    check("the LEGACY signature message is not swallowed by the generic one",
          classify({"message":
                    "signature does not verify (excluded): LEGACY pre-v1 x"})
          == "WARRANT_LEGACY_SIGNATURE")
    # Why `build_receipt` may drop malformed-reason pointers: every shape
    # that produces one also fails the body schema, so the branch that would
    # report them cannot run. Asserted rather than assumed — if the model's
    # schema check ever narrows, this fails and the adapter must grow the
    # missing report.
    template = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64},
                "under": ["b" * 64], "evidence": [], "prior": [],
                "actor": {"id": "x@y"}, "ts": 1}
    subsumed = True
    for because in ([{"kind": "prose", "text": "x"}, 7], "not-a-list",
                    [{"kind": "check", "runtime": "cmd@v1"}], [None]):
        body = dict(template, because=because)
        _p, malformed = reportable_or_empty({"body": body, "sigs": []})
        if malformed and not sm.body_schema_findings(body):
            subsumed = False
    check("a malformed reason always fails the body schema too", subsumed)

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

    # THE round-14 P1 vector. The frozen receipt core exists to represent
    # exactly this: a record whose bytes are unreadable, acknowledged as an
    # ERR, giving a clean verdict and an exclusion. The adapter used to die
    # on it — `b"{"` killed the subprocess, `b"\xff\xfe"` failed to decode —
    # so the first real producer could not emit what the frozen core accepts.
    import tempfile
    for label, payload in ((b"truncated JSON", b"{"),
                           (b"non-UTF-8 bytes", b"\xff\xfe\x00{"),
                           (b"empty file", b""),
                           (b"sigs is not a list", b'{"body":{},"sigs":5}')):
        tmp = tempfile.mkdtemp(prefix="sev-adapter-")
        try:
            shutil.copytree(store, os.path.join(tmp, "s"))
            victim = sorted(glob.glob(os.path.join(tmp, "s", "records", "*.json")))[0]
            with open(victim, "wb") as fh:
                fh.write(payload)
            _snap, rec, res, f = run(os.path.join(tmp, "s"))
            bad = [s for s in rec["core"]["sources"]
                   if s["path"].endswith(os.path.basename(victim))]
            check("%s -> honest negative receipt, clean verdict"
                  % label.decode(),
                  f == [] and res is not None and len(bad) == 1
                  and any(i["severity"] == "ERR" for i in bad[0]["issues"]))
            check("...and the malformed record is excluded, not projected",
                  res is not None
                  and any(x["path"] == bad[0]["path"]
                          for x in res["view_manifest"]["exclusions"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # An EXECUTABLE runtime. The live store is all cmd@v1, which the contract
    # says a verifier does not re-run, so `not-applicable` was hardcoded and
    # happened to be true — a lie waiting for the first ski@v1 reason (the
    # model calls it NOT_APPLICABLE_BUT_EXECUTABLE). This adapter re-executes
    # nothing, so the honest outcome is `unverified` + RUNTIME_UNAVAILABLE,
    # with the WARN joined at that exact pointer.
    tmp = tempfile.mkdtemp(prefix="sev-adapter-ski-")
    try:
        shutil.copytree(store, os.path.join(tmp, "s"))
        donor = json.load(open(sorted(glob.glob(
            os.path.join(tmp, "s", "records", "*.json")))[0]))
        body = dict(donor["body"], because=[
            {"kind": "prose", "text": "a ski check, which IS re-executable"},
            {"kind": "check", "runtime": "ski@v1", "check": "c" * 64,
             "verdict": "pass", "transcript": "d" * 64}])
        wid = sm.sha256_hex(sm.jcs(body))
        with open(os.path.join(tmp, "s", "records", wid + ".json"), "wb") as fh:
            fh.write(sm.jcs({"body": body, "sigs": []}))
        _snap, rec, res, f = run(os.path.join(tmp, "s"))
        src2 = [s for s in rec["core"]["sources"] if s.get("claimed_wid") == wid]
        reason = src2[0]["reasons"][0] if src2 and src2[0].get("reasons") else {}
        check("an executable runtime is reported unverified, not not-applicable",
              f == [] and reason.get("runtime") == "ski@v1"
              and reason.get("outcome", {}).get("re_execution") == "unverified"
              and reason["outcome"].get("failure_code") == "RUNTIME_UNAVAILABLE")
        check("...with the WARN joined at that exact reason pointer",
              any(i["code"] == "REASON_UNVERIFIED" and i["severity"] == "WARN"
                  and i["at"].get("value") == reason.get("ptr")
                  for i in src2[0]["issues"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # A signature the owning protocol could not judge is NOT an invalid one.
    # `valid` is a required boolean in the frozen core, so there is no
    # "unknown" to fall back to — defaulting to False would have SEV assert a
    # verdict Warrant never gave, so the adapter must refuse instead.
    real = signature_verdicts

    def blind(envelopes):
        return {p: [None] * len(envelopes[p]["sigs"]) for p in envelopes}

    globals()["signature_verdicts"] = blind
    try:
        run(store)
        check("an unjudged signature is refused, never called invalid", False)
    except ProtocolUnavailable:
        check("an unjudged signature is refused, never called invalid", True)
    finally:
        globals()["signature_verdicts"] = real
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
