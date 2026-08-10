#!/usr/bin/env python3
"""SEV projector MVP — the first executable output of sev@v0 (round-6 R4).

Scope, deliberately narrow:
  * Warrant quadrant ONLY — projects a (sealed snapshot, warrant
    verification receipt) pair that the composed verdict accepts cleanly;
  * emits canonical N-Quads (zero blank nodes, sorted, LF, trailing LF),
    a JCS view-manifest and a JCS loss_manifest;
  * refuses (findings, no output) when validate_warrant_receipt reports
    anything — a projection of an unverified pair is not an evidence view.

What this is NOT yet: OAIP/BOS quadrants, BOS named-graph observer
partitioning, the full profile mapping (promotion table, relation claims),
or an adapter from live `warrant verify` output. Each absence is either an
L-code in the loss manifest or listed in the profile as open. The receipt
consumed here is built by this repo's fixtures — an sev-side construction,
NOT a Warrant contract (see proposals/ ownership note).

Stdlib only. Run:  python3 sev_projector.py   (self-vectors; exit = verdict)
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import snapshot_model as sm  # noqa: E402

XSD_INT = "http://www.w3.org/2001/XMLSchema#integer"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
PROV = "http://www.w3.org/ns/prov#"
SEV = "https://s0fractal.dev/ns/sev#"
WRT = "https://s0fractal.dev/ns/wrt#"
SIGMA = "https://s0fractal.dev/ns/sigma#"


# ---------------------------------------------------------- N-Quads encoding

def _iri(value: str) -> str:
    return "<%s>" % value


def _escape(s: str) -> str:
    """Canonical literal escaping: the ECHAR set plus \\u-escapes for every
    remaining C0 control. A raw 0x09 inside a literal is grammar-legal
    N-Quads but not canonical bytes (round-6 PR review, P1-3)."""
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04X" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _lit(value, datatype=None) -> str:
    if isinstance(value, bool):
        return '"%s"' % ("true" if value else "false")
    if isinstance(value, int):
        return '"%d"^^<%s>' % (value, XSD_INT)
    return '"%s"%s' % (_escape(str(value)),
                       ("^^<%s>" % datatype) if datatype else "")


class Graph:
    """Collects quads; serializes to canonical N-Quads bytes."""

    def __init__(self):
        self.quads = set()

    def add(self, s, p, o, g=None):
        line = "%s %s %s%s ." % (_iri(s), _iri(p), o,
                                 (" " + _iri(g)) if g else "")
        self.quads.add(line)

    def nquads(self) -> bytes:
        return ("\n".join(sorted(self.quads)) + "\n").encode("utf-8")


# ------------------------------------------------------------- IRI minting

def iri_record(wid):
    return "urn:wrt:record:" + wid


def iri_filing(entry_digest):
    return "urn:wrt:filing:" + entry_digest


def iri_blob(digest):
    return "urn:wrt:blob:" + digest


def iri_run(wid, ptr, reason_digest):
    material = (wid.encode() + b"\x00" + ptr.encode() + b"\x00"
                + reason_digest.encode())
    return "urn:sigma:run:" + sm.sha256_hex(material)


def iri_verify_graph(core_digest):
    return "urn:sev:g:verify:" + core_digest


def iri_receipt(core_digest):
    return "urn:sev:receipt:" + core_digest


# ---------------------------------------------------------------- projection

def _file_digest(*relpath):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, *relpath), "rb") as fh:
        return sm.sha256_hex(fh.read())


def _tool_digest():
    return _file_digest("snapshot_model.py")


def project(snapshot, receipt, cas) -> tuple:
    """(result dict | None, findings). Pure function of its inputs: no
    clocks, no randomness, no filesystem reads beyond the tool digest."""
    findings = sm.validate_warrant_receipt(snapshot, receipt, cas)
    if findings:
        return None, findings

    core = receipt["core"]
    core_digest = sm.sha256_hex(sm.jcs(core))
    vgraph = iri_verify_graph(core_digest)
    g = Graph()

    # verification graph: the receipt itself, mechanically produced
    rnode = iri_receipt(core_digest)
    g.add(rnode, RDF_TYPE, _iri(SEV + "VerificationReceipt"), vgraph)
    g.add(rnode, SEV + "grade", _lit(core["grade"]), vgraph)
    g.add(rnode, SEV + "ok", _lit(core["ok"]), vgraph)
    g.add(rnode, SEV + "subrootDescriptorDigest",
          _lit(core["subroot_descriptor_digest"]), vgraph)

    unverified = 0
    exclusions = []

    def _exclude(src, projection_reason):
        """Exclusions carry the receipt's issues VERBATIM — the exact ordered
        multiset with locators, severities and occurrences. Collapsing them to
        a set of codes destroyed evidence (two ID_UNSOUND at different
        occurrences became one row) and contradicted the profile, which
        requires structured issues[] (re-gate P1-2). The projector's own
        reason for skipping is a separate field, never merged into them."""
        exclusions.append({"path": src["path"],
                           "entry_digest": src["entry_digest"],
                           "projection_reason": projection_reason,
                           "issues": src["issues"]})

    for src in core["sources"]:
        if any(x["severity"] == "ERR" for x in src["issues"]):
            _exclude(src, "ERR_ISSUES")
            continue  # nothing with an ERR judgement becomes a graph node
        if src["loaded"] is not True:
            _exclude(src, "NOT_LOADED")
            continue
        if src["kind"] != "record":
            # Every non-record universe member gets a generic source entity,
            # so "projected" means projected. Rev 1 skipped genesis/other
            # silently while counting them projected — the same
            # silent-truncation class on the other union branch (P1-3).
            node = iri_blob(src["entry_digest"])
            g.add(node, RDF_TYPE, _iri(PROV + "Entity"))
            g.add(node, SEV + "sourceKind", _lit(src["kind"]))
            g.add(node, SEV + "entryDigest", _lit(src["entry_digest"]))
            continue
        if src["id_sound"] is not True:
            _exclude(src, "ID_UNSOUND")
            continue  # R4 rule: only id-sound, ERR-free records become nodes
        wid = src["computed_wid"]
        rec, filing = iri_record(wid), iri_filing(src["entry_digest"])
        g.add(rec, RDF_TYPE, _iri(WRT + "Warrant"))
        g.add(rec, PROV + "wasGeneratedBy", _iri(filing))
        g.add(filing, RDF_TYPE, _iri(WRT + "Filing"))
        g.add(rec, SEV + "entryDigest", _lit(src["entry_digest"]))
        for reason in src["reasons"]:
            run = iri_run(wid, reason["ptr"], reason["reason_digest"])
            o = reason["outcome"]
            g.add(run, RDF_TYPE, _iri(SIGMA + "CheckRun"), vgraph)
            g.add(run, SIGMA + "reasonDigest", _lit(reason["reason_digest"]), vgraph)
            g.add(run, SIGMA + "runtime", _lit(reason["runtime"]), vgraph)
            g.add(run, SIGMA + "claimedVerdict", _lit(o["claimed_verdict"]), vgraph)
            g.add(run, SIGMA + "reExecution", _lit(o["re_execution"]), vgraph)
            g.add(run, PROV + "wasInformedBy", _iri(rec), vgraph)
            if o["re_execution"] in ("matched", "mismatched"):
                g.add(run, SIGMA + "observedVerdict", _lit(o["observed_verdict"]), vgraph)
                g.add(run, SIGMA + "atpSpent", _lit(o["atp_spent"]), vgraph)
                if reason["runtime"] == "ski@v1":
                    g.add(run, PROV + "generated",
                          _iri("urn:sigma:node:" + o["observed_result"]), vgraph)
            if o["re_execution"] == "unverified":
                unverified += 1
                g.add(run, SIGMA + "failureCode", _lit(o["failure_code"]), vgraph)

    nquads = g.nquads()
    tool = _tool_digest()

    def loss(code, note):
        return {"code": code, "affects": "*", "note": note,
                "recheck": {"argv": ["python3", "model/snapshot_model.py"],
                            "tool_digest": tool}}

    receipted = {core["subroot_descriptor_digest"]}
    unjudged = sorted(w["protocol"] for w in snapshot["subroots"]
                      if w["digest"] not in receipted)
    loss_manifest = {"loss_manifest": "sev@v0", "entries": [
        loss("L-SIG", "signature validity/binding are receipt-reported; "
                      "re-verification needs envelope bytes"),
        loss("L-SETTLE", "settlement/grade not re-derivable from the graph"),
        loss("L-REEXEC", "the graph records past re-executions; it cannot re-run"),
        loss("L-CANON", "canonical bytes are not recoverable from the graph"),
        loss("L-COMPLETE", "completeness is relative to the sealed snapshot"),
    ] + ([loss("L-UNJUDGED", "unreceipted subroots: " + ", ".join(unjudged))]
         if unjudged else [])}

    sources = core["sources"]
    view_manifest = {
        "view": "sev@v0",
        "profile_revision": _file_digest("..", "profiles", "PROV-EVIDENCE-VIEW.md"),
        "projector_digest": _file_digest("sev_projector.py"),
        "bundle_root": snapshot["bundle_root"],
        "receipts": [{"protocol": "warrant",
                      "subroot_descriptor_digest": core["subroot_descriptor_digest"],
                      "receipt_core_digest": core_digest,
                      "grade": core["grade"]}],
        "unjudged_subroots": unjudged,
        "sources_in_receipts": len(sources),
        "sources_projected": len(sources) - len(exclusions),
        "sources_excluded": len(exclusions),
        "exclusions": exclusions,
        "unverified_reasons": unverified,
        "graph_digest": sm.sha256_hex(nquads),
        "loss_manifest_digest": sm.sha256_hex(sm.jcs(loss_manifest)),
        "completeness": "relative-to-snapshot",
        "verdict_scope": "projection-of-verification-receipts",
    }
    return {"nquads": nquads, "view_manifest": view_manifest,
            "loss_manifest": loss_manifest}, []


# ------------------------------------------------------------------ fixture

def fixture():
    """An id-sound, ERR-free end-to-end triple (snapshot, receipt, cas)."""
    reason_obj = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
                  "verdict": "pass", "transcript": "b" * 64}
    body = {"warrant": "0.2", "decision": "accept", "subject": {},
            "under": [], "because": [reason_obj], "evidence": [],
            "actor": {"id": "x"}, "prior": [], "ts": 1}
    record = {"body": body,
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    wid = sm.sha256_hex(sm.jcs(body))
    record_bytes = sm.jcs(record)
    files = {".warrants/records/%s.json" % wid: record_bytes,
             ".warrants/blobs/p": b"policy"}
    cas = {sm.sha256_hex(v): v for v in files.values()}
    uni = sm.seal_universe(files)
    contract = {"name": "warrant", "version": "0.4",
                "spec_digest": sm.sha256_hex(b"spec")}
    d = sm.subroot_descriptor("warrant", contract, ".warrants/", uni)
    snap = sm.snapshot_object([d], [])
    by_path = {e["path"]: e["sha256"] for e in uni}
    rec_path = ".warrants/records/%s.json" % wid
    sources = sorted([
        {"kind": "blob", "path": ".warrants/blobs/p",
         "entry_digest": by_path[".warrants/blobs/p"], "loaded": True, "issues": []},
        {"kind": "record", "path": rec_path, "entry_digest": by_path[rec_path],
         "loaded": True, "claimed_wid": wid, "computed_wid": wid,
         "id_sound": True, "settlement": [], "signatures": [], "issues": [],
         "reasons": [{"ptr": "/because/0", "kind": "check", "runtime": "ski@v1",
                      "reason_digest": sm.sha256_hex(sm.jcs(reason_obj)),
                      "outcome": {"re_execution": "matched",
                                  "claimed_verdict": "pass",
                                  "observed_verdict": "pass",
                                  "observed_result": "e" * 64, "atp_spent": 7,
                                  "failure_code": None}}]},
    ], key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
    core = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(d),
            "grade": "base", "trust_config_digest": None,
            "execution_policy": {"runtimes": [
                {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                 "semantics_digest": sm.sha256_hex(b"book1"),
                 "budget_unit": "atp", "ceiling": 1000}]},
            "ok": True, "errors": 0, "warnings": 0, "global_issues": [],
            "sources": sources}
    receipt = {"receipt": "warrant.verification-receipt@v0", "core": core,
               "producer": {"impl": "sev-fixture", "artifact_digest": None,
                            "spec": "0.4", "report_digest": "f" * 64,
                            "local_notes": []}}
    return snap, receipt, cas


# ------------------------------------------------------------------ vectors

def run_vectors():
    snap, receipt, cas = fixture()

    result, f = project(snap, receipt, cas)
    sm.check_equal("fixture projects with no findings", f, [])
    sm.check_true("projection emitted quads",
                  lambda: result is not None and len(result["nquads"]) > 0)
    if result is None:
        return
    nq = result["nquads"]

    sm.check_true("N4: zero blank-node terms",
                  lambda: not any(tok.startswith("_:")
                                  for line in nq.decode().splitlines()
                                  for tok in line.split(" ")))
    sm.check_true("quads sorted, LF-terminated",
                  lambda: nq.decode().splitlines() == sorted(nq.decode().splitlines())
                  and nq.endswith(b"\n") and not nq.endswith(b"\n\n"))
    sm.check_equal("graph digest binds bytes",
                   result["view_manifest"]["graph_digest"], sm.sha256_hex(nq))

    result2, _ = project(snap, receipt, cas)
    sm.check_equal("determinism: second run byte-identical",
                   result2["nquads"], nq)

    # cross-process determinism: a fresh interpreter must emit the same bytes
    code = ("import sev_projector as p, snapshot_model as m, sys, hashlib\n"
            "s, r, c = p.fixture()\n"
            "res, f = p.project(s, r, c)\n"
            "sys.stdout.write(res['view_manifest']['graph_digest'])\n")
    proc = subprocess.run([sys.executable, "-c", code],
                          cwd=os.path.dirname(os.path.abspath(__file__)),
                          capture_output=True, text=True)
    sm.check_equal("determinism: fresh process, same graph digest",
                   proc.stdout.strip(), sm.sha256_hex(nq))

    # manifests are canonical I-JSON
    sm.check_true("view/loss manifests JCS-serializable",
                  lambda: bool(sm.jcs(result["view_manifest"]))
                  and bool(sm.jcs(result["loss_manifest"])))
    sm.check_true("loss recheck is argv + tool digest, not a shell string",
                  lambda: all(isinstance(e["recheck"]["argv"], list)
                              and sm.HEX64.match(e["recheck"]["tool_digest"])
                              for e in result["loss_manifest"]["entries"]))

    # refusal half: any verdict finding means NO output at all
    bad = json.loads(json.dumps(receipt))
    bad["core"]["sources"] = []
    bad["core"].update(ok=True, errors=0)
    res_bad, f_bad = project(snap, bad, cas)
    sm.check_true("truncated receipt -> refusal, no partial output",
                  lambda: res_bad is None
                  and any(x["code"] == "SOURCE_MISSING_FOR_MEMBER" for x in f_bad))

    # mutation moves the graph digest
    snap2, receipt2, cas2 = fixture()
    receipt2["core"]["sources"][1]["reasons"][0]["outcome"]["atp_spent"] = 8
    res2, f2 = project(snap2, receipt2, cas2)
    sm.check_true("outcome mutation -> different graph digest",
                  lambda: f2 == [] and res2["view_manifest"]["graph_digest"]
                  != sm.sha256_hex(nq))

    # unreceipted second subroot -> L-UNJUDGED
    files_b = {".b/z": b"z"}
    d_b = sm.subroot_descriptor("bos", {"name": "bos", "version": "0.4",
                                        "spec_digest": None}, ".b/",
                                sm.seal_universe(files_b))
    snap3, receipt3, cas3 = fixture()
    wrapped = [{k: v for k, v in w.items() if k != "digest"}
               for w in snap3["subroots"]]
    snap3b = sm.snapshot_object(wrapped + [d_b], [])
    cas3.update({sm.sha256_hex(b"z"): b"z"})
    res3, f3 = project(snap3b, receipt3, cas3)
    sm.check_true("unreceipted subroot -> L-UNJUDGED in loss manifest",
                  lambda: f3 == [] and any(
                      e["code"] == "L-UNJUDGED" and "bos" in e["note"]
                      for e in res3["loss_manifest"]["entries"]))
    sm.check_true("unjudged subroots listed in view manifest",
                  lambda: res3["view_manifest"]["unjudged_subroots"] == ["bos"])

    # round-6 PR review, P1-3: canonical literal escaping
    sm.check_equal("tab escapes as \\t", _lit("a\tb"), '"a\\tb"')
    sm.check_equal("other C0 controls escape as \\uXXXX",
                   _lit("a\x01b"), '"a\\u0001b"')
    sm.check_true("no raw control bytes in N-Quads except LF",
                  lambda: not any(b < 0x20 and b != 0x0A for b in nq))

    # round-6 PR review, P1-2: honest negative receipt -> truthful manifest
    def _negative(r):
        src = r["core"]["sources"][1]
        src.update(claimed_wid=None, id_sound=False,
                   issues=[{"code": "ID_UNSOUND", "severity": "ERR",
                            "at": {"kind": "path", "value": src["path"]}}])
        r["core"].update(ok=False, errors=1)
    snap4, receipt4, cas4 = fixture()
    _negative(receipt4)
    res4, f4 = project(snap4, receipt4, cas4)
    sm.check_equal("negative receipt still projects (an honest ERR is evidence)",
                   f4, [])
    vm = res4["view_manifest"]
    sm.check_true("manifest counts the exclusion truthfully",
                  lambda: vm["sources_excluded"] == 1
                  and vm["sources_projected"] == 1
                  and vm["sources_projected"] + vm["sources_excluded"]
                  == vm["sources_in_receipts"]
                  and [x["code"] for x in vm["exclusions"][0]["issues"]]
                  == ["ID_UNSOUND"])
    sm.check_true("excluded record has no graph node",
                  lambda: b"urn:wrt:record:" not in res4["nquads"])

    # re-gate P2-2: digests must EQUAL the real file bytes, not merely look
    # like hex64 — a constant would have satisfied the old test
    sm.check_equal("profile_revision equals the profile document's digest",
                   vm["profile_revision"],
                   _file_digest("..", "profiles", "PROV-EVIDENCE-VIEW.md"))
    sm.check_equal("projector_digest equals this file's digest",
                   vm["projector_digest"], _file_digest("sev_projector.py"))

    # re-gate P1-2: exclusions carry the receipt's issues verbatim
    exc = res4["view_manifest"]["exclusions"][0]
    src_issues = receipt4["core"]["sources"][1]["issues"]
    sm.check_equal("exclusion preserves the ordered issue multiset",
                   exc["issues"], src_issues)
    sm.check_equal("projection reason is separate from the issues",
                   exc["projection_reason"], "ERR_ISSUES")

    def _two_occurrences(r):
        src = r["core"]["sources"][1]
        at = {"kind": "path", "value": src["path"]}
        src.update(claimed_wid=None, id_sound=False, issues=[
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=0)},
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=1)}])
        r["core"].update(ok=False, errors=2)
    snap5, receipt5, cas5 = fixture()
    _two_occurrences(receipt5)
    res5, f5 = project(snap5, receipt5, cas5)
    sm.check_true("two same-code issues at distinct occurrences both survive",
                  lambda: f5 == []
                  and len(res5["view_manifest"]["exclusions"][0]["issues"]) == 2)

    # re-gate P1-3: non-record sources are actually projected, not just counted
    sm.check_true("blob/genesis/other emit a source entity",
                  lambda: b"sourceKind" in nq)
    snap6, receipt6, cas6 = fixture()
    other = dict(receipt6["core"]["sources"][0], kind="other")
    receipt6["core"]["sources"][0] = other
    res6, f6 = project(snap6, receipt6, cas6)
    vm6 = res6["view_manifest"]
    sm.check_true("kind:other is projected, and the count says so honestly",
                  lambda: f6 == [] and vm6["sources_projected"] == 2
                  and vm6["sources_excluded"] == 0
                  and other["entry_digest"].encode() in res6["nquads"])

    # re-gate P1-1: undeclared runtime cannot earn a matched verdict
    snap7, receipt7, cas7 = fixture()
    reason_obj = {"kind": "check", "runtime": "evil@v1", "check": "a" * 64,
                  "verdict": "pass", "transcript": "b" * 64}
    body = {"warrant": "0.2", "decision": "accept", "subject": {}, "under": [],
            "because": [reason_obj], "evidence": [], "actor": {"id": "x"},
            "prior": [], "ts": 1}
    record = {"body": body,
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    wid = sm.sha256_hex(sm.jcs(body))
    files = {".warrants/records/%s.json" % wid: sm.jcs(record),
             ".warrants/blobs/p": b"policy"}
    cas7 = {sm.sha256_hex(v): v for v in files.values()}
    uni = sm.seal_universe(files)
    contract = {"name": "warrant", "version": "0.4",
                "spec_digest": sm.sha256_hex(b"spec")}
    d7 = sm.subroot_descriptor("warrant", contract, ".warrants/", uni)
    snap7 = sm.snapshot_object([d7], [])
    by_path = {e["path"]: e["sha256"] for e in uni}
    rec_path = ".warrants/records/%s.json" % wid
    receipt7["core"].update(
        subroot_descriptor_digest=sm.subroot_descriptor_digest(d7),
        sources=sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": by_path[".warrants/blobs/p"], "loaded": True,
             "issues": []},
            {"kind": "record", "path": rec_path, "entry_digest": by_path[rec_path],
             "loaded": True, "claimed_wid": wid, "computed_wid": wid,
             "id_sound": True, "settlement": [], "signatures": [], "issues": [],
             "reasons": [{"ptr": "/because/0", "kind": "check",
                          "runtime": "evil@v1",
                          "reason_digest": sm.sha256_hex(sm.jcs(reason_obj)),
                          "outcome": {"re_execution": "matched",
                                      "claimed_verdict": "pass",
                                      "observed_verdict": "pass",
                                      "observed_result": "e" * 64,
                                      "atp_spent": 7, "failure_code": None}}]},
        ], key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"])))
    res7, f7 = project(snap7, receipt7, cas7)
    sm.check_true("fully committed undeclared runtime -> refusal, no graph",
                  lambda: res7 is None
                  and any(x["code"] == "RUNTIME_NOT_DECLARED" for x in f7))

    # re-gate P2-1: the empty-corpus guard needs its own negative control
    code_guard = (
        "import json, os, shutil, subprocess, sys, tempfile\n"
        "here = os.path.abspath('.')\n"
        "d = tempfile.mkdtemp()\n"
        "shutil.copy(os.path.join(here, '..', 'conformance', 'replay.py'),\n"
        "            os.path.join(d, 'replay.py'))\n"
        "os.makedirs(os.path.join(d, '..', 'model'), exist_ok=True)\n"
        "json.dump({'vectors': 'x', 'cases': []},\n"
        "          open(os.path.join(d, 'parse-strict.vectors.json'), 'w'))\n"
        "p = subprocess.run([sys.executable, os.path.join(d, 'replay.py')],\n"
        "                   capture_output=True, text=True,\n"
        "                   env=dict(os.environ, PYTHONPATH=os.path.join(here)))\n"
        "sys.exit(0 if p.returncode == 1 and 'vacuous' in p.stdout else 1)\n")
    proc_guard = subprocess.run([sys.executable, "-c", code_guard],
                                cwd=os.path.dirname(os.path.abspath(__file__)),
                                capture_output=True, text=True)
    sm.check_equal("empty fixture corpus fails the replay harness (exit 1)",
                   proc_guard.returncode, 0)


def main():
    run_vectors()
    print()
    if sm.FAILURES:
        print("FAILED: %d vector(s): %s" % (len(sm.FAILURES), ", ".join(sm.FAILURES)))
        return 1
    print("ALL PASS (sev projector MVP: first real SEV output)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
