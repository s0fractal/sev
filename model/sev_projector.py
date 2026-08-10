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


def iri_source(subroot_digest, path, entry_digest):
    """Source OCCURRENCE identity — `(subroot, path, entry_digest)`.

    Two paths holding identical bytes are two sources; keying on the digest
    alone merged them into one node with two `sourceKind` values. And since
    `sourceKind` is a *contract-derived* assertion, the occurrence is scoped
    to the subroot descriptor that derived it — otherwise two snapshots with
    different `contract.spec_digest` (hence different descriptor digests)
    produce identical source IRIs, dissolving the domain separation the
    descriptor exists to provide (re-gate P2)."""
    return "urn:sev:source:" + sm.sha256_hex(
        subroot_digest.encode("ascii") + b"\x00" + path.encode("utf-8")
        + b"\x00" + entry_digest.encode("ascii"))


def iri_reason(wid, ptr, reason_digest):
    """The reason as a stable fact of the record: same across every
    verification of the same bytes."""
    return "urn:wrt:reason:" + sm.sha256_hex(
        wid.encode() + b"\x00" + ptr.encode() + b"\x00" + reason_digest.encode())


def iri_run(core_digest, wid, ptr, reason_digest, semantics_digest):
    """One EXECUTION of that reason. Two receipts re-running the same reason
    under different semantics are two runs; keying only on the reason made
    them one prov:Activity once the datasets were merged, and a named graph
    does not localize an IRI (re-gate P1-2)."""
    return "urn:sigma:run:" + sm.sha256_hex(
        core_digest.encode("ascii") + b"\x00" + wid.encode() + b"\x00"
        + ptr.encode() + b"\x00" + reason_digest.encode() + b"\x00"
        + str(semantics_digest).encode("ascii"))


def iri_verify_graph(core_digest):
    return "urn:sev:g:verify:" + core_digest


def iri_receipt(core_digest):
    return "urn:sev:receipt:" + core_digest


def _committed_reasons(cas, src):
    """{ptr: committed reason object} from the record's committed bytes.

    The receipt names the reason by digest; the check blob it used lives only
    in those bytes, so `prov:used` and the pointer link can be emitted
    faithfully instead of being dropped (re-gate P1-2)."""
    out = {}
    if cas is None:
        return out
    try:
        raw = sm.cas_resolve(cas, src["entry_digest"])
    except (KeyError, sm.SealViolation):
        return out
    obj, _f = sm.parse_strict(raw)
    body = obj.get("body") if isinstance(obj, dict) else None
    because = body.get("because") if isinstance(body, dict) else None
    if not isinstance(because, list):
        return out
    for i, item in enumerate(because):
        if isinstance(item, dict):
            out["/because/%d" % i] = item
    return out


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
    subroot_digest = core["subroot_descriptor_digest"]
    runtime_semantics = {r["runtime"]: r["semantics_digest"]
                         for r in core["execution_policy"]["runtimes"]}

    def _exclude(src, projection_reason):
        """Exclusions carry the receipt's issues VERBATIM — the exact ordered
        multiset with locators, severities and occurrences. Collapsing them to
        a set of codes destroyed evidence (two ID_UNSOUND at different
        occurrences became one row) and contradicted the profile, which
        requires structured issues[] (re-gate P1-2). The projector's own
        reason for skipping is a separate field, never merged into them."""
        # Deep copy: keeping the receipt's list by reference made the emitted
        # manifest mutable through its input — a later edit to the receipt
        # silently rewrote already-issued evidence. An evidence artifact must
        # detach from its source at emission (re-gate P1-2).
        exclusions.append({"path": src["path"],
                           "entry_digest": src["entry_digest"],
                           "projection_reason": projection_reason,
                           "issues": json.loads(json.dumps(src["issues"]))})

    for src in core["sources"]:
        if any(x["severity"] == "ERR" for x in src["issues"]):
            _exclude(src, "ERR_ISSUES")
            continue  # nothing with an ERR judgement becomes a graph node
        if src["loaded"] is not True:
            _exclude(src, "NOT_LOADED")
            continue
        if src["kind"] != "record":
            # Every non-record universe member gets a source-occurrence
            # entity, so "projected" means projected. Occurrence identity is
            # (path, entry_digest); the content entity keyed by digest alone
            # is linked, not conflated — two paths with identical bytes are
            # two occurrences of one content.
            node = iri_source(subroot_digest, src["path"], src["entry_digest"])
            g.add(node, RDF_TYPE, _iri(SEV + "Source"))
            g.add(node, SEV + "path", _lit(src["path"]))
            g.add(node, SEV + "sourceKind", _lit(src["kind"]))
            g.add(node, SEV + "entryDigest", _lit(src["entry_digest"]))
            g.add(node, SEV + "inSubroot", _lit(subroot_digest))
            content = iri_blob(src["entry_digest"])
            g.add(content, RDF_TYPE, _iri(PROV + "Entity"))
            g.add(node, PROV + "specializationOf", _iri(content))
            continue
        if src["id_sound"] is not True:
            _exclude(src, "ID_UNSOUND")
            continue  # R4 rule: only id-sound, ERR-free records become nodes
        wid = src["computed_wid"]
        rec, filing = iri_record(wid), iri_filing(src["entry_digest"])
        occ = iri_source(subroot_digest, src["path"], src["entry_digest"])
        g.add(rec, RDF_TYPE, _iri(WRT + "Warrant"))
        g.add(rec, PROV + "wasGeneratedBy", _iri(filing))
        g.add(filing, RDF_TYPE, _iri(WRT + "Filing"))
        g.add(rec, SEV + "entryDigest", _lit(src["entry_digest"]))
        # the same record content may be sealed at several paths: each path
        # is its own source occurrence pointing at the one record identity
        g.add(occ, RDF_TYPE, _iri(SEV + "Source"))
        g.add(occ, SEV + "path", _lit(src["path"]))
        g.add(occ, SEV + "sourceKind", _lit("record"))
        g.add(occ, SEV + "entryDigest", _lit(src["entry_digest"]))
        g.add(occ, SEV + "inSubroot", _lit(subroot_digest))
        g.add(occ, PROV + "specializationOf", _iri(rec))
        committed = _committed_reasons(cas, src)
        for reason in src["reasons"]:
            o = reason["outcome"]
            rt = reason["runtime"]
            sem = runtime_semantics.get(rt)
            # the reason is a stable fact of the record; the run is one
            # execution of it under one declared semantics
            reason_node = iri_reason(wid, reason["ptr"], reason["reason_digest"])
            g.add(reason_node, RDF_TYPE, _iri(WRT + "Reason"))
            g.add(reason_node, SEV + "pointer", _lit(reason["ptr"]))
            g.add(reason_node, SIGMA + "reasonDigest", _lit(reason["reason_digest"]))
            g.add(reason_node, SIGMA + "runtime", _lit(rt))
            g.add(reason_node, SIGMA + "claimedVerdict", _lit(o["claimed_verdict"]))
            g.add(rec, WRT + "hasReason", _iri(reason_node))
            check_blob = (committed.get(reason["ptr"]) or {}).get("check")
            if check_blob:
                g.add(reason_node, PROV + "used", _iri(iri_blob(check_blob)))

            run = iri_run(core_digest, wid, reason["ptr"],
                          reason["reason_digest"], sem)
            g.add(run, RDF_TYPE, _iri(SIGMA + "CheckRun"), vgraph)
            g.add(run, PROV + "used", _iri(reason_node), vgraph)
            if check_blob:
                g.add(run, PROV + "used", _iri(iri_blob(check_blob)), vgraph)
            if sem:
                g.add(run, SIGMA + "semanticsDigest", _lit(sem), vgraph)
            g.add(run, SEV + "receiptCoreDigest", _lit(core_digest), vgraph)
            g.add(run, SIGMA + "reExecution", _lit(o["re_execution"]), vgraph)
            g.add(run, PROV + "wasInformedBy", _iri(rec), vgraph)
            if o["re_execution"] in ("matched", "mismatched"):
                g.add(run, SIGMA + "observedVerdict", _lit(o["observed_verdict"]), vgraph)
                g.add(run, SIGMA + "atpSpent", _lit(o["atp_spent"]), vgraph)
                if rt == "ski@v1":
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

def fixture(extra_files=None, misfiled_as=None):
    """An id-sound, ERR-free end-to-end triple (snapshot, receipt, cas).

    `extra_files` adds further universe members (paths under the prefix); the
    receipt reports each with the kind the store layout implies.
    `misfiled_as` seals the record under `records/<that hex64>.json`, i.e. an
    honestly id-unsound record: the filename claims one WarrantID while the
    body canonicalizes to another. This is the ONLY way to model id-unsound
    now that both the filename claim and the body hash are derived.
    """
    reason_obj = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
                  "verdict": "pass", "transcript": "b" * 64}
    body = {"warrant": "0.2", "decision": "accept", "subject": {},
            "under": [], "because": [reason_obj], "evidence": [],
            "actor": {"id": "x"}, "prior": [], "ts": 1}
    record = {"body": body,
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    wid = sm.sha256_hex(sm.jcs(body))
    record_bytes = sm.jcs(record)
    filed_as = misfiled_as or wid
    files = {".warrants/records/%s.json" % filed_as: record_bytes,
             ".warrants/blobs/p": b"policy"}
    files.update(extra_files or {})
    cas = {sm.sha256_hex(v): v for v in files.values()}
    uni = sm.seal_universe(files)
    contract = {"name": "warrant", "version": "0.4",
                "spec_digest": sm.sha256_hex(b"spec")}
    d = sm.subroot_descriptor("warrant", contract, ".warrants/", uni)
    snap = sm.snapshot_object([d], [])
    by_path = {e["path"]: e["sha256"] for e in uni}
    rec_path = ".warrants/records/%s.json" % filed_as
    sources = sorted([
        {"kind": "blob", "path": ".warrants/blobs/p",
         "entry_digest": by_path[".warrants/blobs/p"], "loaded": True, "issues": []},
        {"kind": "record", "path": rec_path, "entry_digest": by_path[rec_path],
         "loaded": True, "claimed_wid": filed_as, "computed_wid": wid,
         "id_sound": filed_as == wid, "settlement": [], "signatures": [],
         "issues": ([] if filed_as == wid else
                    [{"code": "ID_UNSOUND", "severity": "ERR",
                      "at": {"kind": "path", "value": rec_path}}]),
         "reasons": [{"ptr": "/because/0", "kind": "check", "runtime": "ski@v1",
                      "reason_digest": sm.sha256_hex(sm.jcs(reason_obj)),
                      "outcome": {"re_execution": "matched",
                                  "claimed_verdict": "pass",
                                  "observed_verdict": "pass",
                                  "observed_result": "e" * 64, "atp_spent": 7,
                                  "failure_code": None}}]},
    ] + [{"kind": sm.classify_warrant_source(p, ".warrants/")[0], "path": p,
          "entry_digest": by_path[p], "loaded": True, "issues": []}
         for p in sorted(extra_files or {})],
        key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
    core = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(d),
            "grade": "base", "trust_config_digest": None,
            "execution_policy": {"runtimes": [
                {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                 "semantics_digest": sm.sha256_hex(b"book1"),
                 "budget_unit": "atp", "ceiling": 1000}]},
            "ok": filed_as == wid, "errors": 0 if filed_as == wid else 1,
            "warnings": 0, "global_issues": [], "sources": sources}
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
    # An honest id-unsound record: filed under one WarrantID, body hashes to
    # another. Both halves are now derived (filename claim + body re-hash),
    # so this is the only shape that can be id-unsound without lying.
    snap4, receipt4, cas4 = fixture(misfiled_as="b" * 64)
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
        src["issues"] = [
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=0)},
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=1)}]
        r["core"].update(ok=False, errors=2)
    snap5, receipt5, cas5 = fixture(misfiled_as="b" * 64)
    _two_occurrences(receipt5)
    res5, f5 = project(snap5, receipt5, cas5)
    sm.check_true("two same-code issues at distinct occurrences both survive",
                  lambda: f5 == []
                  and len(res5["view_manifest"]["exclusions"][0]["issues"]) == 2)

    # re-gate P1-3: non-record sources are actually projected, not just counted
    sm.check_true("blob/genesis/other emit a source entity",
                  lambda: b"sourceKind" in nq)
    # a genuine "other" member (not a relabelling — the classifier derives it)
    snap6, receipt6, cas6 = fixture(extra_files={".warrants/README": b"hi"})
    res6, f6 = project(snap6, receipt6, cas6)
    vm6 = res6["view_manifest"]
    other_digest = sm.sha256_hex(b"hi")
    sm.check_true("kind:other is projected, and the count says so honestly",
                  lambda: f6 == [] and vm6["sources_projected"] == 3
                  and vm6["sources_excluded"] == 0
                  and other_digest.encode() in res6["nquads"])

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

    # re-gate P1-2: emitted evidence must detach from its input
    snap8, receipt8, cas8 = fixture(misfiled_as="b" * 64)
    res8, _f8 = project(snap8, receipt8, cas8)
    before = json.dumps(res8["view_manifest"], sort_keys=True)
    receipt8["core"]["sources"][1]["issues"][0]["code"] = "MUTATED_AFTER_EMISSION"
    receipt8["core"]["sources"][1]["issues"].append(
        {"code": "APPENDED", "severity": "ERR",
         "at": {"kind": "global", "value": "store"}})
    sm.check_equal("manifest is immune to post-projection input mutation",
                   json.dumps(res8["view_manifest"], sort_keys=True), before)

    # re-gate P1-1: source-role confusion is refused by the composed verdict
    def _strip_to_base(src, kind):
        for k in list(src):
            if k not in sm.SOURCE_BASE_KEYS:
                del src[k]
        src["kind"] = kind
    snap9, receipt9, cas9 = fixture()
    _strip_to_base(receipt9["core"]["sources"][1], "other")
    res9, f9 = project(snap9, receipt9, cas9)
    sm.check_true("record relabelled 'other' -> refusal, no generic entity",
                  lambda: res9 is None
                  and any(x["code"] == "SOURCE_KIND_MISMATCH" for x in f9))

    # re-gate P1-1: stale computed_wid over an edited body
    reason_obj = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
                  "verdict": "pass", "transcript": "b" * 64}
    body_v2 = {"warrant": "0.2", "decision": "accept", "subject": {},
               "under": [], "because": [reason_obj], "evidence": [],
               "actor": {"id": "x"}, "prior": [], "ts": 2}   # ts 1 -> 2
    rec_v2 = {"body": body_v2,
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    snapA, receiptA, casA = fixture()
    old_src = receiptA["core"]["sources"][1]
    old_path, old_wid = old_src["path"], old_src["computed_wid"]
    filesA = {old_path: sm.jcs(rec_v2), ".warrants/blobs/p": b"policy"}
    casA = {sm.sha256_hex(v): v for v in filesA.values()}
    uniA = sm.seal_universe(filesA)
    dA = sm.subroot_descriptor("warrant",
                               {"name": "warrant", "version": "0.4",
                                "spec_digest": sm.sha256_hex(b"spec")},
                               ".warrants/", uniA)
    snapA = sm.snapshot_object([dA], [])
    by_pathA = {e["path"]: e["sha256"] for e in uniA}
    for s in receiptA["core"]["sources"]:
        s["entry_digest"] = by_pathA[s["path"]]        # snapshot rebuilt...
    receiptA["core"]["subroot_descriptor_digest"] = sm.subroot_descriptor_digest(dA)
    # ...but the receipt still reports the OLD WarrantID for the new body
    sm.check_equal("fixture keeps the stale WID", old_src["computed_wid"], old_wid)
    resA, fA = project(snapA, receiptA, casA)
    sm.check_true("stale computed_wid over an edited body -> refusal",
                  lambda: resA is None
                  and any(x["code"] == "COMPUTED_WID_MISMATCH" for x in fA))

    # re-gate P1-2: two paths, identical bytes -> two source occurrences
    snapB, receiptB, casB = fixture(
        extra_files={".warrants/genesis.json": b"policy"})   # same bytes as blobs/p
    resB, fB = project(snapB, receiptB, casB)
    sm.check_equal("identical-byte sources both validate", fB, [])
    lines = resB["nquads"].decode().splitlines()
    src_nodes = {ln.split(" ")[0] for ln in lines if "sev#Source" in ln}
    kinds = {ln.split(" ")[0]: ln for ln in lines if "sev#sourceKind" in ln}
    sm.check_true("two distinct source-occurrence nodes for identical bytes",
                  lambda: len(src_nodes) == 3 and len(kinds) == 3)
    sm.check_true("each occurrence carries exactly one kind and its own path",
                  lambda: sum(1 for ln in lines if "sev#sourceKind" in ln) == 3
                  and sum(1 for ln in lines if "sev#path" in ln) == 3)
    sm.check_true("both occurrences specialize the one content entity",
                  lambda: sum(1 for ln in lines
                              if "specializationOf" in ln
                              and sm.sha256_hex(b"policy") in ln) == 2)

    # re-gate P1-1: only a committed `check` under a registry runtime may be
    # a CheckRun — matching the bytes is not the same as being allowed
    def _committed_variant(kind, runtime, body_version="0.2", policy_rt=None):
        rob = {"kind": kind, "runtime": runtime, "check": "a" * 64,
               "verdict": "pass", "transcript": "b" * 64}
        if kind == "prose":
            rob = {"kind": "prose", "text": "because I say so"}
        bod = {"warrant": body_version, "decision": "accept", "subject": {},
               "under": [], "because": [rob], "evidence": [],
               "actor": {"id": "x"}, "prior": [], "ts": 1}
        recd = {"body": bod,
                "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
        w = sm.sha256_hex(sm.jcs(bod))
        fl = {".warrants/records/%s.json" % w: sm.jcs(recd),
              ".warrants/blobs/p": b"policy"}
        cs = {sm.sha256_hex(v): v for v in fl.values()}
        un = sm.seal_universe(fl)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        rp = ".warrants/records/%s.json" % w
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True, "issues": []},
            {"kind": "record", "path": rp, "entry_digest": bp[rp], "loaded": True,
             "claimed_wid": w, "computed_wid": w, "id_sound": True,
             "settlement": [], "signatures": [], "issues": [],
             "reasons": [{"ptr": "/because/0", "kind": rob["kind"],
                          "runtime": rob.get("runtime", runtime),
                          "reason_digest": sm.sha256_hex(sm.jcs(rob)),
                          "outcome": {"re_execution": "matched",
                                      "claimed_verdict": "pass",
                                      "observed_verdict": "pass",
                                      "observed_result": "e" * 64,
                                      "atp_spent": 7, "failure_code": None}}]},
        ], key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": [
                  {"runtime": policy_rt or runtime, "semantics": "s",
                   "semantics_digest": sm.sha256_hex(b"book1"),
                   "budget_unit": "atp", "ceiling": 1000}]},
              "ok": True, "errors": 0, "warnings": 0, "global_issues": [],
              "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    for kind, runtime, ver, code in [
            # a committed prose reason carries no runtime at all, so it is
            # caught one step earlier — the receipt cannot even name a runtime
            # for it without contradicting the bytes
            ("prose", "ski@v1", "0.2", "REASON_ROLE_MISMATCH"),
            ("evil", "ski@v1", "0.2", "REASON_NOT_A_CHECK"),
            ("check", "evil@v1", "0.2", "RUNTIME_NOT_IN_REGISTRY"),
            ("check", "ski@v1", "0.1", "RUNTIME_NOT_IN_REGISTRY"),
            ("check", "ski@v1", "9.9", "UNKNOWN_BODY_VERSION")]:
        snX, recX, casX = _committed_variant(kind, runtime, ver)
        resX, fX = project(snX, recX, casX)
        sm.check_true("committed %s/%s in a %s body -> %s"
                      % (kind, runtime, ver, code),
                      lambda resX=resX, fX=fX, code=code:
                      resX is None and any(x["code"] == code for x in fX))

    # re-gate P1-2: CheckRun carries semantics and its execution input
    sm.check_true("CheckRun emits semanticsDigest, prov:used and a pointer",
                  lambda: b"semanticsDigest" in nq and b"prov#used" in nq
                  and b"sev#pointer" in nq and b"wrt:reason:" in nq)
    snapC, receiptC, casC = fixture()
    receiptC["core"]["execution_policy"]["runtimes"][0]["semantics_digest"] = \
        sm.sha256_hex(b"book1-B")
    resC, fC = project(snapC, receiptC, casC)
    runs_a = {ln.split(" ")[0] for ln in nq.decode().splitlines()
              if "sigma#CheckRun" in ln}
    runs_b = {ln.split(" ")[0] for ln in resC["nquads"].decode().splitlines()
              if "sigma#CheckRun" in ln}
    reasons_a = {ln.split(" ")[0] for ln in nq.decode().splitlines()
                 if "wrt#Reason" in ln}
    reasons_b = {ln.split(" ")[0] for ln in resC["nquads"].decode().splitlines()
                 if "wrt#Reason" in ln}
    sm.check_true("different semantics -> different CheckRun IRIs",
                  lambda: fC == [] and runs_a and runs_b and runs_a != runs_b)
    sm.check_equal("the reason itself is stable across semantics",
                   reasons_a, reasons_b)

    # re-gate P2: source occurrence scoped to the subroot descriptor
    snapD, receiptD, casD = fixture()
    dD = sm.subroot_descriptor(
        "warrant", {"name": "warrant", "version": "0.4",
                    "spec_digest": sm.sha256_hex(b"OTHER-SPEC")},
        ".warrants/",
        [{k: v for k, v in e.items()}
         for e in snapD["subroots"][0]["universe"]])
    snapD2 = sm.snapshot_object([dD], [])
    receiptD["core"]["subroot_descriptor_digest"] = sm.subroot_descriptor_digest(dD)
    resD, fD = project(snapD2, receiptD, casD)
    srcs_a = {ln.split(" ")[0] for ln in nq.decode().splitlines()
              if "sev#Source" in ln}
    srcs_d = {ln.split(" ")[0] for ln in resD["nquads"].decode().splitlines()
              if "sev#Source" in ln}
    sm.check_true("same bytes under a different contract -> different source IRIs",
                  lambda: fD == [] and srcs_a and srcs_d and srcs_a != srcs_d)
    sm.check_true("sources declare their subroot",
                  lambda: b"sev#inSubroot" in resD["nquads"])

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
