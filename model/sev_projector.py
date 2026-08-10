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
        + (semantics_digest or "").encode("ascii"))
    # absent semantics contributes an empty field, never the literal
    # "None": digests are fixed-length, so "" is unambiguous


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
    # ONE validation pass produces both the verdict and the parsed view it
    # was rendered over. Re-reading the CAS afterwards let a stateful
    # resolver hand the projector different bytes than the verdict judged
    # (re-gate P1-4) — the projector now touches no store at all.
    view = {}
    findings = sm.validate_warrant_receipt(snapshot, receipt, cas, view=view)
    if findings:
        return None, findings
    # From here on the projector reads ONLY the validated view: the private
    # frozen copies the verdict was actually rendered over. Reading the
    # caller's receipt/snapshot again would reopen the verdict->assertion
    # seam on the objects themselves (re-gate P1-1).
    committed_by_path = view.get("committed", {})
    snapshot = view["snapshot"]
    receipt = view["receipt"]

    core = view["core"]
    core_digest = sm.sha256_hex(sm.jcs(core))
    vgraph = iri_verify_graph(core_digest)
    g = Graph()

    emitted_kinds = set()

    # verification graph: the receipt itself, mechanically produced
    rnode = iri_receipt(core_digest)
    g.add(rnode, RDF_TYPE, _iri(SEV + "VerificationReceipt"), vgraph)
    emitted_kinds.add("verification-receipt")
    g.add(rnode, SEV + "grade", _lit(core["grade"]), vgraph)
    g.add(rnode, SEV + "ok", _lit(core["ok"]), vgraph)
    g.add(rnode, SEV + "subrootDescriptorDigest",
          _lit(core["subroot_descriptor_digest"]), vgraph)

    unverified = 0
    exclusions = []
    subroot_digest = core["subroot_descriptor_digest"]
    runtime_semantics = {r["runtime"]: r["semantics_digest"]
                         for r in core["execution_policy"]["runtimes"]}
    # what a check reference may legitimately resolve to: loaded, ERR-free
    # blob sources of THIS subroot — never a README, a record, or a source
    # the manifest simultaneously excludes
    source_digests = sm.available_blob_digests(core)

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
            emitted_kinds.add("source")
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
        emitted_kinds.update(("source", "record", "filing"))
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
        for reason in src["reasons"]:
            o = reason["outcome"]
            rt = reason["runtime"]
            sem = runtime_semantics.get(rt)
            # the reason is a stable fact of the record; the run is one
            # execution of it under one declared semantics
            reason_node = iri_reason(wid, reason["ptr"], reason["reason_digest"])
            emitted_kinds.add("reason")
            g.add(reason_node, RDF_TYPE, _iri(WRT + "Reason"))
            g.add(reason_node, SEV + "pointer", _lit(reason["ptr"]))
            g.add(reason_node, SIGMA + "reasonDigest", _lit(reason["reason_digest"]))
            g.add(reason_node, SIGMA + "runtime", _lit(rt))
            g.add(reason_node, SIGMA + "claimedVerdict", _lit(o["claimed_verdict"]))
            g.add(rec, WRT + "hasReason", _iri(reason_node))
            idx = int(reason["ptr"].rsplit("/", 1)[1])
            because = committed_by_path.get(src["path"], [])
            committed = because[idx] if idx < len(because) else {}
            check_blob = committed.get("check") if isinstance(committed, dict) else None
            check_present = check_blob in source_digests
            if check_blob:
                # a weak reference: the reason NAMES a check blob. prov:used
                # has an Activity domain, and asserting it here would turn the
                # stable reason fact back into an execution (re-gate P1-3)
                g.add(reason_node, WRT + "checkRef", _lit(check_blob))
                if check_present:
                    g.add(reason_node, WRT + "checkBlob", _iri(iri_blob(check_blob)))

            run = iri_run(core_digest, wid, reason["ptr"],
                          reason["reason_digest"], sem)
            emitted_kinds.add("check-run")
            g.add(run, RDF_TYPE, _iri(SIGMA + "CheckRun"), vgraph)
            g.add(run, PROV + "used", _iri(reason_node), vgraph)
            if check_blob and check_present and o["re_execution"] in (
                    "matched", "mismatched"):
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

    # What this MVP does NOT emit. Declared machine-readably and only when
    # the data actually exists, because a loss manifest that describes
    # caveats on absent facts is worse than none: it reads as
    # "present, with reservations" (self-review 2026-08-10).
    has_sigs = any(s.get("signatures") for s in core["sources"]
                   if s.get("kind") == "record")
    has_settlement = any(s.get("settlement") for s in core["sources"]
                         if s.get("kind") == "record")
    has_unclaimed = bool(snapshot.get("unclaimed"))
    absent = []
    if has_sigs:
        absent.append(loss("L-NOSIG", "the receipt carries signature results; "
                                      "this MVP emits NO signature nodes at all"))
    if has_settlement:
        absent.append(loss("L-NOSETTLE", "the receipt carries jurisdiction-scoped "
                                         "settlement; this MVP emits NO settlement "
                                         "nodes at all"))
    if has_unclaimed:
        absent.append(loss("L-NOUNCLAIMED", "the snapshot pins unclaimed members; "
                                            "they are not projected"))
    # §4.1 body mapping only applies where a record was actually projected: a
    # blob-only subroot has no body to map, and claiming the loss would be a
    # caveat on an absent fact — the very thing this manifest exists to stop
    if "record" in emitted_kinds:
        absent.append(loss("L-NOMAP", "profile §4.1 record-body mapping is not "
                                      "implemented: actor, under/Plan, subject, "
                                      "evidence and prior are absent from the graph"))

    # Every remaining loss is likewise dataset-relative: emitted only when the
    # graph actually contains the thing being qualified.
    qualified = []
    if has_sigs or has_settlement:
        qualified.append(loss("L-SETTLE", "grade is emitted on the receipt node but "
                                          "is not re-derivable from the graph"))
    if "check-run" in emitted_kinds:
        qualified.append(loss("L-REEXEC", "the graph records past re-executions; "
                                          "it cannot re-run them"))
    if emitted_kinds:
        qualified.append(loss("L-CANON", "canonical bytes are not recoverable from "
                                         "the graph; hashes are copied, not "
                                         "recomputable"))
    qualified.append(loss("L-COMPLETE", "completeness is relative to the sealed "
                                        "snapshot's universe, never global"))
    if unjudged:
        qualified.append(loss("L-UNJUDGED", "unreceipted subroots: "
                              + ", ".join(unjudged)))

    loss_manifest = {"loss_manifest": "sev@v0", "entries": absent + qualified}

    not_emitted = set()
    if has_sigs:
        not_emitted.add("signature")
    if has_settlement:
        not_emitted.add("settlement")
    if has_unclaimed:
        not_emitted.add("unclaimed")
    if "record" in emitted_kinds:      # a body exists, so its mapping is missing
        not_emitted.update(("actor", "policy-plan", "subject", "evidence", "prior"))

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
        "coverage": {
            # DATASET-RELATIVE, derived from what this run actually emitted
            # and from what evidence the input actually held — never a static
            # capability list, which claimed categories absent from the input
            "emitted": sorted(emitted_kinds),
            "not_emitted": sorted(not_emitted),
            "note": "categories are relative to THIS dataset; "
                    "sources_projected counts sources admitted to the graph, "
                    "NOT completeness of the profile mapping over them",
        },
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
    check_bytes = b"policy"           # the blob sealed at .warrants/blobs/p
    reason_obj = {"kind": "check", "runtime": "ski@v1",
                  "check": sm.sha256_hex(check_bytes),
                  "verdict": "pass", "transcript": "b" * 64}
    body = {"warrant": "0.2", "decision": "accept", "subject": {},
            "under": [], "because": [reason_obj], "evidence": [],
            "actor": {"id": "signer@example"}, "prior": [], "ts": 1}
    record = {"body": body,
              "sigs": [{"actor": "signer@example", "key": "c" * 64,
                        "sig": "d" * 128}]}
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
         "id_sound": filed_as == wid, "settlement": [],
         "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                         "key": k, "valid": True, "binding": "unverified"}
                        for d, m, a, k in sm.envelope_signature_entries(record)[0]],
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
             "settlement": [],
             "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                             "key": k, "valid": True, "binding": "unverified"}
                            for d, m, a, k in sm.envelope_signature_entries(recd)[0]],
             "issues": [],
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

    # re-gate P1-1: a forged source sharing a path with the real one
    snapE, receiptE, casE = fixture()
    real = receiptE["core"]["sources"][0]
    forged = dict(real, entry_digest="0" * 64)
    receiptE["core"]["sources"] = sorted(
        receiptE["core"]["sources"] + [forged],
        key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
    resE, fE = project(snapE, receiptE, casE)
    sm.check_true("forged source sharing a path -> refusal, no forged blob",
                  lambda: resE is None
                  and any(x["code"] == "DUPLICATE_SOURCE_PATH" for x in fE)
                  and any(x["code"] == "SOURCE_DIGEST_MISMATCH" for x in fE))

    # re-gate P1-2: one runtime, two semantics
    snapF, receiptF, casF = fixture()
    rts = receiptF["core"]["execution_policy"]["runtimes"]
    rts.append(dict(rts[0], semantics_digest="f" * 64))
    resF, fF = project(snapF, receiptF, casF)
    sm.check_true("duplicate runtime with a second anchor -> refusal",
                  lambda: resF is None
                  and any(x["code"] == "DUPLICATE_RUNTIME" for x in fF))

    # re-gate P1-3: matched over a check blob absent from this subroot
    snapG, receiptG, casG = fixture()
    # rebuild the record so its committed check names a blob nobody sealed
    ghost = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
             "verdict": "pass", "transcript": "b" * 64}
    bodyG = {"warrant": "0.2", "decision": "accept", "subject": {}, "under": [],
             "because": [ghost], "evidence": [], "actor": {"id": "x"},
             "prior": [], "ts": 1}
    recG = {"body": bodyG,
            "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    widG = sm.sha256_hex(sm.jcs(bodyG))
    filesG = {".warrants/records/%s.json" % widG: sm.jcs(recG),
              ".warrants/blobs/p": b"policy"}
    casG = {sm.sha256_hex(v): v for v in filesG.values()}
    uniG = sm.seal_universe(filesG)
    dG = sm.subroot_descriptor("warrant",
                               {"name": "warrant", "version": "0.4",
                                "spec_digest": sm.sha256_hex(b"spec")},
                               ".warrants/", uniG)
    snapG = sm.snapshot_object([dG], [])
    bpG = {e["path"]: e["sha256"] for e in uniG}
    rpG = ".warrants/records/%s.json" % widG
    receiptG["core"].update(
        subroot_descriptor_digest=sm.subroot_descriptor_digest(dG),
        sources=sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bpG[".warrants/blobs/p"], "loaded": True,
             "issues": []},
            {"kind": "record", "path": rpG, "entry_digest": bpG[rpG],
             "loaded": True, "claimed_wid": widG, "computed_wid": widG,
             "id_sound": True, "settlement": [],
             "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                             "key": k, "valid": True, "binding": "unverified"}
                            for d, m, a, k in sm.envelope_signature_entries(recG)[0]],
             "issues": [],
             "reasons": [{"ptr": "/because/0", "kind": "check",
                          "runtime": "ski@v1",
                          "reason_digest": sm.sha256_hex(sm.jcs(ghost)),
                          "outcome": {"re_execution": "matched",
                                      "claimed_verdict": "pass",
                                      "observed_verdict": "pass",
                                      "observed_result": "e" * 64,
                                      "atp_spent": 7, "failure_code": None}}]},
        ], key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"])))
    resG, fG = project(snapG, receiptG, casG)
    sm.check_true("matched over an unsealed check blob -> CHECK_BLOB_ABSENT",
                  lambda: resG is None
                  and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fG))

    # ...and an honest unverified/MISSING_BLOB keeps only a weak reference
    def _missing(r):
        src = r["core"]["sources"][1]
        src["reasons"][0]["outcome"].update(
            re_execution="unverified", observed_verdict=None,
            observed_result=None, atp_spent=None, failure_code="MISSING_BLOB")
        src["issues"] = [{"code": "REASON_UNVERIFIED", "severity": "WARN",
                          "at": {"kind": "json-pointer", "value": "/because/0"}}]
        r["core"].update(warnings=1)
    receiptG2 = json.loads(json.dumps(receiptG))
    _missing(receiptG2)
    resG2, fG2 = project(snapG, receiptG2, casG)
    sm.check_true("unverified/MISSING_BLOB projects with a weak ref only",
                  lambda: fG2 == []
                  and b"wrt#checkRef" in resG2["nquads"]
                  and b"prov#used <urn:wrt:blob:" + b"a" * 64 not in resG2["nquads"])
    sm.check_true("Reason never carries prov:used (its domain is Activity)",
                  lambda: not any(
                      ln.startswith("<urn:wrt:reason:") and "prov#used" in ln
                      for ln in resG2["nquads"].decode().splitlines()))

    # re-gate P1-4 + P2: the store is REVOKED at the verdict boundary, so a
    # projector that re-read it would fail rather than quietly lose edges.
    # (The previous OnceCAS never set `exhausted`, which made this guard
    # vacuous — the old projector would have passed it.)
    class RevokedAfterVerdict(dict):
        def __init__(self, base):
            super().__init__(base)
            self.revoked = False
            self.reads_after_verdict = 0

        def __getitem__(self, k):
            if self.revoked:
                self.reads_after_verdict += 1
                raise KeyError("store revoked at the verdict boundary")
            return super().__getitem__(k)

    snapH, receiptH, casH = fixture()
    revoked = RevokedAfterVerdict(casH)
    real_validate = sm.validate_warrant_receipt

    def _revoke_after(*a, **kw):
        out = real_validate(*a, **kw)
        revoked.revoked = True          # exactly at the verdict boundary
        return out
    sm.validate_warrant_receipt = _revoke_after
    try:
        resH, fH = project(snapH, receiptH, revoked)
    finally:
        sm.validate_warrant_receipt = real_validate
    baseline, _ = project(snapH, receiptH, casH)
    sm.check_equal("projection is byte-identical with the store revoked",
                   resH["nquads"], baseline["nquads"])
    sm.check_equal("zero store reads after the verdict",
                   revoked.reads_after_verdict, 0)

    # re-gate P1-1: the caller's objects are mutated exactly at the verdict
    # boundary. Only a private frozen view can survive this; a projector
    # reading receipt["core"] or snapshot again picks the poison up.
    snapI, receiptI, casI = fixture()
    clean, _ = project(snapI, receiptI, casI)
    snapJ, receiptJ, casJ = fixture()
    real_validate2 = sm.validate_warrant_receipt

    def _poison_after(*a, **kw):
        out = real_validate2(*a, **kw)
        rt = receiptJ["core"]["execution_policy"]["runtimes"][0]
        rt["semantics_digest"] = "f" * 64
        receiptJ["core"]["sources"][1]["reasons"][0]["outcome"][
            "observed_result"] = "not-a-nodehash"
        snapJ["bundle_root"] = "0" * 64
        return out
    sm.validate_warrant_receipt = _poison_after
    try:
        resJ, fJ = project(snapJ, receiptJ, casJ)
    finally:
        sm.validate_warrant_receipt = real_validate2
    sm.check_equal("inputs poisoned at the verdict boundary cannot reach the graph",
                   resJ["nquads"], clean["nquads"])
    sm.check_equal("...nor the view manifest",
                   resJ["view_manifest"]["bundle_root"],
                   clean["view_manifest"]["bundle_root"])
    sm.check_true("no evil semantics or invalid result present",
                  lambda: b"f" * 64 not in resJ["nquads"]
                  and b"not-a-nodehash" not in resJ["nquads"])

    # re-gate P1-2: a check digest must resolve to an AVAILABLE BLOB
    def _check_resolves_to(kind_path, extra=None, break_blob=None):
        cb = sm.sha256_hex(b"policy")
        rob = {"kind": "check", "runtime": "ski@v1", "check": cb,
               "verdict": "pass", "transcript": "b" * 64}
        bod = {"warrant": "0.2", "decision": "accept", "subject": {}, "under": [],
               "because": [rob], "evidence": [], "actor": {"id": "x"},
               "prior": [], "ts": 1}
        recd = {"body": bod,
                "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
        w = sm.sha256_hex(sm.jcs(bod))
        fl = {".warrants/records/%s.json" % w: sm.jcs(recd), kind_path: b"policy"}
        fl.update(extra or {})
        cs = {sm.sha256_hex(v): v for v in fl.values()}
        un = sm.seal_universe(fl)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        rp = ".warrants/records/%s.json" % w
        others = []
        for pth in fl:
            if pth == rp:
                continue
            entry = {"kind": sm.classify_warrant_source(pth, ".warrants/")[0],
                     "path": pth, "entry_digest": bp[pth], "loaded": True,
                     "issues": []}
            if break_blob and entry["kind"] == "blob":
                # "err": readable but judged bad; "unloaded": never read at all
                entry["issues"] = [{"code": "BLOB_UNREADABLE", "severity": "ERR",
                                    "at": {"kind": "path", "value": pth}}]
                if break_blob == "unloaded":
                    entry["loaded"] = False
            others.append(entry)
        srcs = sorted(others + [
            {"kind": "record", "path": rp, "entry_digest": bp[rp], "loaded": True,
             "claimed_wid": w, "computed_wid": w, "id_sound": True,
             "settlement": [],
             "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                             "key": k, "valid": True, "binding": "unverified"}
                            for d, m, a, k in sm.envelope_signature_entries(recd)[0]],
             "issues": [],
             "reasons": [{"ptr": "/because/0", "kind": "check", "runtime": "ski@v1",
                          "reason_digest": sm.sha256_hex(sm.jcs(rob)),
                          "outcome": {"re_execution": "matched",
                                      "claimed_verdict": "pass",
                                      "observed_verdict": "pass",
                                      "observed_result": "e" * 64,
                                      "atp_spent": 7, "failure_code": None}}]}],
            key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
        errs = sum(1 for s in srcs for i in s["issues"] if i["severity"] == "ERR")
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": [
                  {"runtime": "ski@v1", "semantics": "s",
                   "semantics_digest": sm.sha256_hex(b"book1"),
                   "budget_unit": "atp", "ceiling": 1000}]},
              "ok": errs == 0, "errors": errs, "warnings": 0,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    snJ, recJ, casJ = _check_resolves_to(".warrants/README")   # digest is `other`
    resJ, fJ = project(snJ, recJ, casJ)
    sm.check_true("check resolving only to a non-blob source -> refusal",
                  lambda: resJ is None
                  and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fJ))

    for mode, label in [("err", "an ERR-judged blob"),
                        ("unloaded", "a blob that was never loaded")]:
        snK, recK, casK = _check_resolves_to(".warrants/blobs/p", break_blob=mode)
        resK, fK = project(snK, recK, casK)
        sm.check_true("check resolving to %s -> refusal" % label,
                      lambda resK=resK, fK=fK: resK is None
                      and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fK))

    # self-review: what the receipt asserts and the graph omits must be
    # DECLARED, not implied. A loss manifest that puts caveats on absent
    # facts reads as "present, with reservations".
    # the fixture's record carries a real envelope signature, faithfully
    # reported by the receipt — and the graph still says nothing about it
    snapL, receiptL, casL = fixture()
    actor = receiptL["core"]["sources"][1]["signatures"][0]["actor"]
    resL, fL = project(snapL, receiptL, casL)
    codesL = [e["code"] for e in resL["loss_manifest"]["entries"]]
    sm.check_true("a receipt-reported signature is absent from the graph",
                  lambda: fL == [] and actor.encode() not in resL["nquads"])
    sm.check_true("...and that absence is declared as L-NOSIG",
                  lambda: "L-NOSIG" in codesL)
    sm.check_true("the unimplemented body mapping is always declared",
                  lambda: "L-NOMAP" in codesL)
    sm.check_true("no absence code is emitted for data that is not there",
                  lambda: "L-NOSETTLE" not in codesL
                  and "L-NOUNCLAIMED" not in codesL)   # this fixture has neither
    # ...but a snapshot that DOES pin unclaimed bytes must declare them
    snapU, receiptU, casU = fixture()
    dU = {k: v for k, v in snapU["subroots"][0].items() if k != "digest"}
    note = b"loose note"
    snapU2 = sm.snapshot_object([dU], [{"path": "notes.txt",
                                        "sha256": sm.sha256_hex(note)}])
    casU[sm.sha256_hex(note)] = note
    receiptU["core"]["subroot_descriptor_digest"] = sm.subroot_descriptor_digest(dU)
    resU, fU = project(snapU2, receiptU, casU)
    sm.check_true("unclaimed snapshot members are declared when present",
                  lambda: fU == [] and "L-NOUNCLAIMED" in
                  [e["code"] for e in resU["loss_manifest"]["entries"]])
    cov = resL["view_manifest"]["coverage"]
    sm.check_true("coverage qualifies what 'projected' means",
                  lambda: "signature" in cov["not_emitted"]
                  and "record" in cov["emitted"])

    # absent semantics must not stringify into the run's hash material
    snapM, receiptM, casM = fixture()
    srcM = receiptM["core"]["sources"][1]
    srcM["reasons"][0]["outcome"].update(
        re_execution="unverified", observed_verdict=None, observed_result=None,
        atp_spent=None, failure_code="RUNTIME_UNAVAILABLE")
    srcM["issues"] = [{"code": "REASON_UNVERIFIED", "severity": "WARN",
                       "at": {"kind": "json-pointer", "value": "/because/0"}}]
    receiptM["core"].update(warnings=1)
    receiptM["core"]["execution_policy"]["runtimes"] = []
    resM, fM = project(snapM, receiptM, casM)
    sm.check_equal("a run with no declared semantics still validates", fM, [])
    sm.check_equal("its IRI hashes an empty semantics field, not 'None'",
                   {ln.split(" ")[0] for ln in resM["nquads"].decode().splitlines()
                    if "sigma#CheckRun" in ln},
                   {"<" + iri_run(sm.sha256_hex(sm.jcs(resM and receiptM["core"])),
                                  srcM["computed_wid"], "/because/0",
                                  srcM["reasons"][0]["reason_digest"], None) + ">"})

    # re-gate: an input that cannot be detached must be REFUSED, not shared.
    # The old freeze fell back to the caller's object on a copy failure, so
    # isolation opened exactly for the inputs that need it most.
    class Uncopyable(dict):
        def __deepcopy__(self, memo):
            raise RuntimeError("refuses to be copied")

    snapN, receiptN, casN = fixture()
    hostile = Uncopyable(receiptN)
    real_validate3 = sm.validate_warrant_receipt

    def _mutate_after(*a, **kw):
        out = real_validate3(*a, **kw)
        hostile["core"]["execution_policy"]["runtimes"][0][
            "semantics_digest"] = "f" * 64
        hostile["core"]["sources"][1]["reasons"][0]["outcome"][
            "observed_result"] = "not-a-nodehash"
        return out
    sm.validate_warrant_receipt = _mutate_after
    try:
        resN, fN = project(snapN, hostile, casN)
    finally:
        sm.validate_warrant_receipt = real_validate3
    sm.check_true("an uncopyable input is refused, not shared",
                  lambda: resN is None
                  and [x["code"] for x in fN] == ["INPUT_NOT_FREEZABLE"])
    sm.check_true("nothing the validator never judged reached any output",
                  lambda: resN is None)

    # exact-type freezing: subclasses are the usual carrier of read-dependent
    # behaviour, so they are refused even when they copy cleanly
    class PlainSubclass(dict):
        pass
    snapO, receiptO, casO = fixture()
    resO, fO = project(snapO, PlainSubclass(receiptO), casO)
    sm.check_equal("a dict subclass is refused too",
                   [x["code"] for x in fO], ["INPUT_NOT_FREEZABLE"])
    sm.check_true("...and the honest plain-dict path still projects",
                  lambda: project(snapO, receiptO, casO)[1] == [])

    # re-gate: cyclic / over-deep plain containers must REFUSE, not crash.
    # These are exact dict/list values, so the type check alone lets them in.
    snapP, receiptP, casP = fixture()
    cyc_dict = json.loads(json.dumps(receiptP))
    cyc_dict["core"]["self"] = cyc_dict           # dict cycle
    cyc_list_receipt = json.loads(json.dumps(receiptP))
    loop = []
    loop.append(loop)                             # list cycle
    cyc_list_receipt["core"]["loop"] = loop
    deep = cur = {}
    for _ in range(sm.MAX_FREEZE_DEPTH + 5):      # over depth budget
        cur["n"] = {}
        cur = cur["n"]
    deep_receipt = json.loads(json.dumps(receiptP))
    deep_receipt["core"]["deep"] = deep
    cyc_snapshot = json.loads(json.dumps(snapP))
    cyc_snapshot["self"] = cyc_snapshot

    for label, sn, rc in [("dict-cycle in receipt", snapP, cyc_dict),
                          ("list-cycle in receipt", snapP, cyc_list_receipt),
                          ("over-depth in receipt", snapP, deep_receipt),
                          ("dict-cycle in snapshot", cyc_snapshot, receiptP)]:
        try:
            resP, fP = project(sn, rc, casP)
            ok = resP is None and [x["code"] for x in fP] == ["INPUT_NOT_FREEZABLE"]
            detail = "" if ok else "findings=%s" % [x["code"] for x in fP]
        except RecursionError:
            ok, detail = False, "RecursionError escaped project()"
        sm._record("%s -> bounded INPUT_NOT_FREEZABLE" % label, ok, detail)

    # re-gate: the node budget must count scalars, not only containers — a
    # wide flat list was previously copied whole and the ceiling never fired
    wide = [0] * (sm.MAX_FREEZE_NODES + 1)
    _resW, fW = project(snapP, wide, casP)
    sm.check_equal("a wide scalar list exhausts the node budget",
                   [x["code"] for x in fW], ["INPUT_NOT_FREEZABLE"])
    narrow = [0] * 16
    _resW2, fW2 = project(snapP, narrow, casP)
    sm.check_true("a small list is refused on shape, not on budget",
                  lambda: [x["code"] for x in fW2] != ["INPUT_NOT_FREEZABLE"])

    # ...and the byte budget must bound payload, which a node count cannot.
    # The limit is lowered for the duration so the vector isolates the rule
    # without allocating 64 MiB.
    real_bytes = sm.MAX_FREEZE_BYTES
    sm.MAX_FREEZE_BYTES = 1024
    try:
        fat = {"core": {"blob": "z" * 4096}}
        _resZ, fZ = project(snapP, fat, casP)
        sm.check_equal("oversized string payload exhausts the byte budget",
                       [x["code"] for x in fZ], ["INPUT_NOT_FREEZABLE"])
    finally:
        sm.MAX_FREEZE_BYTES = real_bytes

    # re-gate: a blob-only dataset must not claim record/reason/run evidence
    only_blob = {".warrants/blobs/p": b"policy"}
    uniB = sm.seal_universe(only_blob)
    dB = sm.subroot_descriptor("warrant",
                               {"name": "warrant", "version": "0.4",
                                "spec_digest": sm.sha256_hex(b"spec")},
                               ".warrants/", uniB)
    snapB = sm.snapshot_object([dB], [])
    casB = {sm.sha256_hex(v): v for v in only_blob.values()}
    coreB = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dB),
             "grade": "base", "trust_config_digest": None,
             "execution_policy": {"runtimes": []},
             "ok": True, "errors": 0, "warnings": 0, "global_issues": [],
             "sources": [{"kind": "blob", "path": ".warrants/blobs/p",
                          "entry_digest": uniB[0]["sha256"], "loaded": True,
                          "issues": []}]}
    receiptB = {"receipt": "warrant.verification-receipt@v0", "core": coreB,
                "producer": {"impl": "x", "artifact_digest": None, "spec": "0.4",
                             "report_digest": "f" * 64, "local_notes": []}}
    resB, fB = project(snapB, receiptB, casB)
    covB = resB["view_manifest"]["coverage"]
    codesB = [e["code"] for e in resB["loss_manifest"]["entries"]]
    sm.check_equal("blob-only dataset validates", fB, [])
    sm.check_equal("coverage claims only what this dataset holds",
                   covB["emitted"], ["source", "verification-receipt"])
    sm.check_equal("nothing is declared un-emitted that never existed",
                   covB["not_emitted"], [])
    sm.check_true("no losses about records, reasons, runs or signatures",
                  lambda: not ({"L-NOMAP", "L-NOSIG", "L-NOSETTLE",
                                "L-REEXEC", "L-SETTLE"} & set(codesB)))
    sm.check_true("the losses that DO apply are still stated",
                  lambda: {"L-CANON", "L-COMPLETE"} <= set(codesB))
    # ...while the full fixture, which does hold those facts, still declares them
    fullres, _ = project(*fixture())
    codesFull = [e["code"] for e in fullres["loss_manifest"]["entries"]]
    sm.check_true("a record-bearing dataset still declares L-NOMAP and L-REEXEC",
                  lambda: {"L-NOMAP", "L-REEXEC"} <= set(codesFull))

    # re-gate: nested entries must be BOUND to the committed envelope, or a
    # clean receipt can hide and invent evidence at will
    def _tamper(fn):
        sn, rc, cs = fixture()
        fn(rc["core"]["sources"][1])
        return project(sn, rc, cs)

    resS1, fS1 = _tamper(lambda src: src.update(signatures=[]))
    sm.check_true("omitted envelope signature -> SIGNATURE_MISSING",
                  lambda: resS1 is None
                  and any(x["code"] == "SIGNATURE_MISSING" for x in fS1))

    resS2, fS2 = _tamper(lambda src: src["signatures"].append(
        {"sig_digest": "0" * 64, "multiplicity": 0, "actor": "fabricated",
         "key": "1" * 64, "valid": True, "binding": "bound"}))
    sm.check_true("fabricated signature -> SIGNATURE_NOT_IN_ENVELOPE",
                  lambda: resS2 is None
                  and any(x["code"] == "SIGNATURE_NOT_IN_ENVELOPE" for x in fS2))

    resS3, fS3 = _tamper(lambda src: src["signatures"][0].update(actor="someone@else"))
    sm.check_true("signature attributed to another actor -> field mismatch",
                  lambda: resS3 is None
                  and any(x["code"] == "SIGNATURE_FIELD_MISMATCH" for x in fS3))

    resS4, fS4 = _tamper(lambda src: src["signatures"].append(
        dict(src["signatures"][0])))
    sm.check_true("duplicate signature entry -> refusal",
                  lambda: resS4 is None
                  and any(x["code"] == "DUPLICATE_SIGNATURE_ENTRY" for x in fS4))

    resR1, fR1 = _tamper(lambda src: src.update(reasons=[]))
    sm.check_true("omitted committed check reason -> REASON_MISSING",
                  lambda: resR1 is None
                  and any(x["code"] == "REASON_MISSING" for x in fR1))

    resR2, fR2 = _tamper(lambda src: src["reasons"].append(
        dict(src["reasons"][0], ptr="/because/1")))
    sm.check_true("reason over a pointer with no committed check -> refusal",
                  lambda: resR2 is None
                  and any(x["code"] in ("REASON_NOT_COMMITTED",
                                        "REASON_PTR_UNRESOLVABLE") for x in fR2))

    resR3, fR3 = _tamper(lambda src: src["reasons"].append(
        dict(src["reasons"][0])))
    sm.check_true("duplicate reason pointer -> refusal",
                  lambda: resR3 is None
                  and any(x["code"] == "DUPLICATE_REASON_POINTER" for x in fR3))

    # a committed PROSE reason is not reportable and must not be demanded
    prose_reason = {"kind": "prose", "text": "because the policy says so"}
    check_obj = {"kind": "check", "runtime": "ski@v1",
                 "check": sm.sha256_hex(b"policy"), "verdict": "pass",
                 "transcript": "b" * 64}
    bodyP = {"warrant": "0.2", "decision": "accept", "subject": {}, "under": [],
             "because": [prose_reason, check_obj], "evidence": [],
             "actor": {"id": "signer@example"}, "prior": [], "ts": 1}
    recP = {"body": bodyP, "sigs": [{"actor": "signer@example", "key": "c" * 64,
                                     "sig": "d" * 128}]}
    widP = sm.sha256_hex(sm.jcs(bodyP))
    filesP = {".warrants/records/%s.json" % widP: sm.jcs(recP),
              ".warrants/blobs/p": b"policy"}
    casP2 = {sm.sha256_hex(v): v for v in filesP.values()}
    uniP = sm.seal_universe(filesP)
    dP = sm.subroot_descriptor("warrant",
                               {"name": "warrant", "version": "0.4",
                                "spec_digest": sm.sha256_hex(b"spec")},
                               ".warrants/", uniP)
    snapP2 = sm.snapshot_object([dP], [])
    bpP = {e["path"]: e["sha256"] for e in uniP}
    rpP = ".warrants/records/%s.json" % widP
    coreP = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dP),
             "grade": "base", "trust_config_digest": None,
             "execution_policy": {"runtimes": [
                 {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                  "semantics_digest": sm.sha256_hex(b"book1"),
                  "budget_unit": "atp", "ceiling": 1000}]},
             "ok": True, "errors": 0, "warnings": 0, "global_issues": [],
             "sources": sorted([
                 {"kind": "blob", "path": ".warrants/blobs/p",
                  "entry_digest": bpP[".warrants/blobs/p"], "loaded": True,
                  "issues": []},
                 {"kind": "record", "path": rpP, "entry_digest": bpP[rpP],
                  "loaded": True, "claimed_wid": widP, "computed_wid": widP,
                  "id_sound": True, "settlement": [],
                  "signatures": [{"sig_digest": d, "multiplicity": m,
                                  "actor": a, "key": k, "valid": True,
                                  "binding": "unverified"}
                                 for d, m, a, k in
                                 sm.envelope_signature_entries(recP)[0]],
                  "issues": [],
                  "reasons": [{"ptr": "/because/1", "kind": "check",
                               "runtime": "ski@v1",
                               "reason_digest": sm.sha256_hex(sm.jcs(check_obj)),
                               "outcome": {"re_execution": "matched",
                                           "claimed_verdict": "pass",
                                           "observed_verdict": "pass",
                                           "observed_result": "e" * 64,
                                           "atp_spent": 7,
                                           "failure_code": None}}]},
             ], key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))}
    receiptP2 = {"receipt": "warrant.verification-receipt@v0", "core": coreP,
                 "producer": {"impl": "x", "artifact_digest": None,
                              "spec": "0.4", "report_digest": "f" * 64,
                              "local_notes": []}}
    resP2, fP2 = project(snapP2, receiptP2, casP2)
    sm.check_equal("a committed prose reason is not demanded of the receipt",
                   fP2, [])

    # re-gate: malformed COMMITTED evidence must not vanish before the
    # bijection. A derivation that returns only what it understood makes an
    # empty receipt an "exact bijection" with an empty derived set.
    def _with_committed(sigs=None, because=None):
        """Seal a record whose envelope/body carry the given raw shapes."""
        body = {"warrant": "0.2", "decision": "accept", "subject": {},
                "under": [],
                "because": because if because is not None else [
                    {"kind": "check", "runtime": "ski@v1",
                     "check": sm.sha256_hex(b"policy"), "verdict": "pass",
                     "transcript": "b" * 64}],
                "evidence": [], "actor": {"id": "signer@example"},
                "prior": [], "ts": 1}
        rec = {"body": body,
               "sigs": sigs if sigs is not None else [
                   {"actor": "signer@example", "key": "c" * 64,
                    "sig": "d" * 128}]}
        w = sm.sha256_hex(sm.jcs(body))
        fl = {".warrants/records/%s.json" % w: sm.jcs(rec),
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
        entries, _mal = sm.envelope_signature_entries(rec)
        ptrs, _mal2 = sm.reportable_reason_pointers(rec)
        reasons = []
        for ptr in sorted(ptrs):
            idx = int(ptr.rsplit("/", 1)[1])
            reasons.append({"ptr": ptr, "kind": "check", "runtime": "ski@v1",
                            "reason_digest": sm.sha256_hex(sm.jcs(body["because"][idx])),
                            "outcome": {"re_execution": "matched",
                                        "claimed_verdict": "pass",
                                        "observed_verdict": "pass",
                                        "observed_result": "e" * 64,
                                        "atp_spent": 7, "failure_code": None}})
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True, "issues": []},
            {"kind": "record", "path": rp, "entry_digest": bp[rp], "loaded": True,
             "claimed_wid": w, "computed_wid": w, "id_sound": True,
             "settlement": [],
             "signatures": [{"sig_digest": d, "multiplicity": m, "actor": a,
                             "key": k, "valid": True, "binding": "unverified"}
                            for d, m, a, k in entries],
             "issues": [], "reasons": reasons}],
            key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": [
                  {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                   "semantics_digest": sm.sha256_hex(b"book1"),
                   "budget_unit": "atp", "ceiling": 1000}]},
              "ok": True, "errors": 0, "warnings": 0, "global_issues": [],
              "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    malformed_cases = [
        ("sigs is not a list", {"sigs": 7}, None),
        ("sigs holds a scalar", {"sigs": [7]}, None),
        ("signature missing fields", {"sigs": [{"actor": "a"}]}, None),
        ("signature field of wrong type", {"sigs": [{"actor": "a", "key": "c" * 64,
                                                    "sig": 7}]}, None),
        # warrant's envelope schema is closed: an unknown member is not a
        # harmless extra, it is a different object
        ("signature with an unknown member",
         {"sigs": [{"actor": "a", "key": "c" * 64, "sig": "d" * 128,
                    "note": "smuggled"}]}, None),
        ("because is not a list", None, 7),
        ("because holds a scalar", None, [7]),
        ("unknown reason kind", None, [{"kind": "sideways", "text": "hm"}]),
        ("check reason with a bad field", None, [{"kind": "check", "runtime": "ski@v1",
                                                  "check": "not-hex",
                                                  "verdict": "pass"}]),
    ]
    for label, sigs, because in malformed_cases:
        sn, rc, cs = _with_committed(
            sigs=(sigs or {}).get("sigs") if sigs else None, because=because)
        resX, fX = project(sn, rc, cs)
        sm.check_true("malformed committed evidence (%s) -> refusal" % label,
                      lambda resX=resX, fX=fX: resX is None and any(
                          x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fX))

    # positive control: a well-formed prose reason is legitimately
    # non-reportable and must NOT be treated as malformed
    snPC, rcPC, csPC = _with_committed(because=[
        {"kind": "prose", "text": "clause 1 of the policy"},
        {"kind": "check", "runtime": "ski@v1", "check": sm.sha256_hex(b"policy"),
         "verdict": "pass", "transcript": "b" * 64}])
    resPC, fPC = project(snPC, rcPC, csPC)
    sm.check_equal("well-formed prose beside a check projects cleanly", fPC, [])

    # ...and a malformed occurrence that IS reported as a located issue is
    # accepted, carrying the record into exclusions honestly
    snR, rcR, csR = _with_committed(sigs=[7])
    rec_src = [s for s in rcR["core"]["sources"] if s["kind"] == "record"][0]
    rec_src["issues"] = [{"code": "MALFORMED_SIGNATURE", "severity": "ERR",
                          "at": {"kind": "json-pointer", "value": "/sigs/0"}}]
    rcR["core"].update(ok=False, errors=1)
    resR, fR = project(snR, rcR, csR)
    sm.check_equal("a reported malformed occurrence is accepted", fR, [])
    sm.check_true("...and excludes the record honestly",
                  lambda: resR["view_manifest"]["sources_excluded"] == 1)

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
