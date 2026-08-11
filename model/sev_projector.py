#!/usr/bin/env python3
"""SEV projector MVP — the first executable output of sev@v0 (round-6 R4).

Scope, deliberately narrow:
  * Warrant quadrant ONLY — projects a (sealed snapshot, warrant
    verification receipt) pair that the composed verdict accepts cleanly;
  * emits canonical N-Quads (zero blank nodes, sorted, LF, trailing LF),
    a JCS view-manifest and a JCS loss_manifest;
  * refuses (findings, no output) when the byte verdict reports
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
import re
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

# The exported surface is ONE byte-first entry point. A public projector that
# takes already-decoded objects is a door around the byte verdict: duplicate
# member names, trailing data and a BOM are gone by the time a caller holds a
# dict, so the same bytes the verdict refuses yield a graph (round 15).
__all__ = ["project_bytes"]


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
        # quad lines embed literals that may carry astral characters, and
        # graph_digest binds the resulting byte order — so the same UTF-16
        # comparator the format uses everywhere else
        return ("\n".join(sorted(self.quads, key=sm.path_sort_key))
                + "\n").encode("utf-8")


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


def iri_usage(filing, role, target):
    """One `prov:Usage` per (filing, role, used entity).

    §2 forbids blank nodes, so the qualified relation needs a minted IRI.
    Keying on the role as well as the target is not cosmetic: the same blob
    can be a record's `subject` AND appear in its `evidence[]`, and merging
    those into one Usage node would erase the distinction the qualification
    exists to carry.
    """
    return "urn:sev:usage:" + sm.sha256_hex(
        filing.encode("utf-8") + b"\x00" + role.encode("ascii")
        + b"\x00" + target.encode("utf-8"))


def iri_signature(wid, sig_digest, multiplicity):
    """`urn:wrt:sig:<WID>:<sig_digest>:<multiplicity>` — profile §2.

    Every component stays **visible** rather than hashed into one opaque
    digest: `sig_digest` is what a consumer joins on, and an implementation
    that hashes the triple together makes the join impossible and its
    N-Quads non-comparable with anyone else's.

    `multiplicity` is present because a record may carry the same signature
    bytes twice. `WID` is present because the same *invalid* `{actor, key,
    sig}` can be replayed into several records — without it, two records
    sharing a bad signature would share one node, and each record's
    judgement of it would overwrite the other's (round 17 P1; the profile
    was amended to require the WID rather than the code bent to match it).
    """
    return "urn:wrt:sig:%s:%s:%d" % (wid, sig_digest, multiplicity)


def iri_actor(actor_id):
    """`urn:wrt:actor:<pct-encoded actor string>` — profile §2.

    Minted ONLY where a signature was valid AND bound, which is what makes
    minting it from the actor string safe: an unbound signature never
    reaches this function, so the graph cannot contain an actor IRI that no
    binding vouched for.

    The encoding is spelled out here rather than delegated: **retain the
    ASCII unreserved set `A-Z a-z 0-9 - . _ ~` literally; percent-encode
    every other UTF-8 octet as uppercase `%HH`.** "Empty safe set" was not a
    specification — `urllib.parse.quote(safe="")` still keeps the unreserved
    characters raw, JavaScript's `encodeURIComponent` additionally keeps
    `!*'()`, and lowercase `%hh` is equally legal in RFC 3986. Three honest
    implementations, three different IRIs, and a join that silently finds
    nothing (round 18 P1).
    """
    out = []
    for byte in actor_id.encode("utf-8"):
        ch = chr(byte)
        if ch.isascii() and (ch.isalpha() or ch.isdigit() or ch in "-._~"):
            out.append(ch)
        else:
            out.append("%%%02X" % byte)
    return "urn:wrt:actor:" + "".join(out)


def iri_reason(wid, ptr, reason_digest):
    """The reason as a stable fact of the record: same across every
    verification of the same bytes."""
    return "urn:wrt:reason:" + sm.sha256_hex(
        wid.encode() + b"\x00" + ptr.encode() + b"\x00" + reason_digest.encode())


def iri_assessment(core_digest, wid, ptr, reason_digest):
    """What one receipt says about executing one reason — an Entity. Present
    for every outcome, including the ones where nothing ran."""
    return "urn:sev:assess:" + sm.sha256_hex(
        core_digest.encode("ascii") + b"\x00" + wid.encode() + b"\x00"
        + ptr.encode() + b"\x00" + reason_digest.encode())


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


def project_bytes(snapshot_raw, receipt_raw, cas) -> tuple:
    """THE public projector: BYTES in.

    Taking objects reopened the bypass the byte verdict exists to close —
    a caller could `json.loads` bytes the format rejects, hand over the
    resulting dict, and receive a graph. The product must not offer a door
    the verdict closed (round 14).
    """
    view = {}
    findings = sm.verify_receipt_bytes(snapshot_raw, receipt_raw, cas, view=view)
    if findings:
        return None, findings
    return _project_validated(view, cas)


def _project_objects(snapshot, receipt, cas) -> tuple:
    """(result dict | None, findings). Pure function of its inputs: no
    clocks, no randomness, no filesystem reads beyond the tool digest.

    `cas` is required: projecting without an evidence resolver would turn
    "nothing could be checked" into an emitted evidence view.
    """
    # ONE validation pass produces both the verdict and the parsed view it
    # was rendered over. Re-reading the CAS afterwards let a stateful
    # resolver hand the projector different bytes than the verdict judged
    # (re-gate P1-4) — the projector now touches no store at all.
    view = {}
    try:
        raw_s, raw_r = sm.jcs(snapshot), sm.jcs(receipt)
    except (ValueError, RecursionError):
        findings = sm._verdict_over_objects(snapshot, receipt, cas, view=view)
    else:
        findings = sm.verify_receipt_bytes(raw_s, raw_r, cas, view=view)
    if findings:
        return None, findings
    return _project_validated(view, cas)


def _project_validated(view, cas) -> tuple:
    """Both entry points converge here, reading ONLY the validated view —
    the private frozen copies the verdict was rendered over."""
    committed_by_path = view.get("committed", {})
    body_by_path = view.get("body", {})
    snapshot = view["snapshot"]
    receipt = view["receipt"]

    core = view["core"]
    core_digest = sm.sha256_hex(sm.jcs(core))
    vgraph = iri_verify_graph(core_digest)
    g = Graph()

    emitted_kinds = set()
    # what the committed bodies HELD, and what of it reached the graph;
    # `not_emitted` is their difference, never a proxy for it
    body_present, body_mapped = set(), set()
    # signature occurrences that actually became nodes, and the actors
    # those nodes named as unattributed claims. Counting receipt ENTRIES
    # instead let an excluded record's signature be reported as emitted
    # (round 17 P1)
    emitted_sig_occurrences = 0
    unattributed_nodes = 0

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

        # ---- §4.1 record-body mapping ------------------------------------
        # Read from the validated view, never the store: these are the bytes
        # THIS verdict was rendered over. Every fact below is licensed by
        # byte identity — the record reached here only because
        # `computed_wid == claimed_wid`, so its body is exactly what the
        # WarrantID commits to. Weak defaults only: the profile marks actor
        # and policy "promotable", and nothing in the receipt licenses a
        # promotion, so `wrt:claimedActor` and `wrt:underPolicy` are emitted
        # rather than `prov:Agent` and `prov:hadPlan` (declared L-NOPROMOTE).
        body = body_by_path.get(src["path"])
        if isinstance(body, dict):
            emitted_kinds.add("body")
            actor = body.get("actor")
            if isinstance(actor, dict) and isinstance(actor.get("id"), str):
                body_present.add("actor")
                body_mapped.add("actor")
                g.add(rec, WRT + "claimedActor", _lit(actor["id"]))
            if isinstance(body.get("decision"), str):
                g.add(filing, WRT + "verdict", _lit(body["decision"]))
            if isinstance(body.get("ts"), int) and not isinstance(body.get("ts"), bool):
                g.add(filing, WRT + "declaredTimestamp", _lit(body["ts"]))
            for policy in body.get("under") or []:
                if sm._is_hex64(policy):
                    # the weak default IS emitted; the PLAN promotion is not,
                    # which is why "policy-plan" stays a declared absence
                    # while "actor"/"subject"/"evidence"/"prior" must not
                    body_present.add("policy-plan")
                    g.add(rec, WRT + "underPolicy", _iri(iri_blob(policy)))
                    g.add(iri_blob(policy), RDF_TYPE, _iri(PROV + "Entity"))
            for prior in body.get("prior") or []:
                if sm._is_hex64(prior):
                    body_present.add("prior")
                    body_mapped.add("prior")
                    # a prior is another RECORD, not a blob: keying it as a
                    # blob would make the lineage edge point at a content
                    # entity that no source in this bundle need contain
                    g.add(rec, WRT + "prior", _iri(iri_record(prior)))
            # subject and evidence are USES by the filing, qualified with the
            # role, because "this blob was the subject" and "this blob was
            # evidence" are different claims about the same bytes
            subject = body.get("subject")
            uses = []
            if isinstance(subject, dict) and sm._is_hex64(subject.get("hash")):
                uses.append(("subject", subject["hash"]))
            for ev in body.get("evidence") or []:
                if sm._is_hex64(ev):
                    uses.append(("evidence", ev))
            for role, digest in uses:
                body_present.add(role)
                body_mapped.add(role)
                target = iri_blob(digest)
                usage = iri_usage(filing, role, target)
                g.add(target, RDF_TYPE, _iri(PROV + "Entity"))
                g.add(filing, PROV + "used", _iri(target))
                g.add(filing, PROV + "qualifiedUsage", _iri(usage))
                g.add(usage, RDF_TYPE, _iri(PROV + "Usage"))
                g.add(usage, PROV + "entity", _iri(target))
                g.add(usage, SEV + "role", _lit(role))
            for i, item in enumerate(committed_by_path.get(src["path"], [])):
                if isinstance(item, dict) and item.get("kind") == "prose" \
                        and isinstance(item.get("text"), str):
                    g.add(rec, WRT + "prose", _lit(item["text"]))

        # ---- §4.1 signatures ---------------------------------------------
        # Validity and binding are COPIED from the receipt, never re-derived:
        # SEV performs no cryptography, and the graph must not read as though
        # it did (declared L-SIG). The promotion rule is the profile's and is
        # the whole point of this block — validity proves that *this key
        # signed this WarrantID*, not that *this key belongs to this actor*.
        # Only `valid AND bound` licenses `prov:wasAttributedTo`; anything
        # weaker gets `wrt:claimedSigner`, a claim the graph attributes to
        # nobody.
        for sig in src.get("signatures") or []:
            node = iri_signature(wid, sig["sig_digest"], sig["multiplicity"])
            emitted_kinds.add("signature")
            emitted_sig_occurrences += 1
            # Mechanical topology — derivable from the sealed bytes alone,
            # identical under every receipt — stays in the default graph.
            g.add(node, RDF_TYPE, _iri(WRT + "Signature"))
            g.add(node, SEV + "multiplicity", _lit(sig["multiplicity"]))
            g.add(rec, WRT + "hasSignature", _iri(node))
            # Everything below is this RECEIPT's judgement and belongs in its
            # verification graph. Unscoped, two honest receipts over the same
            # signature — one reporting `unverified`, one `bound` — merged
            # into a single node carrying both bindings, with nothing left to
            # say which core digest asserted which (round 17 P1).
            g.add(node, WRT + "sigValid", _lit(sig["valid"]), vgraph)
            g.add(node, WRT + "binding", _lit(sig["binding"]), vgraph)
            actor_id = sig.get("actor")
            if not isinstance(actor_id, str):
                continue
            if sig["valid"] is True and sig["binding"] == "bound":
                agent = iri_actor(actor_id)
                g.add(agent, RDF_TYPE, _iri(PROV + "Agent"), vgraph)
                g.add(agent, WRT + "actorId", _lit(actor_id), vgraph)
                # the SIGNATURE is what the agent made. Attributing the
                # record itself would claim authorship of everything the
                # body says, which one bound signature does not establish
                emitted_kinds.add("attribution")
                g.add(node, PROV + "wasAttributedTo", _iri(agent), vgraph)
            else:
                unattributed_nodes += 1
                g.add(node, WRT + "claimedSigner", _lit(actor_id), vgraph)

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

            # What the receipt SAYS about executing this reason — an Entity,
            # never an Activity. `not-applicable` and `unverified` mean no
            # execution happened; emitting a CheckRun for them (and with it
            # prov:used / prov:wasInformedBy, whose PROV domain is Activity)
            # made the graph assert a run under entailment — the exact
            # "re-ran ≠ was not executed" collapse warrant SPEC §7 forbids.
            assess = iri_assessment(core_digest, wid, reason["ptr"],
                                    reason["reason_digest"])
            emitted_kinds.add("execution-assessment")
            g.add(assess, RDF_TYPE, _iri(SEV + "ExecutionAssessment"), vgraph)
            g.add(assess, SEV + "assesses", _iri(reason_node), vgraph)
            g.add(assess, SEV + "receiptCoreDigest", _lit(core_digest), vgraph)
            g.add(assess, SIGMA + "reExecution", _lit(o["re_execution"]), vgraph)
            if o["re_execution"] == "unverified":
                unverified += 1
                g.add(assess, SIGMA + "failureCode", _lit(o["failure_code"]), vgraph)

            if o["re_execution"] not in ("matched", "mismatched"):
                continue        # nothing ran: no Activity, no PROV relations

            run = iri_run(core_digest, wid, reason["ptr"],
                          reason["reason_digest"], sem)
            emitted_kinds.add("check-run")
            g.add(run, RDF_TYPE, _iri(SIGMA + "CheckRun"), vgraph)
            g.add(assess, SEV + "executedAs", _iri(run), vgraph)
            g.add(run, PROV + "used", _iri(reason_node), vgraph)
            if check_blob and check_present:
                g.add(run, PROV + "used", _iri(iri_blob(check_blob)), vgraph)
            if sem:
                g.add(run, SIGMA + "semanticsDigest", _lit(sem), vgraph)
            g.add(run, SEV + "receiptCoreDigest", _lit(core_digest), vgraph)
            g.add(run, SIGMA + "reExecution", _lit(o["re_execution"]), vgraph)
            # the run consumed the record's bytes to reach the reason —
            # prov:used (Activity -> Entity). NOT prov:wasInformedBy, whose
            # RANGE is also an Activity: that entailed the Warrant record
            # itself being an Activity (re-gate P1)
            g.add(run, PROV + "used", _iri(rec), vgraph)
            g.add(run, SIGMA + "observedVerdict", _lit(o["observed_verdict"]), vgraph)
            g.add(run, SIGMA + "atpSpent", _lit(o["atp_spent"]), vgraph)
            if rt == "ski@v1":
                g.add(run, PROV + "generated",
                      _iri("urn:sigma:node:" + o["observed_result"]), vgraph)

    nquads = g.nquads()
    tool = _tool_digest()

    def loss(code, note):
        return {"code": code, "affects": "*", "note": note,
                "recheck": {"argv": ["python3", "model/snapshot_model.py"],
                            "tool_digest": tool}}

    receipted = {core["subroot_descriptor_digest"]}
    # UTF-16 order, like every other ordering in this format: codepoint
    # sorting disagrees on astral-vs-BMP, and this list is JCS-serialized
    # into the view manifest and joined into the L-UNJUDGED note, so two
    # honest implementations would emit different manifest digests
    unjudged = sorted((w["protocol"] for w in snapshot["subroots"]
                       if w["digest"] not in receipted), key=sm.path_sort_key)

    # What this MVP does NOT emit. Declared machine-readably and only when
    # the data actually exists, because a loss manifest that describes
    # caveats on absent facts is worse than none: it reads as
    # "present, with reservations" (self-review 2026-08-10).
    # presence is derived from the TOTAL derivation: a malformed signature
    # occurrence is still signature evidence the input held, even though it
    # is represented by an issue rather than a signatures[] entry
    evidence = view.get("evidence", {})
    has_sigs = (any(s.get("signatures") for s in core["sources"]
                    if s.get("kind") == "record")
                or any(e.get("signature_occurrences") for e in evidence.values()))
    has_settlement = any(s.get("settlement") for s in core["sources"]
                         if s.get("kind") == "record")
    has_unclaimed = bool(snapshot.get("unclaimed"))
    # A signature occurrence the receipt could not represent as an entry —
    # a malformed one, carried as an issue instead — has no node in the
    # graph either. That is a real absence and keeps its own code; the rest
    # of the family is now emitted, so the old blanket code is gone rather than
    # standing as a caveat on facts that are present.
    # Measured against nodes that EXIST, not entries the receipt happens to
    # carry. Counting entries meant an excluded record's signature — never
    # projected, no node anywhere — was reported as emitted: no L-NOSIGNODE,
    # `signature` missing from not_emitted, and an L-UNBOUND claiming a
    # `wrt:claimedSigner` that appears nowhere in the graph (round 17 P1).
    total_sig_occurrences = sum(e.get("signature_occurrences", 0)
                                for e in evidence.values())
    absent = []
    if total_sig_occurrences > emitted_sig_occurrences:
        absent.append(loss("L-NOSIGNODE", "%d signature occurrence(s) got no node "
                                          "— malformed, or belonging to a record "
                                          "this projection excluded"
                           % (total_sig_occurrences - emitted_sig_occurrences)))
    if has_settlement:
        absent.append(loss("L-NOSETTLE", "the receipt carries jurisdiction-scoped "
                                         "settlement; this MVP emits NO settlement "
                                         "nodes at all"))
    if has_unclaimed:
        absent.append(loss("L-NOUNCLAIMED", "the snapshot pins unclaimed members; "
                                            "they are not projected"))
    # A projected source's issues vanish from the graph. Exclusions carry
    # theirs verbatim in the view manifest, so the asymmetry was invisible:
    # a source good enough to project looks unqualified in RDF no matter what
    # the receipt said about it. Found against a LIVE store, where the owning
    # protocol WARNed on all 16 records ("binding unverified") and the graph
    # asserted 16 filings with no trace of it.
    excluded_occurrences = {(x["path"], x["entry_digest"]) for x in exclusions}
    has_projected_issues = any(
        s.get("issues") for s in core["sources"]
        if (s["path"], s["entry_digest"]) not in excluded_occurrences)
    if has_projected_issues:
        absent.append(loss("L-NOISSUE", "projected sources carry issues in the "
                                        "receipt; NO issue reaches the graph, so "
                                        "an unqualified node is not a clean one"))
    # §4.1 body mapping only applies where a record was actually projected: a
    # blob-only subroot has no body to map, and claiming the loss would be a
    # caveat on an absent fact — the very thing this manifest exists to stop
    if "record" in emitted_kinds:
        # §4.1 is mapped now, but only at the profile's WEAK defaults. The
        # table marks actor and policy "promotable", and promotion is a
        # claim about identity — that this key belongs to this actor, that
        # this policy governed this filing — which the receipt does not
        # license. So the honest residue is not "no mapping" but "no
        # promotion", and it must say which direction is missing.
        # Named as the exact RESIDUE. It used to say "nothing licenses
        # promotion to prov:Agent ... so none is asserted", which a
        # valid && bound signature makes false — that promotion IS licensed
        # and the Agent IS in the graph (round 18 P1). What remains missing
        # is the BODY-actor association and the policy Plan, and the loss now
        # says only that.
        absent.append(loss("L-NOPROMOTE", "the body's actor and policy stay at "
                                          "their weak defaults (wrt:claimedActor, "
                                          "wrt:underPolicy): no "
                                          "prov:Association/wasAssociatedWith "
                                          "and no prov:Plan/hadPlan. Signature "
                                          "attribution is separate and may be "
                                          "present"))

    # Every remaining loss is likewise dataset-relative: emitted only when the
    # graph actually contains the thing being qualified.
    qualified = []
    if "signature" in emitted_kinds:
        qualified.append(loss("L-SIG", "signature validity and binding are COPIED "
                                       "from the receipt; SEV performs no "
                                       "cryptography and re-derives neither"))
    # Withheld attribution is a fact about the graph a consumer must be told,
    # or `wrt:claimedSigner` reads as an oversight instead of a refusal.
    # Scoped to signature NODES that exist. Derived from the receipt's
    # entries it counted signatures on excluded records and then described
    # them as carrying `wrt:claimedSigner` — a statement about a node the
    # graph does not contain (round 17 P1).
    if unattributed_nodes:
        qualified.append(loss("L-UNBOUND", "%d projected signature(s) are not both "
                                           "valid and bound, so no agent is "
                                           "attributed; they carry "
                                           "wrt:claimedSigner instead"
                              % unattributed_nodes))
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
    if total_sig_occurrences > emitted_sig_occurrences:
        not_emitted.add("signature")
    if unattributed_nodes:
        not_emitted.add("attribution")
    if has_settlement:
        not_emitted.add("settlement")
    if has_unclaimed:
        not_emitted.add("unclaimed")
    if has_projected_issues:
        not_emitted.add("issue")
    # Derived from what was ACTUALLY emitted, per category. This block used
    # to read "a record exists, therefore its mapping is missing" — true
    # while §4.1 was unimplemented, and a direct contradiction of the graph
    # afterwards: the manifest named actor, subject, evidence and prior
    # un-emitted while the N-Quads carried all four. The presence of a record
    # is not evidence about the mapping; only the mapping is.
    not_emitted |= body_present - body_mapped

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

UPSTREAM_ACCEPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "conformance", "upstream",
                               "warrant-accept.warrant.json")
UPSTREAM_DIGEST = "bcd9765d73705a27f9273cf5e2fd2bd48ac5b1a1c02fc1e0958ede9dbdd4a88a"


def fixture(extra_files=None, misfiled_as=None, settlement=False):
    """An end-to-end triple (snapshot, receipt, cas) built on a **vendored
    upstream Warrant record** whose signature that protocol vouches for.

    The synthetic records this fixture used before were reported
    `valid: false` by their own receipts — so every positive projection path
    rested on a record its own receipt called unsigned. SEV still performs no
    cryptography: it consumes the upstream bytes as an external fixture
    (`conformance/upstream/README.md` records provenance and digest).
    """
    with open(UPSTREAM_ACCEPT, "rb") as fh:
        record_bytes = fh.read()
    if sm.sha256_hex(record_bytes) != UPSTREAM_DIGEST:
        raise AssertionError("vendored upstream fixture digest changed")
    record, _pf = sm.parse_strict(record_bytes)
    body = record["body"]
    wid = sm.sha256_hex(sm.jcs(body))
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
    entries = sm.envelope_signature_entries(record)[0]
    sources = sorted([
        {"kind": "blob", "path": ".warrants/blobs/p",
         "entry_digest": by_path[".warrants/blobs/p"], "loaded": True,
         "issues": []},
        {"kind": "record", "path": rec_path, "entry_digest": by_path[rec_path],
         "loaded": True, "claimed_wid": filed_as if sm.HEX64.match(filed_as) else None,
         "computed_wid": wid, "id_sound": filed_as == wid, "settlement": [],
         "signatures": [{"sig_digest": dg, "multiplicity": m, "actor": a,
                         "key": k, "valid": True, "binding": "unverified"}
                        for dg, m, a, k, _i in entries],
         "issues": ([] if filed_as == wid else
                    [{"code": "ID_UNSOUND", "severity": "ERR",
                      "at": {"kind": "path", "value": rec_path}}]),
         "reasons": [{"ptr": "/because/0", "kind": "check", "runtime": "cmd@v1",
                      "reason_digest": sm.sha256_hex(sm.jcs(body["because"][0])),
                      "outcome": {"re_execution": "not-applicable",
                                  "claimed_verdict": body["because"][0]["verdict"],
                                  "observed_verdict": None,
                                  "observed_result": None, "atp_spent": None,
                                  "failure_code": None}}]},
    ] + [{"kind": sm.classify_warrant_source(pth, ".warrants/")[0], "path": pth,
          "entry_digest": by_path[pth], "loaded": True, "issues": []}
         for pth in sorted(extra_files or {})],
        key=lambda x: (sm.path_sort_key(x["path"]), x["entry_digest"]))
    # `settlement=True` is what a receipt needs before it may report a
    # binding at all: without a pinned trust config no verifier can associate
    # a key with an actor, so `bound`/`unbound` are unreachable states and
    # the core now refuses them (round 18 P1)
    core = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(d),
            "grade": "settlement" if settlement else "base",
            "trust_config_digest": "c" * 64 if settlement else None,
            "execution_policy": {"runtimes": []},
            "ok": filed_as == wid, "errors": 0 if filed_as == wid else 1,
            "warnings": 0, "global_issues": [], "sources": sources}
    receipt = {"receipt": "warrant.verification-receipt@v0", "core": core,
               "producer": {"impl": "sev-fixture", "artifact_digest": None,
                            "spec": "0.4", "report_digest": "f" * 64,
                            "local_notes": []}}
    return snap, receipt, cas


def _mutate(receipt, fn):
    r = json.loads(json.dumps(receipt))
    fn(r)
    return r


def ski_fixture(extra_files=None, misfiled_as=None, body_extra=None,
                sigs_extra=None, settlement=False):
    """A SYNTHETIC ski@v1 triple, for vectors that need a projected check run.

    Its signature is a placeholder, and the receipt reports `valid: true` —
    a **producer claim SEV cannot verify**. The internal-consistency rule is
    one-way by design (a receipt may not contradict its own negative claims;
    a positive claim buys it nothing), so this is contract-legal. The
    flagship positive path uses the vendored upstream record instead, whose
    signature the owning protocol vouches for.

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
    body = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64},
            "under": ["b" * 64], "because": [reason_obj], "evidence": [],
            "actor": {"id": "signer@example"}, "prior": [], "ts": 1}
    # `body_extra` edits the committed body BEFORE the WarrantID is derived,
    # so a vector can exercise the §4.1 mapping without hand-forging an
    # id-unsound record: the wid below follows whatever the body becomes.
    body.update(body_extra or {})
    record = {"body": body,
              "sigs": [{"actor": "signer@example", "key": "c" * 64,
                        "sig": "d" * 128}] + list(sigs_extra or [])}
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
         # sorted, as the contract requires: envelope order is not receipt
         # order, and a second signature with a smaller digest made the
         # fixture itself unrepresentable (SIGNATURES_NOT_SORTED)
         "signatures": sorted(
             [{"sig_digest": d, "multiplicity": m, "actor": a,
               "key": k, "valid": True, "binding": "unverified"}
              for d, m, a, k, _i in sm.envelope_signature_entries(record)[0]],
             key=lambda x: (x["sig_digest"], x["multiplicity"])),
         "issues": sorted(
             ([] if filed_as == wid else
                [{"code": "ID_UNSOUND", "severity": "ERR",
                  "at": {"kind": "path", "value": rec_path}}]),
             key=lambda x: sm.jcs(x)),
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
            "grade": "settlement" if settlement else "base",
            "trust_config_digest": "c" * 64 if settlement else None,
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
    snap, receipt, cas = ski_fixture()

    result, f = _project_objects(snap, receipt, cas)
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

    result2, _ = _project_objects(snap, receipt, cas)
    sm.check_equal("determinism: second run byte-identical",
                   result2["nquads"], nq)

    # cross-process determinism: a fresh interpreter must emit the same bytes
    code = ("import sev_projector as p, snapshot_model as m, sys, hashlib\n"
            "s, r, c = p.ski_fixture()\n"
            "res, f = p._project_objects(s, r, c)\n"
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
    res_bad, f_bad = _project_objects(snap, bad, cas)
    sm.check_true("truncated receipt -> refusal, no partial output",
                  lambda: res_bad is None
                  and any(x["code"] == "SOURCE_MISSING_FOR_MEMBER" for x in f_bad))

    # mutation moves the graph digest
    snap2, receipt2, cas2 = ski_fixture()
    receipt2["core"]["sources"][1]["reasons"][0]["outcome"]["atp_spent"] = 8
    res2, f2 = _project_objects(snap2, receipt2, cas2)
    sm.check_true("outcome mutation -> different graph digest",
                  lambda: f2 == [] and res2["view_manifest"]["graph_digest"]
                  != sm.sha256_hex(nq))

    # unreceipted second subroot -> L-UNJUDGED
    files_b = {".b/z": b"z"}
    d_b = sm.subroot_descriptor("bos", {"name": "bos", "version": "0.4",
                                        "spec_digest": None}, ".b/",
                                sm.seal_universe(files_b))
    snap3, receipt3, cas3 = ski_fixture()
    wrapped = [{k: v for k, v in w.items() if k != "digest"}
               for w in snap3["subroots"]]
    snap3b = sm.snapshot_object(wrapped + [d_b], [])
    cas3.update({sm.sha256_hex(b"z"): b"z"})
    res3, f3 = _project_objects(snap3b, receipt3, cas3)
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
    snap4, receipt4, cas4 = ski_fixture(misfiled_as="b" * 64)
    res4, f4 = _project_objects(snap4, receipt4, cas4)
    sm.check_equal("negative receipt still projects (an honest ERR is evidence)",
                   f4, [])
    vm = res4["view_manifest"]
    sm.check_true("manifest counts the exclusion truthfully",
                  lambda: vm["sources_excluded"] == 1
                  and vm["sources_projected"] == 1
                  and vm["sources_projected"] + vm["sources_excluded"]
                  == vm["sources_in_receipts"]
                  and "ID_UNSOUND" in
                  [x["code"] for x in vm["exclusions"][0]["issues"]])
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
        src["issues"] = sorted(src["issues"] + [
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=0)},
            {"code": "ID_UNSOUND", "severity": "ERR", "at": dict(at, occurrence=1)}],
            key=lambda x: sm.jcs(x))
        r["core"].update(ok=False, errors=r["core"]["errors"] + 2)
    snap5, receipt5, cas5 = ski_fixture(misfiled_as="b" * 64)
    _two_occurrences(receipt5)
    res5, f5 = _project_objects(snap5, receipt5, cas5)
    sm.check_true("two same-code issues at distinct occurrences both survive",
                  lambda: f5 == [] and sum(
                      1 for x in res5["view_manifest"]["exclusions"][0]["issues"]
                      if x["code"] == "ID_UNSOUND"
                      and "occurrence" in x["at"]) == 2)

    # re-gate P1-3: non-record sources are actually projected, not just counted
    sm.check_true("blob/genesis/other emit a source entity",
                  lambda: b"sourceKind" in nq)
    # a genuine "other" member (not a relabelling — the classifier derives it)
    snap6, receipt6, cas6 = ski_fixture(extra_files={".warrants/README": b"hi"})
    res6, f6 = _project_objects(snap6, receipt6, cas6)
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
    body = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64}, "under": ["b" * 64],
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
    res7, f7 = _project_objects(snap7, receipt7, cas7)
    sm.check_true("fully committed undeclared runtime -> refusal, no graph",
                  lambda: res7 is None
                  and any(x["code"] == "RUNTIME_NOT_DECLARED" for x in f7))

    # re-gate P1-2: emitted evidence must detach from its input
    snap8, receipt8, cas8 = ski_fixture(misfiled_as="b" * 64)
    res8, _f8 = _project_objects(snap8, receipt8, cas8)
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
    res9, f9 = _project_objects(snap9, receipt9, cas9)
    sm.check_true("record relabelled 'other' -> refusal, no generic entity",
                  lambda: res9 is None
                  and any(x["code"] == "SOURCE_KIND_MISMATCH" for x in f9))

    # re-gate P1-1: stale computed_wid over an edited body
    reason_obj = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
                  "verdict": "pass", "transcript": "b" * 64}
    body_v2 = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64},
               "under": ["b" * 64], "because": [reason_obj], "evidence": [],
               "actor": {"id": "x"}, "prior": [], "ts": 2}   # ts 1 -> 2
    rec_v2 = {"body": body_v2,
              "sigs": [{"actor": "x", "key": "c" * 64, "sig": "d" * 128}]}
    snapA, receiptA, casA = ski_fixture()
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
    resA, fA = _project_objects(snapA, receiptA, casA)
    sm.check_true("stale computed_wid over an edited body -> refusal",
                  lambda: resA is None
                  and any(x["code"] == "COMPUTED_WID_MISMATCH" for x in fA))

    # re-gate P1-2: two paths, identical bytes -> two source occurrences
    snapB, receiptB, casB = ski_fixture(
        extra_files={".warrants/genesis.json": b"policy"})   # same bytes as blobs/p
    resB, fB = _project_objects(snapB, receiptB, casB)
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
        bod = {"warrant": body_version, "decision": "accept", "subject": {"hash": "a" * 64},
               "under": ["b" * 64], "because": [rob], "evidence": [],
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
                            for d, m, a, k, _i in sm.envelope_signature_entries(recd)[0]],
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
              "ok": True, "errors": 0,
              "warnings": 0,
              "global_issues": [], "sources": srcs}
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
        resX, fX = _project_objects(snX, recX, casX)
        sm.check_true("committed %s/%s in a %s body -> %s"
                      % (kind, runtime, ver, code),
                      lambda resX=resX, fX=fX, code=code:
                      resX is None and any(x["code"] == code for x in fX))

    # re-gate P1-2: CheckRun carries semantics and its execution input
    sm.check_true("CheckRun emits semanticsDigest, prov:used and a pointer",
                  lambda: b"semanticsDigest" in nq and b"prov#used" in nq
                  and b"sev#pointer" in nq and b"wrt:reason:" in nq)
    snapC, receiptC, casC = ski_fixture()
    receiptC["core"]["execution_policy"]["runtimes"][0]["semantics_digest"] = \
        sm.sha256_hex(b"book1-B")
    resC, fC = _project_objects(snapC, receiptC, casC)
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
    snapD, receiptD, casD = ski_fixture()
    dD = sm.subroot_descriptor(
        "warrant", {"name": "warrant", "version": "0.4",
                    "spec_digest": sm.sha256_hex(b"OTHER-SPEC")},
        ".warrants/",
        [{k: v for k, v in e.items()}
         for e in snapD["subroots"][0]["universe"]])
    snapD2 = sm.snapshot_object([dD], [])
    receiptD["core"]["subroot_descriptor_digest"] = sm.subroot_descriptor_digest(dD)
    resD, fD = _project_objects(snapD2, receiptD, casD)
    srcs_a = {ln.split(" ")[0] for ln in nq.decode().splitlines()
              if "sev#Source" in ln}
    srcs_d = {ln.split(" ")[0] for ln in resD["nquads"].decode().splitlines()
              if "sev#Source" in ln}
    sm.check_true("same bytes under a different contract -> different source IRIs",
                  lambda: fD == [] and srcs_a and srcs_d and srcs_a != srcs_d)
    sm.check_true("sources declare their subroot",
                  lambda: b"sev#inSubroot" in resD["nquads"])

    # re-gate P1-1: a forged source sharing a path with the real one
    snapE, receiptE, casE = ski_fixture()
    real = receiptE["core"]["sources"][0]
    forged = dict(real, entry_digest="0" * 64)
    receiptE["core"]["sources"] = sorted(
        receiptE["core"]["sources"] + [forged],
        key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
    resE, fE = _project_objects(snapE, receiptE, casE)
    sm.check_true("forged source sharing a path -> refusal, no forged blob",
                  lambda: resE is None
                  and any(x["code"] == "DUPLICATE_SOURCE_PATH" for x in fE)
                  and any(x["code"] == "SOURCE_DIGEST_MISMATCH" for x in fE))

    # re-gate P1-2: one runtime, two semantics
    snapF, receiptF, casF = ski_fixture()
    rts = receiptF["core"]["execution_policy"]["runtimes"]
    rts.append(dict(rts[0], semantics_digest="f" * 64))
    resF, fF = _project_objects(snapF, receiptF, casF)
    sm.check_true("duplicate runtime with a second anchor -> refusal",
                  lambda: resF is None
                  and any(x["code"] == "DUPLICATE_RUNTIME" for x in fF))

    # re-gate P1-3: matched over a check blob absent from this subroot
    snapG, receiptG, casG = ski_fixture()
    # rebuild the record so its committed check names a blob nobody sealed
    ghost = {"kind": "check", "runtime": "ski@v1", "check": "a" * 64,
             "verdict": "pass", "transcript": "b" * 64}
    bodyG = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64}, "under": ["b" * 64],
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
                            for d, m, a, k, _i in sm.envelope_signature_entries(recG)[0]],
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
    resG, fG = _project_objects(snapG, receiptG, casG)
    sm.check_true("matched over an unsealed check blob -> CHECK_BLOB_ABSENT",
                  lambda: resG is None
                  and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fG))

    # ...and an honest unverified/MISSING_BLOB keeps only a weak reference
    def _missing(r):
        src = r["core"]["sources"][1]
        src["reasons"][0]["outcome"].update(
            re_execution="unverified", observed_verdict=None,
            observed_result=None, atp_spent=None, failure_code="MISSING_BLOB")
        src["issues"] = sorted(src["issues"] + [
            {"code": "REASON_UNVERIFIED", "severity": "WARN",
             "at": {"kind": "json-pointer", "value": "/because/0"}}],
            key=lambda x: sm.jcs(x))
        r["core"].update(warnings=r["core"]["warnings"] + 1)
    receiptG2 = json.loads(json.dumps(receiptG))
    _missing(receiptG2)
    resG2, fG2 = _project_objects(snapG, receiptG2, casG)
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

    snapH, receiptH, casH = ski_fixture()
    revoked = RevokedAfterVerdict(casH)
    real_validate = sm.verify_receipt_bytes

    def _revoke_after(*a, **kw):
        out = real_validate(*a, **kw)
        revoked.revoked = True          # exactly at the verdict boundary
        return out
    sm.verify_receipt_bytes = _revoke_after
    try:
        resH, fH = _project_objects(snapH, receiptH, revoked)
    finally:
        sm.verify_receipt_bytes = real_validate
    baseline, _ = _project_objects(snapH, receiptH, casH)
    sm.check_equal("projection is byte-identical with the store revoked",
                   resH["nquads"], baseline["nquads"])
    sm.check_equal("zero store reads after the verdict",
                   revoked.reads_after_verdict, 0)

    # re-gate P1-1: the caller's objects are mutated exactly at the verdict
    # boundary. Only a private frozen view can survive this; a projector
    # reading receipt["core"] or snapshot again picks the poison up.
    snapI, receiptI, casI = ski_fixture()
    clean, _ = _project_objects(snapI, receiptI, casI)
    snapJ, receiptJ, casJ = ski_fixture()
    real_validate2 = sm.verify_receipt_bytes

    def _poison_after(*a, **kw):
        out = real_validate2(*a, **kw)
        rt = receiptJ["core"]["execution_policy"]["runtimes"][0]
        rt["semantics_digest"] = "f" * 64
        receiptJ["core"]["sources"][1]["reasons"][0]["outcome"][
            "observed_result"] = "not-a-nodehash"
        snapJ["bundle_root"] = "0" * 64
        return out
    sm.verify_receipt_bytes = _poison_after
    try:
        resJ, fJ = _project_objects(snapJ, receiptJ, casJ)
    finally:
        sm.verify_receipt_bytes = real_validate2
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
        bod = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64}, "under": ["b" * 64],
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
                            for d, m, a, k, _i in sm.envelope_signature_entries(recd)[0]],
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
              "ok": errs == 0, "errors": errs,
              "warnings": 0,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    snJ, recJ, casJ = _check_resolves_to(".warrants/README")   # digest is `other`
    resJ, fJ = _project_objects(snJ, recJ, casJ)
    sm.check_true("check resolving only to a non-blob source -> refusal",
                  lambda: resJ is None
                  and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fJ))

    for mode, label in [("err", "an ERR-judged blob"),
                        ("unloaded", "a blob that was never loaded")]:
        snK, recK, casK = _check_resolves_to(".warrants/blobs/p", break_blob=mode)
        resK, fK = _project_objects(snK, recK, casK)
        sm.check_true("check resolving to %s -> refusal" % label,
                      lambda resK=resK, fK=fK: resK is None
                      and any(x["code"] == "CHECK_BLOB_ABSENT" for x in fK))

    # self-review: what the receipt asserts and the graph omits must be
    # DECLARED, not implied. A loss manifest that puts caveats on absent
    # facts reads as "present, with reservations".
    # the fixture's record carries a real envelope signature, faithfully
    # reported by the receipt — and the graph still says nothing about it
    snapL, receiptL, casL = ski_fixture()
    actor = receiptL["core"]["sources"][1]["signatures"][0]["actor"]
    resL, fL = _project_objects(snapL, receiptL, casL)
    codesL = [e["code"] for e in resL["loss_manifest"]["entries"]]
    # The claim is about SIGNATURE nodes, and it used to be tested by the
    # absence of the actor STRING — which held only while the body mapping
    # was missing. §4.1 emits `wrt:claimedActor`, so the actor id now appears
    # legitimately; what must still be absent is any signature node, any
    # validity or binding statement, and any attribution.
    # §4.1 signatures. The fixture's signature is reported `valid: true` with
    # `binding: "unverified"` — a producer claim SEV cannot check. Validity
    # proves this KEY signed this WarrantID; it says nothing about whose key
    # it is. So the node exists, carries what the receipt said, and
    # attributes NOBODY.
    sm.check_true("a receipt-reported signature becomes a node",
                  lambda: fL == [] and all(
                      m in resL["nquads"] for m in
                      (b"wrt#Signature", b"wrt#sigValid", b"wrt#binding")))
    sm.check_true("...but an unbound signature attributes no agent",
                  lambda: not any(m in resL["nquads"] for m in
                                  (b"prov#wasAttributedTo", b"prov#Agent",
                                   b"urn:sev:agent:")))
    sm.check_true("...and names the signer only as a claim",
                  lambda: b"wrt#claimedSigner" in resL["nquads"]
                  and actor.encode() in resL["nquads"])
    sm.check_true("...and the record points at its signature",
                  lambda: any("wrt#hasSignature" in ln
                              and "urn:wrt:sig:" in ln
                              for ln in resL["nquads"].decode().splitlines()))

    # The same signature bytes twice is one entry per OCCURRENCE in the
    # receipt, so it must be two nodes in the graph. Keying the IRI on the
    # digest alone merged them, and the merged node then carried one set of
    # properties for two facts.
    dup = {"actor": "signer@example", "key": "c" * 64, "sig": "d" * 128}
    snapD, receiptD, casD = ski_fixture(sigs_extra=[dup])
    resD, fD = _project_objects(snapD, receiptD, casD)
    sm.check_equal("a duplicated signature projects", fD, [])
    sig_nodes = {ln.split(" ")[0][1:-1] for ln in resD["nquads"].decode().splitlines()
                 if "wrt#Signature" in ln}
    sm.check_equal("two identical signature occurrences are two nodes",
                   len(sig_nodes), 2)
    sm.check_true("...distinguished by multiplicity, not by content",
                  lambda: len({ln.split('"')[1] for ln in
                               resD["nquads"].decode().splitlines()
                               if "sev#multiplicity" in ln}) == 2)

    # The normative identity, component by component. Hashing the triple into
    # one opaque digest destroyed the join a consumer needs on `sig_digest`
    # and made these N-Quads incomparable with any other implementation's.
    sig_iri = sorted({ln.split(" ")[0][1:-1]
                      for ln in resL["nquads"].decode().splitlines()
                      if "wrt#Signature" in ln})[0]
    _wid_L = [s for s in receiptL["core"]["sources"]
              if s.get("computed_wid")][0]["computed_wid"]
    _sd_L = [s for s in receiptL["core"]["sources"]
             if s.get("signatures")][0]["signatures"][0]["sig_digest"]
    sm.check_equal("the signature IRI is the profile's, component by component",
                   sig_iri, "urn:wrt:sig:%s:%s:0" % (_wid_L, _sd_L))
    sm.check_true("...so sig_digest stays joinable as a substring",
                  lambda: _sd_L in sig_iri and _wid_L in sig_iri)

    # The WID is in that identity because the same INVALID {actor,key,sig}
    # can be replayed into several records. Without it the two records share
    # one node and each receipt's judgement of it overwrites the other's.
    replay = {"actor": "signer@example", "key": "c" * 64, "sig": "d" * 128}
    snapR1, receiptR1, casR1 = ski_fixture(body_extra={"ts": 1},
                                           sigs_extra=[replay])
    snapR2, receiptR2, casR2 = ski_fixture(body_extra={"ts": 2},
                                           sigs_extra=[replay])
    resR1, _ = _project_objects(snapR1, receiptR1, casR1)
    resR2, _ = _project_objects(snapR2, receiptR2, casR2)
    nodes1 = {ln.split(" ")[0][1:-1] for ln in resR1["nquads"].decode().splitlines()
              if "wrt#Signature" in ln}
    nodes2 = {ln.split(" ")[0][1:-1] for ln in resR2["nquads"].decode().splitlines()
              if "wrt#Signature" in ln}
    sm.check_equal("the same signature in two records shares no node",
                   sorted(nodes1 & nodes2), [])

    # An EXCLUDED record's signature never becomes a node. Counting the
    # receipt's entries instead of emitted nodes reported it as projected:
    # no L-NOSIGNODE, `signature` absent from not_emitted, and an L-UNBOUND
    # describing a `wrt:claimedSigner` that exists nowhere (round 17 P1).
    snapX2, receiptX2, casX2 = ski_fixture(misfiled_as="9" * 64)
    resX2, fX2 = _project_objects(snapX2, receiptX2, casX2)
    entriesX2 = sum(len(s.get("signatures") or [])
                    for s in receiptX2["core"]["sources"])
    quadsX2 = resX2["nquads"].decode()
    codesX2 = [e["code"] for e in resX2["loss_manifest"]["entries"]]
    sm.check_equal("an id-unsound record projects, excluded", fX2, [])
    sm.check_true("...its signature entry exists but its node does not",
                  lambda: entriesX2 >= 1 and "wrt#Signature" not in quadsX2)
    sm.check_true("...so the absence is declared, not implied",
                  lambda: "L-NOSIGNODE" in codesX2
                  and "signature" in
                  resX2["view_manifest"]["coverage"]["not_emitted"])
    sm.check_true("...and no loss describes a node the graph lacks",
                  lambda: "L-UNBOUND" not in codesX2
                  and "attribution" not in
                  resX2["view_manifest"]["coverage"]["not_emitted"])

    # A non-ASCII actor id must percent-encode identically everywhere, or two
    # honest implementations disagree on the IRI and the join silently fails.
    uactor = "Оксана/Ко@варрант"
    snapU3, receiptU3, casU3 = ski_fixture(
        body_extra={"actor": {"id": uactor}},
        sigs_extra=[{"actor": uactor, "key": "e" * 64, "sig": "f" * 128}],
        settlement=True)
    srcU3 = [s for s in receiptU3["core"]["sources"] if s.get("signatures")][0]
    for sg in srcU3["signatures"]:
        # the actor comes from the ENVELOPE; only the binding is the
        # receipt's to report, so only it is set here. Under settlement every
        # valid signature must resolve to bound or unbound -- `unverified`
        # would claim a pinned trust config produced no key state at all
        sg["binding"] = "bound" if sg["actor"] == uactor else "unbound"
    resU3, fU3 = _project_objects(snapU3, receiptU3, casU3)
    sm.check_equal("a unicode actor projects", fU3, [])
    # THE round-17 vector. Two honest receipts over the same bytes, one
    # reporting `unverified` and one `bound`. Unscoped, their union gave a
    # single node both bindings with nothing left to say which core digest
    # asserted which. Scoped, each judgement sits in its own verification
    # graph and the union stays readable.
    snapG, receiptG, casG = ski_fixture()
    resG1, _ = _project_objects(snapG, receiptG, casG)
    snapG2, receiptG2, casG2 = ski_fixture(settlement=True)
    for sg in [s for s in receiptG2["core"]["sources"]
               if s.get("signatures")][0]["signatures"]:
        sg["binding"] = "bound"
    resG2, _ = _project_objects(snapG2, receiptG2, casG2)
    union = resG1["nquads"].decode().splitlines() + \
        resG2["nquads"].decode().splitlines()
    binding_lines = [ln for ln in union if "wrt#binding" in ln]
    sm.check_equal("two receipts, two binding statements", len(binding_lines), 2)
    sm.check_equal("...on the same signature node",
                   len({ln.split(" ")[0] for ln in binding_lines}), 1)
    sm.check_equal("...but in two different verification graphs",
                   len({ln.rsplit("<", 1)[1] for ln in binding_lines}), 2)
    sm.check_true("...each naming its own receipt core digest",
                  lambda: all("urn:sev:g:verify:" in ln for ln in binding_lines))
    # the type statement is derivable from the sealed bytes alone, so both
    # projections emit it identically and it collapses to one line on union
    sm.check_equal("...while the mechanical topology stays unscoped and shared",
                   len({ln for ln in union if "wrt#Signature" in ln
                        and "urn:sev:g:verify:" not in ln}), 1)

    # Checking one predicate covered one predicate: `sigValid`, the agent
    # node and the attribution all leaked past a guard that only watched
    # `binding`. Every RECEIPT-DERIVED term is enumerated here, and the rule
    # is stated once over all of them.
    _RECEIPT_DERIVED = ("wrt#sigValid", "wrt#binding", "wrt#claimedSigner",
                        "prov#wasAttributedTo", "prov#Agent", "wrt#actorId")

    def _unscoped_receipt_terms(res):
        return sorted({t for ln in res["nquads"].decode().splitlines()
                       for t in _RECEIPT_DERIVED
                       if t in ln and "urn:sev:g:verify:" not in ln})

    for _label, _res in (("unbound fixture", resG1), ("bound fixture", resG2)):
        sm.check_equal("no receipt judgement sits in the default graph (%s)"
                       % _label, _unscoped_receipt_terms(_res), [])

    # The bound path emits an Agent and an attribution, so the manifest must
    # SAY so. It did not: `attribution` was missing from `emitted` while both
    # sat in the N-Quads, and `L-NOPROMOTE` went on denying the promotion the
    # graph had just made (round 18 P1).
    covG2 = resG2["view_manifest"]["coverage"]
    quadsG2 = resG2["nquads"].decode()
    sm.check_true("the bound path really does emit an agent",
                  lambda: "prov#Agent" in quadsG2
                  and "prov#wasAttributedTo" in quadsG2)
    sm.check_true("...so coverage lists attribution as emitted",
                  lambda: "attribution" in covG2["emitted"]
                  and "attribution" not in covG2["not_emitted"])
    sm.check_true("...and L-NOPROMOTE no longer denies it",
                  lambda: not any(
                      "none is asserted" in e.get("note", "")
                      for e in resG2["loss_manifest"]["entries"]
                      if e["code"] == "L-NOPROMOTE"))
    sm.check_equal("...and no emitted category is called un-emitted",
                   sorted(c for c in covG2["not_emitted"]
                          if c == "attribution" and "prov#wasAttributedTo" in quadsG2),
                   [])
    # The ASCII boundary, character class by character class — this is what
    # makes the contract language-neutral. `!*'()` is the set JavaScript's
    # encodeURIComponent keeps raw; `-._~` is the set that must stay raw;
    # `%` must itself be encoded, or the IRI is ambiguous.
    sm.check_equal("unreserved ASCII is retained literally",
                   iri_actor("AZaz09-._~"), "urn:wrt:actor:AZaz09-._~")
    sm.check_equal("...JavaScript's extra safe set is NOT",
                   iri_actor("!*'()"), "urn:wrt:actor:%21%2A%27%28%29")
    sm.check_equal("...and the delimiters an actor id carries are encoded",
                   iri_actor("/@%:+ "),
                   "urn:wrt:actor:%2F%40%25%3A%2B%20")
    sm.check_equal("...in uppercase hex, which RFC 3986 leaves optional",
                   iri_actor("\x0f"), "urn:wrt:actor:%0F")
    sm.check_equal("...over UTF-8 octets, not code points",
                   iri_actor("é"), "urn:wrt:actor:%C3%A9")
    sm.check_true("...to a fully percent-encoded actor IRI",
                  lambda: "<urn:wrt:actor:%D0%9E%D0%BA%D1%81%D0%B0%D0%BD%D0%B0"
                          "%2F%D0%9A%D0%BE%40%D0%B2%D0%B0%D1%80%D1%80%D0%B0"
                          "%D0%BD%D1%82>" in resU3["nquads"].decode())
    sm.check_true("...while the actor the body commits to IS mapped, weakly",
                  lambda: b"wrt#claimedActor" in resL["nquads"])

    # ---- §4.1 record-body mapping --------------------------------------
    # Every fact here is licensed by byte identity: the record reached the
    # graph only because computed_wid == claimed_wid, so its body is exactly
    # what the WarrantID commits to.
    shared, other, ancestor = "1" * 64, "2" * 64, "3" * 64
    snap_body, receipt_body, cas_body = ski_fixture(body_extra={
        "subject": {"hash": shared}, "evidence": [shared, other],
        "prior": [ancestor], "under": ["b" * 64]})
    res_body, f_body = _project_objects(snap_body, receipt_body, cas_body)
    sm.check_equal("a body-bearing fixture projects", f_body, [])
    quads = res_body["nquads"].decode()

    def _triples(subject):
        return [ln for ln in quads.splitlines() if ln.startswith("<%s> " % subject)]

    # the same blob is BOTH subject and evidence; one Usage node per role,
    # because merging them erases the distinction qualification exists for
    usages = sorted({ln.split(" ")[0][1:-1] for ln in quads.splitlines()
                     if "prov#Usage" in ln})
    roles = sorted(ln.split('"')[1] for ln in quads.splitlines()
                   if "sev#role" in ln)
    sm.check_equal("one blob in two roles yields two Usage nodes", len(usages), 3)
    sm.check_equal("...carrying the roles the body assigned",
                   roles, ["evidence", "evidence", "subject"])
    sm.check_true("...each pointing at its entity",
                  lambda: all(any("prov#entity" in ln for ln in _triples(u))
                              for u in usages))
    # a Usage node no activity points at is an orphan: typed, role-bearing,
    # and unreachable from the filing it is supposed to qualify
    _qualified = {ln.rsplit("<", 1)[1].rstrip("> .") for ln in quads.splitlines()
                  if "prov#qualifiedUsage" in ln}
    sm.check_equal("...and every Usage is reachable from its filing",
                   sorted(_qualified), usages)
    sm.check_true("...and the shared blob is ONE entity under both roles",
                  lambda: len({ln.split("> <")[-1].rstrip("> .")
                               for ln in quads.splitlines()
                               if "prov#entity" in ln
                               and shared in ln}) == 1)
    # a prior is another RECORD; keying it as a blob would point the lineage
    # edge at content this bundle need not contain
    sm.check_true("prior is a record IRI, never a blob IRI",
                  lambda: ("<urn:wrt:record:%s>" % ancestor) in quads
                  and ("urn:wrt:blob:%s" % ancestor) not in quads)
    sm.check_true("under[] maps to a policy entity, weakly",
                  lambda: "wrt#underPolicy" in quads
                  and ("<urn:wrt:blob:%s>" % ("b" * 64)) in quads)
    # promotion is a claim about identity that the receipt does not license
    sm.check_true("no promotion is asserted anywhere",
                  lambda: not any(m in quads for m in (
                      "prov#Agent", "prov#wasAttributedTo", "prov#hadPlan",
                      "prov#Association", "prov#wasAssociatedWith")))
    sm.check_true("...and that restraint is declared as L-NOPROMOTE",
                  lambda: "L-NOPROMOTE" in
                  [e["code"] for e in res_body["loss_manifest"]["entries"]])
    # The manifest must never contradict the bytes it ships with. A category
    # is listed un-emitted ONLY if its marker is genuinely absent from the
    # graph — checked against the N-Quads themselves rather than against the
    # code's intentions, because the previous version derived "the mapping is
    # missing" from "a record exists" and kept saying it after the mapping
    # landed (round 15 P1).
    _MARKERS = {"actor": "wrt#claimedActor",
                "subject": '<https://s0fractal.dev/ns/sev#role> "subject"',
                "evidence": '<https://s0fractal.dev/ns/sev#role> "evidence"',
                "prior": "wrt#prior",
                "policy-plan": "prov#hadPlan",
                "signature": "wrt#Signature",
                "attribution": "prov#wasAttributedTo",
                "settlement": "wrt#SettlementStatus"}

    def _coverage_lies(res):
        quads = res["nquads"].decode()
        return sorted(c for c in res["view_manifest"]["coverage"]["not_emitted"]
                      if c in _MARKERS and _MARKERS[c] in quads)

    # The weak default is a LITERAL, and the actor IRI is minted only on the
    # promotion path. Before a `valid && bound` signature the body's actor is
    # a claim the record makes, not an identity the bundle can name: minting
    # `urn:wrt:actor:…` would let two records that merely assert the same
    # string be merged into one referent by any consumer, on the strength of
    # nothing. Round 16 P1 — the profile said IRI, the code emitted a
    # literal, and the code was right.
    sm.check_true("claimedActor is a literal, not an IRI",
                  lambda: any(
                      ln.split(" ", 2)[2].startswith('"')
                      for ln in quads.splitlines()
                      if "wrt#claimedActor" in ln))
    sm.check_true("...and no actor IRI is minted without a binding",
                  lambda: "urn:wrt:actor:" not in quads
                  and "prov#wasAssociatedWith" not in quads
                  and "prov#Agent" not in quads)

    sm.check_equal("coverage never calls an emitted fact un-emitted",
                   _coverage_lies(res_body), [])
    sm.check_true("...while still declaring what is genuinely missing",
                  lambda: "policy-plan" in
                  res_body["view_manifest"]["coverage"]["not_emitted"])
    sm.check_equal("...and the same holds for the default fixture",
                   _coverage_lies(result), [])
    # (type closure over this graph is asserted below, where the guard is
    # defined — the mapped fixture is carried down to it as `res_body`)
    # a body with none of these fields must not invent empty structure
    snapE, receiptE, casE = ski_fixture(body_extra={
        "subject": {"hash": "a" * 64}, "evidence": [], "prior": []})
    resE, _fE = _project_objects(snapE, receiptE, casE)
    sm.check_true("absent evidence yields no evidence Usage",
                  lambda: '"evidence"' not in resE["nquads"].decode()
                  and "wrt#prior" not in resE["nquads"].decode())
    sm.check_true("...and the copied-not-derived caveat is declared",
                  lambda: "L-SIG" in codesL and "L-UNBOUND" in codesL)
    sm.check_true("the unimplemented body mapping is always declared",
                  lambda: "L-NOPROMOTE" in codesL)
    sm.check_true("no absence code is emitted for data that is not there",
                  lambda: "L-NOSETTLE" not in codesL
                  and "L-NOUNCLAIMED" not in codesL)   # this fixture has neither
    # ...but a snapshot that DOES pin unclaimed bytes must declare them
    snapU, receiptU, casU = ski_fixture()
    dU = {k: v for k, v in snapU["subroots"][0].items() if k != "digest"}
    note = b"loose note"
    snapU2 = sm.snapshot_object([dU], [{"path": "notes.txt",
                                        "sha256": sm.sha256_hex(note)}])
    casU[sm.sha256_hex(note)] = note
    receiptU["core"]["subroot_descriptor_digest"] = sm.subroot_descriptor_digest(dU)
    resU, fU = _project_objects(snapU2, receiptU, casU)
    sm.check_true("unclaimed snapshot members are declared when present",
                  lambda: fU == [] and "L-NOUNCLAIMED" in
                  [e["code"] for e in resU["loss_manifest"]["entries"]])
    cov = resL["view_manifest"]["coverage"]
    sm.check_true("coverage qualifies what 'projected' means",
                  lambda: "attribution" in cov["not_emitted"]
                  and "signature" not in cov["not_emitted"]
                  and {"record", "signature"} <= set(cov["emitted"]))

    # Live-store finding: the owning protocol WARNed on every record
    # ("binding unverified") and the graph asserted every filing with no
    # trace of it. Exclusions carry issues verbatim; projected sources
    # dropped theirs, so a node good enough to project looked unqualified.
    sm.check_true("a clean projected source declares no issue loss",
                  lambda: "L-NOISSUE" not in codesL
                  and "issue" not in cov["not_emitted"])
    snapW, receiptW, casW = ski_fixture()
    warned = receiptW["core"]["sources"][1]
    warned["issues"] = [{"code": "WARRANT_WARN", "severity": "WARN",
                         "at": {"kind": "path", "value": warned["path"]}}]
    receiptW["core"]["warnings"] = 1
    resW, fW = _project_objects(snapW, receiptW, casW)
    covW = resW["view_manifest"]["coverage"]
    codesW = [e["code"] for e in resW["loss_manifest"]["entries"]]
    sm.check_true("a WARN issue does not exclude its source",
                  lambda: fW == [] and resW["view_manifest"]["sources_excluded"] == 0)
    sm.check_true("...but no issue reaches the graph",
                  lambda: b"WARRANT_WARN" not in resW["nquads"])
    sm.check_true("...and that silence is declared as L-NOISSUE",
                  lambda: "L-NOISSUE" in codesW and "issue" in covW["not_emitted"])
    # The loss is about PROJECTED sources. Issues on an excluded source are
    # already carried verbatim in the exclusion, so claiming the loss for
    # them would put a caveat on a fact the manifest does in fact preserve.
    snapX, receiptX, casX = ski_fixture()
    droppedX = receiptX["core"]["sources"][1]
    # a plain reported ERR, not `ID_UNSOUND`: id-soundness is DERIVED from the
    # bytes, so asserting it would be refused as inconsistent (re-gate f7aa39c)
    droppedX["issues"] = [{"code": "WARRANT_ERR", "severity": "ERR",
                           "at": {"kind": "path", "value": droppedX["path"]}}]
    receiptX["core"]["errors"] = 1
    receiptX["core"]["ok"] = False
    resX, fX = _project_objects(snapX, receiptX, casX)
    covX = resX["view_manifest"]["coverage"]
    sm.check_true("issues on an EXCLUDED source do not raise L-NOISSUE",
                  lambda: fX == [] and resX["view_manifest"]["sources_excluded"] == 1
                  and "L-NOISSUE" not in
                  [e["code"] for e in resX["loss_manifest"]["entries"]]
                  and "issue" not in covX["not_emitted"])
    sm.check_true("...while the exclusion still carries them verbatim",
                  lambda: resX["view_manifest"]["exclusions"][0]["issues"]
                  == droppedX["issues"])

    # absent semantics must not stringify into the run's hash material
    snapM, receiptM, casM = ski_fixture()
    srcM = receiptM["core"]["sources"][1]
    srcM["reasons"][0]["outcome"].update(
        re_execution="unverified", observed_verdict=None, observed_result=None,
        atp_spent=None, failure_code="RUNTIME_UNAVAILABLE")
    srcM["issues"] = sorted(srcM["issues"] + [
        {"code": "REASON_UNVERIFIED", "severity": "WARN",
         "at": {"kind": "json-pointer", "value": "/because/0"}}],
        key=lambda x: sm.jcs(x))
    receiptM["core"].update(warnings=receiptM["core"]["warnings"] + 1)
    receiptM["core"]["execution_policy"]["runtimes"] = []
    resM, fM = _project_objects(snapM, receiptM, casM)
    sm.check_equal("a run with no declared semantics still validates", fM, [])
    sm.check_true("an unverified outcome yields an assessment, not a run",
                  lambda: b"sev#ExecutionAssessment" in resM["nquads"]
                  and b"sigma#CheckRun" not in resM["nquads"])
    # Scoped to the assessment's OWN triples, as the name always claimed. It
    # used to scan the whole document, which passed only because the MVP
    # emitted so little that no other node could carry `prov:used`; the §4.1
    # filing mapping (subject/evidence uses) made the coarse form fail. A
    # guard that depends on the rest of the graph staying small is not a
    # guard about the node it names.
    def _subject_triples(nquads, subject_iri):
        prefix = "<%s> " % subject_iri
        return [ln for ln in nquads.decode().splitlines() if ln.startswith(prefix)]

    assess_iri = [ln.split(" ")[0][1:-1]
                  for ln in resM["nquads"].decode().splitlines()
                  if "sev#ExecutionAssessment" in ln][0]
    sm.check_true("...and no PROV execution relation hangs off it",
                  lambda: not any(
                      p in ln for ln in _subject_triples(resM["nquads"], assess_iri)
                      for p in ("prov#used", "prov#wasInformedBy",
                                "prov#generated")))
    sm.check_true("...and the scoped guard sees a non-empty node",
                  lambda: len(_subject_triples(resM["nquads"], assess_iri)) > 1)

    # re-gate: an input that cannot be detached must be REFUSED, not shared.
    # The old freeze fell back to the caller's object on a copy failure, so
    # isolation opened exactly for the inputs that need it most.
    class Uncopyable(dict):
        def __deepcopy__(self, memo):
            raise RuntimeError("refuses to be copied")

    snapN, receiptN, casN = ski_fixture()
    hostile = Uncopyable(receiptN)
    real_validate3 = sm.verify_receipt_bytes

    def _mutate_after(*a, **kw):
        out = real_validate3(*a, **kw)
        hostile["core"]["execution_policy"]["runtimes"][0][
            "semantics_digest"] = "f" * 64
        hostile["core"]["sources"][1]["reasons"][0]["outcome"][
            "observed_result"] = "not-a-nodehash"
        return out
    sm.verify_receipt_bytes = _mutate_after
    try:
        resN, fN = _project_objects(snapN, hostile, casN)
    finally:
        sm.verify_receipt_bytes = real_validate3
    # round 13: the public verdict now takes BYTES, so a hostile caller
    # object cannot reach the validator at all — the projector serializes
    # first and detachment is structural rather than defended. The freeze
    # still guards the internal object path, asserted right below and
    # covered directly by the model suite.
    clean_ref, _ = _project_objects(*ski_fixture())
    sm.check_equal("a hostile caller object cannot poison the projection",
                   resN["nquads"], clean_ref["nquads"])
    sm.check_true("nothing the validator never judged reached any output",
                  lambda: b"not-a-nodehash" not in resN["nquads"])
    sm.check_equal("the internal object path still refuses it",
                   [x["code"] for x in sm._verdict_over_objects(
                       snapN, hostile, casN)],
                   ["INPUT_NOT_FREEZABLE"])

    # exact-type freezing: subclasses are the usual carrier of read-dependent
    # behaviour, so they are refused even when they copy cleanly
    class PlainSubclass(dict):
        pass
    snapO, receiptO, casO = ski_fixture()
    resO, fO = _project_objects(snapO, PlainSubclass(receiptO), casO)
    sm.check_equal("a dict subclass is refused on the object path",
                   [x["code"] for x in sm._verdict_over_objects(
                       snapO, PlainSubclass(receiptO), casO)],
                   ["INPUT_NOT_FREEZABLE"])
    sm.check_true("...and the honest plain-dict path still projects",
                  lambda: _project_objects(snapO, receiptO, casO)[1] == [])

    # re-gate: cyclic / over-deep plain containers must REFUSE, not crash.
    # These are exact dict/list values, so the type check alone lets them in.
    snapP, receiptP, casP = ski_fixture()
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
            resP, fP = _project_objects(sn, rc, casP)
            ok = resP is None and [x["code"] for x in fP] == ["INPUT_NOT_FREEZABLE"]
            detail = "" if ok else "findings=%s" % [x["code"] for x in fP]
        except RecursionError:
            ok, detail = False, "RecursionError escaped _project_objects()"
        sm._record("%s -> bounded INPUT_NOT_FREEZABLE" % label, ok, detail)

    # re-gate: the node budget must count scalars, not only containers — a
    # wide flat list was previously copied whole and the ceiling never fired
    wide = [0] * (sm.MAX_FREEZE_NODES + 1)
    _resW, fW = _project_objects(snapP, wide, casP)
    sm.check_equal("a wide scalar list exhausts the node budget",
                   [x["code"] for x in fW], ["INPUT_NOT_FREEZABLE"])
    narrow = [0] * 16
    _resW2, fW2 = _project_objects(snapP, narrow, casP)
    sm.check_true("a small list is refused on shape, not on budget",
                  lambda: [x["code"] for x in fW2] != ["INPUT_NOT_FREEZABLE"])

    # ...and the byte budget must bound payload, which a node count cannot.
    # The limit is lowered for the duration so the vector isolates the rule
    # without allocating 64 MiB.
    real_bytes = sm.MAX_FREEZE_BYTES
    sm.MAX_FREEZE_BYTES = 1024
    try:
        fat = {"core": {"blob": "z" * 4096}}
        _resZ, fZ = _project_objects(snapP, fat, casP)
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
    resB, fB = _project_objects(snapB, receiptB, casB)
    covB = resB["view_manifest"]["coverage"]
    codesB = [e["code"] for e in resB["loss_manifest"]["entries"]]
    sm.check_equal("blob-only dataset validates", fB, [])
    sm.check_equal("coverage claims only what this dataset holds",
                   covB["emitted"], ["source", "verification-receipt"])
    sm.check_equal("nothing is declared un-emitted that never existed",
                   covB["not_emitted"], [])
    sm.check_true("no losses about records, reasons, runs or signatures",
                  lambda: not ({"L-NOPROMOTE", "L-SIG", "L-UNBOUND",
                                "L-NOSIGNODE", "L-NOSETTLE",
                                "L-REEXEC", "L-SETTLE"} & set(codesB)))
    sm.check_true("the losses that DO apply are still stated",
                  lambda: {"L-CANON", "L-COMPLETE"} <= set(codesB))
    # ...while the full fixture, which does hold those facts, still declares them
    fullres, _ = _project_objects(*ski_fixture())
    codesFull = [e["code"] for e in fullres["loss_manifest"]["entries"]]
    sm.check_true("a record-bearing dataset still declares L-NOPROMOTE and L-REEXEC",
                  lambda: {"L-NOPROMOTE", "L-REEXEC"} <= set(codesFull))

    # re-gate: nested entries must be BOUND to the committed envelope, or a
    # clean receipt can hide and invent evidence at will
    def _tamper(fn):
        sn, rc, cs = ski_fixture()
        fn(rc["core"]["sources"][1])
        return _project_objects(sn, rc, cs)

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
    bodyP = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64}, "under": ["b" * 64],
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
             "ok": True, "errors": 0,
             "warnings": 0, "global_issues": [],
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
                                 for d, m, a, k, _i in
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
    resP2, fP2 = _project_objects(snapP2, receiptP2, casP2)
    sm.check_equal("a committed prose reason is not demanded of the receipt",
                   fP2, [])

    # re-gate: malformed COMMITTED evidence must not vanish before the
    # bijection. A derivation that returns only what it understood makes an
    # empty receipt an "exact bijection" with an empty derived set.
    def _with_committed(sigs=None, because=None):
        """Seal a record whose envelope/body carry the given raw shapes."""
        body = {"warrant": "0.2", "decision": "accept", "subject": {"hash": "a" * 64},
                "under": ["b" * 64],
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
                            for d, m, a, k, _i in entries],
             "issues": [], "reasons": reasons}],
            key=lambda s: (sm.path_sort_key(s["path"]), s["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": [
                  {"runtime": "ski@v1", "semantics": "sigma-book-i@v0.5",
                   "semantics_digest": sm.sha256_hex(b"book1"),
                   "budget_unit": "atp", "ceiling": 1000}]},
              "ok": True, "errors": 0, "warnings": 0,
              "global_issues": [],
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
        resX, fX = _project_objects(sn, rc, cs)
        sm.check_true("malformed committed evidence (%s) -> refusal" % label,
                      lambda resX=resX, fX=fX: resX is None and any(
                          x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fX))

    # positive control: a well-formed prose reason is legitimately
    # non-reportable and must NOT be treated as malformed
    snPC, rcPC, csPC = _with_committed(because=[
        {"kind": "prose", "text": "clause 1 of the policy"},
        {"kind": "check", "runtime": "ski@v1", "check": sm.sha256_hex(b"policy"),
         "verdict": "pass", "transcript": "b" * 64}])
    resPC, fPC = _project_objects(snPC, rcPC, csPC)
    sm.check_equal("well-formed prose beside a check projects cleanly", fPC, [])

    # The acknowledgement must be SEMANTIC: pointer alone let any unrelated
    # issue at the same address legalise malformed evidence.
    def _with_issue(code, severity, ptr="/sigs/0", sigs=[7], because=None,
                    errors=None, warnings=None):
        sn, rc, cs = _with_committed(sigs=sigs, because=because)
        rec_src = [x for x in rc["core"]["sources"] if x["kind"] == "record"][0]
        entries_here = [x for x in rec_src["signatures"]]
        extra = ([] if entries_here else
                 [{"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
                   "at": {"kind": "path", "value": rec_src["path"]}}])
        rec_src["issues"] = sorted(
            [{"code": code, "severity": severity,
              "at": {"kind": "json-pointer", "value": ptr}}] + extra,
            key=lambda x: sm.jcs(x))
        errs = (1 if severity == "ERR" else 0) + len(extra)
        rc["core"].update(ok=errs == 0, errors=errs,
                          warnings=1 if severity == "WARN" else 0)
        return _project_objects(sn, rc, cs)

    resU, fU = _with_issue("UNRELATED_WARNING", "WARN")
    sm.check_true("an unrelated issue at the right pointer does NOT legalise it",
                  lambda: resU is None
                  and any(x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fU))

    resV, fV = _with_issue("MALFORMED_SIGNATURE", "WARN")
    sm.check_true("right code, wrong severity (no valid actor sig) -> refusal",
                  lambda: resV is None
                  and any(x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fV))

    resW, fW3 = _with_issue("MALFORMED_SIGNATURE", "ERR", ptr="/body/because/0",
                            sigs=None, because=[7])
    sm.check_true("a signature code over a malformed reason -> refusal",
                  lambda: resW is None
                  and any(x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fW3))

    resR, fR = _with_issue("MALFORMED_SIGNATURE", "ERR")
    sm.check_equal("the normative (pointer, code, severity) tuple is accepted",
                   fR, [])
    sm.check_true("...and excludes the record honestly",
                  lambda: resR["view_manifest"]["sources_excluded"] == 1)
    # the record is excluded, so its malformed signature occurrence gets no
    # node — an absence that must be declared, not inferred from silence
    sm.check_true("...while coverage still knows signature evidence existed",
                  lambda: "L-NOSIGNODE" in [e["code"] for e in
                                            resR["loss_manifest"]["entries"]]
                  and "signature" in
                  resR["view_manifest"]["coverage"]["not_emitted"])

    # The producer-asserted `valid` field must NOT buy a severity downgrade.
    # The fixture below claims a valid actor signature over a key/signature
    # pair that cannot verify under warrant-sig-v1 — exactly the shape that
    # previously purchased a WARN for its malformed extra signature.
    snX, rcX, csX = _with_committed(
        sigs=[{"actor": "signer@example", "key": "c" * 64, "sig": "d" * 128}, 7])
    rec_srcX = [x for x in rcX["core"]["sources"] if x["kind"] == "record"][0]
    rec_srcX["signatures"][0]["valid"] = True          # self-asserted
    rec_srcX["issues"] = [{"code": "MALFORMED_SIGNATURE", "severity": "WARN",
                           "at": {"kind": "json-pointer", "value": "/sigs/1"}}]
    rcX["core"].update(warnings=1)
    resX, fX2 = _project_objects(snX, rcX, csX)
    sm.check_true("a self-asserted valid signature cannot downgrade to WARN",
                  lambda: resX is None
                  and any(x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fX2))

    # ...and the honest ERR path is accepted, excluding the record
    rcX2 = json.loads(json.dumps(rcX))
    rec2 = [x for x in rcX2["core"]["sources"] if x["kind"] == "record"][0]
    rec2["issues"] = [{"code": "MALFORMED_SIGNATURE", "severity": "ERR",
                       "at": {"kind": "json-pointer", "value": "/sigs/1"}}]
    rcX2["core"].update(ok=False, errors=1, warnings=0)
    resX2, fX3 = _project_objects(snX, rcX2, csX)
    sm.check_equal("malformed extra signature as ERR is accepted", fX3, [])
    sm.check_true("...and the record is excluded",
                  lambda: resX2["view_manifest"]["sources_excluded"] == 1)

    # re-gate: an outcome where nothing ran must not become an Activity
    snUP, rcUP, csUP = fixture()          # upstream cmd@v1 / not-applicable
    resUP, fUP = _project_objects(snUP, rcUP, csUP)
    nqUP = resUP["nquads"].decode()
    sm.check_equal("the upstream not-applicable record projects cleanly", fUP, [])
    sm.check_true("not-applicable yields an assessment and NO CheckRun",
                  lambda: "sev#ExecutionAssessment" in nqUP
                  and "sigma#CheckRun" not in nqUP)
    sm.check_true("...no coverage claim of a check-run, no L-REEXEC",
                  lambda: "check-run" not in resUP["view_manifest"]["coverage"]["emitted"]
                  and "L-REEXEC" not in [e["code"] for e in
                                         resUP["loss_manifest"]["entries"]])

    # independent entailment guard: PROV predicates whose domain is an
    # Activity may only have CheckRun subjects — checked by parsing the
    # output back, not by trusting the emitter
    # Bidirectional, predicate-specific and TOTAL over the profile's own type
    # registry. Recognising only CheckRun and Filing as activities meant an
    # explicit `prov:Activity` — or the profile's own VerificationActivity —
    # could stand in an Entity position although PROV makes those classes
    # disjoint; and the Agent branch and literal objects were never checked
    # at all (re-gate P1).
    # The shapes are DATA, not code: classes, disjointness axioms and
    # predicate endpoint kinds live together in one machine-readable
    # artifact, so a complete class registry can no longer sit beside an
    # MVP-only predicate list (re-gate P1). A second implementation reads
    # the same file.
    SHAPES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "conformance", "prov-shapes.json")
    with open(SHAPES_PATH) as _fh:
        SHAPES = json.load(_fh)
    RDF_TYPE_IRI = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
    PROFILE_CLASSES = SHAPES["classes"]
    PROV_SIGNATURES = SHAPES["predicates"]
    DISJOINT_PAIRS = [tuple(p) for p in SHAPES["disjoint_pairs"]]
    ROOT_KINDS = {"http://www.w3.org/ns/prov#Activity": "activity",
                  "http://www.w3.org/ns/prov#Entity": "entity",
                  "http://www.w3.org/ns/prov#Agent": "agent",
                  "http://www.w3.org/ns/prov#Influence": "influence"}

    def _ancestry(cls):
        """Full class ancestry (the class itself plus every declared parent).

        Resolving straight to a root kind threw away the identity a
        qualified relation needs: `qualifiedUsage` requires an object of
        class `prov:Usage`, not merely something of kind `influence`.
        """
        out, seen, cur = [], set(), cls
        while cur is not None and cur in PROFILE_CLASSES and cur not in seen:
            out.append(cur)
            seen.add(cur)
            cur = PROFILE_CLASSES[cur]
        return out

    def _kind_of_class(cls):
        """Root kind for a class, or None if it is unknown."""
        for anc in _ancestry(cls):
            if anc in ROOT_KINDS:
                return ROOT_KINDS[anc]
        return None

    def _validate_shapes():
        """The shapes artifact validates itself: no dangling parents, no
        cycles, every class reaching a declared root, every endpoint class
        known, every declared MVP predicate real."""
        problems = []
        for cls, parent in PROFILE_CLASSES.items():
            if parent is not None and parent not in PROFILE_CLASSES:
                problems.append(("dangling-parent", cls))
            seen, cur = set(), cls
            while cur is not None and cur in PROFILE_CLASSES:
                if cur in seen:
                    problems.append(("cycle", cls))
                    break
                seen.add(cur)
                cur = PROFILE_CLASSES[cur]
            if _kind_of_class(cls) is None:
                problems.append(("no-root", cls))
        for pred, shape in PROV_SIGNATURES.items():
            for pos in ("subject", "object"):
                spec = shape.get(pos, {})
                if "class" in spec and spec["class"] not in PROFILE_CLASSES:
                    problems.append(("unknown-endpoint-class", pred))
                if "kind" in spec and spec["kind"] not in SHAPES["kinds"]:
                    problems.append(("unknown-kind", pred))
                if "class" not in spec and "kind" not in spec:
                    problems.append(("empty-endpoint", pred))
        for pred in SHAPES["mvp_predicates"]:
            if pred not in PROV_SIGNATURES:
                problems.append(("mvp-predicate-not-in-target", pred))
        return sorted(set(problems))

    _TERM = re.compile(r'<([^>]*)>|"((?:[^"\\]|\\.)*)"(?:\^\^<[^>]*>)?')

    def _parse_nquads(nquads):
        """Structural: a term is an IRI or a literal, never a space-split
        token.

        Unisolatable by a behavioural vector today, and labelled rather than
        counted: N-Quads always has an IRI subject and predicate, so a naive
        space split misreads only the *content* of a spaced literal, never
        its IRI-vs-literal classification. Kept because that coincidence is a
        property of the current signature set, not of the format.
        """
        out = []
        for line in nquads.decode().splitlines():
            terms = [(m.group(1), True) if m.group(1) is not None
                     else (m.group(2), False)
                     for m in _TERM.finditer(line)]
            if len(terms) >= 3:
                out.append(terms[:4])
        return out

    def _prov_violations(nquads):
        quads = _parse_nquads(nquads)
        kinds, classes = {}, {}
        for terms in quads:
            (subj, s_iri), (pred, _p), (obj, o_iri) = terms[0], terms[1], terms[2]
            if s_iri and pred == RDF_TYPE_IRI and o_iri:
                anc = _ancestry(obj)
                if anc:
                    classes.setdefault(subj, set()).update(anc)
                kind = _kind_of_class(obj)
                if kind:
                    kinds.setdefault(subj, set()).add(kind)

        bad = set()
        for node, have in kinds.items():
            for a, b in DISJOINT_PAIRS:
                if a in have and b in have:
                    bad.add(("disjoint", "%s+%s" % (a, b), node))

        def _bad(node, is_iri, spec):
            if not is_iri:
                return True                    # a literal is never a PROV node
            if "class" in spec:
                # satisfied by the exact class or any declared subclass
                return spec["class"] not in classes.get(node, set())
            want = spec["kind"]
            if want == "any":
                return False
            have = kinds.get(node, set())
            if not have:
                return want != "entity"        # untyped nodes are Entities
            return want not in have            # presence, after disjointness

        for terms in quads:
            (subj, s_iri), (pred, _p), (obj, o_iri) = terms[0], terms[1], terms[2]
            shape = PROV_SIGNATURES.get(pred)
            if not shape:
                continue
            if _bad(subj, s_iri, shape["subject"]):
                bad.add(("subject", pred.rsplit("#", 1)[-1], subj))
            if _bad(obj, o_iri, shape["object"]):
                bad.add(("object", pred.rsplit("#", 1)[-1], obj))
        return bad

    # the guard itself is unit-tested: on a healthy graph the range clause
    # has nothing to catch, so it would otherwise be vacuous
    _bad_range = (
        b'<urn:sigma:run:a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> '
        b'<https://s0fractal.dev/ns/sigma#CheckRun> .\n'
        b'<urn:wrt:record:b> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> '
        b'<https://s0fractal.dev/ns/wrt#Warrant> .\n'
        b'<urn:sigma:run:a> <http://www.w3.org/ns/prov#wasInformedBy> '
        b'<urn:wrt:record:b> .\n')
    sm.check_true("guard catches an Activity-range violation",
                  lambda: ("object", "wasInformedBy", "urn:wrt:record:b")
                  in _prov_violations(_bad_range))
    # the §4.1 mapping introduced the first qualified relation this projector
    # emits (Usage), so it is run against the closure guard rather than
    # trusted: prov:qualifiedUsage needs an Activity subject and a Usage
    # object, and prov:entity needs an EntityInfluence subject
    # sorted(), not `== []`: the guard returns a SET, and comparing a set to
    # a list is vacuously false -- the assertion would have "failed" on a
    # perfectly clean graph, which is how it was caught
    sm.check_equal("the §4.1 mapped graph passes type closure",
                   sorted(_prov_violations(res_body["nquads"])), [])
    _bad_domain = (
        b'<urn:wrt:record:b> <http://www.w3.org/ns/prov#used> '
        b'<urn:wrt:blob:c> .\n')
    sm.check_true("guard catches an Activity-domain violation",
                  lambda: any(v[0] == "subject" for v in
                              _prov_violations(_bad_domain)))
    _entity_position = (
        b'<urn:sigma:run:a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> '
        b'<https://s0fractal.dev/ns/sigma#CheckRun> .\n'
        b'<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> '
        b'<urn:sigma:run:a> .\n')
    sm.check_true("guard catches an Activity standing in an Entity position",
                  lambda: any(v[0] == "object" for v in
                              _prov_violations(_entity_position)))

    # the re-gate's own countervectors, kept permanently
    def _nq(*lines):
        return ("\n".join(lines) + "\n").encode()

    T = "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>"
    _explicit_activity = _nq(
        "<urn:x> %s <http://www.w3.org/ns/prov#Activity> ." % T,
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        "<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> <urn:x> .")
    sm.check_true("an explicit prov:Activity cannot sit in an Entity position",
                  lambda: any(v[0] == "object"
                              for v in _prov_violations(_explicit_activity)))

    _profile_activity = _nq(
        "<urn:v> %s <https://s0fractal.dev/ns/sev#VerificationActivity> ." % T,
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        "<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> <urn:v> .")
    sm.check_true("...and neither can the profile's own VerificationActivity",
                  lambda: any(v[0] == "object"
                              for v in _prov_violations(_profile_activity)))

    _record_as_agent = _nq(
        "<urn:wrt:record:b> %s <https://s0fractal.dev/ns/wrt#Warrant> ." % T,
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        "<urn:sigma:run:a> <http://www.w3.org/ns/prov#wasAssociatedWith> "
        "<urn:wrt:record:b> .")
    sm.check_true("an Entity cannot stand in an Agent position",
                  lambda: any(v[0] == "object"
                              for v in _prov_violations(_record_as_agent)))

    _literal_agent = _nq(
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        '<urn:sigma:run:a> <http://www.w3.org/ns/prov#wasAssociatedWith> '
        '"alice" .')
    sm.check_true("a literal is never a PROV node (Agent position)",
                  lambda: any(v[0] == "object"
                              for v in _prov_violations(_literal_agent)))

    _literal_entity = _nq(
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        '<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> "just text" .')
    sm.check_true("...nor in an Entity position",
                  lambda: any(v[0] == "object"
                              for v in _prov_violations(_literal_entity)))

    _spaced_literal = _nq(
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        '<urn:sigma:run:a> <https://s0fractal.dev/ns/sigma#runtime> '
        '"a b c" .')
    sm.check_equal("a literal containing spaces parses as one term",
                   _prov_violations(_spaced_literal), set())

    # disjointness is decided over the closure, not by membership
    _both = _nq(
        "<urn:x> %s <http://www.w3.org/ns/prov#Activity> ." % T,
        "<urn:x> %s <http://www.w3.org/ns/prov#Entity> ." % T,
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        "<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> <urn:x> .")
    sm.check_true("a node typed Activity AND Entity is rejected outright",
                  lambda: ("disjoint", "activity+entity", "urn:x")
                  in _prov_violations(_both))

    # round 10: the envelope's top-level shape is derived, not assumed —
    # and the attack lands on genuinely pretty-printed bytes, the same form
    # every real Warrant store uses
    import json as _json

    def _envelope_record(extra=None, ack=None, wid=None, sound=False):
        env = _json.loads(open(UPSTREAM_ACCEPT, "rb").read())
        if extra:
            env.update(extra)
        raw = _json.dumps(env, indent=2, sort_keys=True).encode() + b"\n"
        path = ".warrants/records/%s.json" % ("c" * 64)
        files = {path: raw, ".warrants/blobs/p": b"policy"}
        cs = {sm.sha256_hex(v): v for v in files.values()}
        un = sm.seal_universe(files)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        issues = ([{"code": ack, "severity": "ERR",
                    "at": {"kind": "path", "value": path}}] if ack else [])
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True, "issues": []},
            {"kind": "record", "path": path, "entry_digest": bp[path],
             "loaded": True, "claimed_wid": "c" * 64, "computed_wid": wid,
             "id_sound": sound, "settlement": [], "signatures": [],
             "issues": issues, "reasons": []}],
            key=lambda x: (sm.path_sort_key(x["path"]), x["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": []},
              "ok": not issues, "errors": len(issues), "warnings": 0,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    snX1, rcX1, csX1 = _envelope_record(extra={"attacker_extra": 1})
    resX1, fX1 = _project_objects(snX1, rcX1, csX1)
    sm.check_true("a pretty-printed envelope with an extra member is refused",
                  lambda: resX1 is None and any(
                      x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fX1))

    snX2, rcX2, csX2 = _envelope_record(extra={"attacker_extra": 1},
                                        ack="MALFORMED_ENVELOPE")
    resX2, fX2 = _project_objects(snX2, rcX2, csX2)
    sm.check_equal("...acknowledged, it is valid negative evidence", fX2, [])
    sm.check_true("...and the record is excluded, never a graph node",
                  lambda: resX2["view_manifest"]["sources_excluded"] == 1
                  and b"urn:wrt:record:" not in resX2["nquads"])

    snX3, rcX3, csX3 = _envelope_record(ack="MALFORMED_ENVELOPE")
    resX3, fX3 = _project_objects(snX3, rcX3, csX3)
    sm.check_true("claiming a malformed envelope over a sound one is refused",
                  lambda: resX3 is None and any(
                      x["code"] == "SPURIOUS_MALFORMED_ENVELOPE" for x in fX3))

    snX4, rcX4, csX4 = _envelope_record(extra={"attacker_extra": 1},
                                        ack="MALFORMED_ENVELOPE",
                                        wid="d" * 64)
    resX4, fX4 = _project_objects(snX4, rcX4, csX4)
    sm.check_true("a refused envelope may not carry an identity claim",
                  lambda: resX4 is None and any(
                      x["code"] == "UNREADABLE_WITH_IDENTITY_CLAIM" for x in fX4))

    for missing in ("body", "sigs"):
        env_missing = {"body": {}, "sigs": []}
        del env_missing[missing]
        snX5, rcX5, csX5 = _envelope_record(extra=None)
        # rebuild with the member removed rather than added
        import copy as _copy
        raw5 = _json.dumps(env_missing, indent=2, sort_keys=True).encode() + b"\n"
        path5 = ".warrants/records/%s.json" % ("c" * 64)
        files5 = {path5: raw5, ".warrants/blobs/p": b"policy"}
        cs5 = {sm.sha256_hex(v): v for v in files5.values()}
        un5 = sm.seal_universe(files5)
        dd5 = sm.subroot_descriptor("warrant",
                                    {"name": "warrant", "version": "0.4",
                                     "spec_digest": sm.sha256_hex(b"spec")},
                                    ".warrants/", un5)
        sn5 = sm.snapshot_object([dd5], [])
        bp5 = {e["path"]: e["sha256"] for e in un5}
        src5 = _copy.deepcopy(rcX5["core"]["sources"])
        for x in src5:
            x["entry_digest"] = bp5[x["path"]]
        rc5 = _copy.deepcopy(rcX5)
        rc5["core"].update(subroot_descriptor_digest=sm.subroot_descriptor_digest(dd5),
                           sources=sorted(src5, key=lambda x: (
                               sm.path_sort_key(x["path"]), x["entry_digest"])))
        res5, f5 = _project_objects(sn5, rc5, cs5)
        sm.check_true("an envelope missing `%s` is refused" % missing,
                      lambda f5=f5, res5=res5: res5 is None and any(
                          x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in f5))

    # round 9: a strict-parser finding must not be discarded — but envelope
    # canonicality is NOT one of Warrant's requirements
    _up_raw = open(UPSTREAM_ACCEPT, "rb").read()
    sm.check_equal("the real upstream Warrant record is non-canonical bytes",
                   [x["code"] for x in sm.parse_strict(_up_raw)[1]],
                   ["NOT_CANONICAL"])
    sm.check_true("...and it is still readable evidence (envelopes are not hashed)",
                  lambda: _project_objects(*fixture())[1] == []
                  and b"urn:wrt:record:" in _project_objects(*fixture())[0]["nquads"])

    def _bad_bytes_record(raw, ack=False, wid=None, sound=False):
        path = ".warrants/records/%s.json" % ("c" * 64)
        files = {path: raw, ".warrants/blobs/p": b"policy"}
        cs = {sm.sha256_hex(v): v for v in files.values()}
        un = sm.seal_universe(files)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        issues = ([{"code": "RECORD_UNREADABLE", "severity": "ERR",
                    "at": {"kind": "path", "value": path}}] if ack else [])
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True, "issues": []},
            {"kind": "record", "path": path, "entry_digest": bp[path],
             "loaded": True, "claimed_wid": "c" * 64, "computed_wid": wid,
             "id_sound": sound, "settlement": [], "signatures": [],
             "issues": issues, "reasons": []}],
            key=lambda x: (sm.path_sort_key(x["path"]), x["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": []},
              "ok": not issues, "errors": len(issues), "warnings": 0,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    # findings that ARE fatal: bytes Warrant's own contract rejects
    for label, raw in [
            ("duplicate members", b'{"body":1,"body":2}'),
            ("trailing data", b'{"body":{}} trailing'),
            ("a float", b'{"body":{"ts":1.5}}'),
            ("a BOM", b'\xef\xbb\xbf{"body":{}}')]:
        snF, rcF, csF = _bad_bytes_record(raw)
        resF, fF = _project_objects(snF, rcF, csF)
        sm.check_true("a record with %s is unreadable and must be acknowledged"
                      % label,
                      lambda resF=resF, fF=fF: resF is None and any(
                          x["code"] == "RECORD_UNREADABLE_UNREPORTED" for x in fF))
        snG, rcG, csG = _bad_bytes_record(raw, ack=True)
        resG, fG = _project_objects(snG, rcG, csG)
        sm.check_true("...and acknowledged, it is valid negative evidence",
                      lambda resG=resG, fG=fG: fG == []
                      and resG["view_manifest"]["sources_excluded"] == 1)

    # round 8: malformed evidence, honestly acknowledged, is VALID evidence
    def _unparseable(ack=True, wid_residue=False, spurious=False):
        """Seal a record whose bytes do not parse (or, for `spurious`, one
        that parses fine while the receipt claims it does not)."""
        raw = sm.jcs({"body": {"warrant": "0.2", "decision": "accept",
                               "subject": {"hash": "a" * 64}, "under": ["b" * 64], "because": [],
                               "evidence": [], "actor": {"id": "signer@example"},
                               "prior": [], "ts": 1},
                      "sigs": []}) if spurious else b"{"
        path = ".warrants/records/%s.json" % ("c" * 64)
        files = {path: raw, ".warrants/blobs/p": b"policy"}
        cs = {sm.sha256_hex(v): v for v in files.values()}
        un = sm.seal_universe(files)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        issues = ([{"code": "RECORD_UNREADABLE", "severity": "ERR",
                    "at": {"kind": "path", "value": path}}] if ack else [])
        rec_src = {"kind": "record", "path": path, "entry_digest": bp[path],
                   "loaded": True,            # the bytes WERE obtained
                   "claimed_wid": "c" * 64,
                   "computed_wid": ("d" * 64 if wid_residue else None),
                   "id_sound": False, "settlement": [], "signatures": [],
                   "issues": issues, "reasons": []}
        if spurious:
            body = sm.parse_strict(raw)[0]["body"]
            rec_src.update(computed_wid=sm.sha256_hex(sm.jcs(body)),
                           id_sound=False)
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True,
             "issues": []}, rec_src],
            key=lambda x: (sm.path_sort_key(x["path"]), x["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": []},
              "ok": not issues, "errors": len(issues), "warnings": 0,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    snA, rcA, csA = _unparseable(ack=True)
    resA, fA = _project_objects(snA, rcA, csA)
    sm.check_equal("acknowledged malformed evidence is a VALID receipt", fA, [])
    sm.check_true("...and the record is excluded, not fatal",
                  lambda: resA["view_manifest"]["sources_excluded"] == 1
                  and [x["code"] for x in
                       resA["view_manifest"]["exclusions"][0]["issues"]]
                  == ["RECORD_UNREADABLE"])

    snB, rcB, csB = _unparseable(ack=False)
    resB, fB = _project_objects(snB, rcB, csB)
    sm.check_true("unacknowledged malformed evidence is refused",
                  lambda: resB is None and any(
                      x["code"] == "RECORD_UNREADABLE_UNREPORTED" for x in fB))

    snC, rcC, csC = _unparseable(spurious=True)
    resC, fC = _project_objects(snC, rcC, csC)
    sm.check_true("claiming unreadable over parseable bytes is refused",
                  lambda: resC is None and any(
                      x["code"] == "SPURIOUS_RECORD_UNREADABLE" for x in fC))

    snD, rcD, csD = _unparseable(ack=True, wid_residue=True)
    resD, fD = _project_objects(snD, rcD, csD)
    sm.check_true("an unparseable body may not carry an identity claim",
                  lambda: resD is None and any(
                      x["code"] == "UNREADABLE_WITH_IDENTITY_CLAIM" for x in fD))

    # round 12: a source's issues are local to it. Fixing the
    # acknowledgement join was not enough — exclusion keys on "any ERR
    # here", so a misdirected ERR still erased a healthy record.
    snS1, rcS1, csS1 = _envelope_record()            # a SOUND envelope
    recS1 = [x for x in rcS1["core"]["sources"] if x["kind"] == "record"][0]
    recS1["issues"] = [{"code": "MALFORMED_ENVELOPE", "severity": "ERR",
                        "at": {"kind": "path",
                               "value": ".warrants/blobs/p"}}]
    rcS1["core"].update(ok=False, errors=1)
    resS1, fS1 = _project_objects(snS1, rcS1, csS1)
    sm.check_true("a misdirected ERR cannot erase a healthy record",
                  lambda: resS1 is None and any(
                      x["code"] == "ISSUE_OUT_OF_SCOPE" for x in fS1))

    snS2, rcS2, csS2 = _envelope_record()
    recS2 = [x for x in rcS2["core"]["sources"] if x["kind"] == "record"][0]
    recS2["issues"] = [{"code": "SOMETHING", "severity": "ERR",
                        "at": {"kind": "global", "value": "store"}}]
    rcS2["core"].update(ok=False, errors=1)
    resS2, fS2 = _project_objects(snS2, rcS2, csS2)
    sm.check_true("a store-wide subject may not be attached to a source",
                  lambda: resS2 is None and any(
                      x["code"] == "GLOBAL_ISSUE_ON_SOURCE" for x in fS2))

    # ...while a correctly scoped issue still works, in both locator forms
    snS3, rcS3, csS3 = _envelope_record(extra={"attacker_extra": 1},
                                        ack="MALFORMED_ENVELOPE")
    resS3, fS3 = _project_objects(snS3, rcS3, csS3)
    sm.check_equal("a locally scoped path issue is still valid", fS3, [])
    sm.check_true("...and a json-pointer issue into this record is too",
                  lambda: _project_objects(*ski_fixture())[1] == [])

    # ...and the severity is part of the join too: an acknowledgement that
    # does not make the record fatal has not acknowledged anything
    snW, rcW, csW = _envelope_record(extra={"attacker_extra": 1},
                                     ack="MALFORMED_ENVELOPE")
    recW = [x for x in rcW["core"]["sources"] if x["kind"] == "record"][0]
    recW["issues"][0]["severity"] = "WARN"
    rcW["core"].update(ok=True, errors=0, warnings=1)
    resW, fW = _project_objects(snW, rcW, csW)
    sm.check_true("a WARN-level acknowledgement does not acknowledge",
                  lambda: resW is None and any(
                      x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fW))

    # round 11: an acknowledgement must name THIS source, not merely carry
    # the right code — an issue pointing elsewhere describes elsewhere
    def _misdirected(builder, code, **kw):
        sn, rc, cs = builder(ack=code, **kw)
        rec = [x for x in rc["core"]["sources"] if x["kind"] == "record"][0]
        # same code, same severity, but the locator names the blob member
        rec["issues"][0]["at"] = {"kind": "path",
                                  "value": ".warrants/blobs/p"}
        return _project_objects(sn, rc, cs)

    resM1, fM1 = _misdirected(_envelope_record, "MALFORMED_ENVELOPE",
                              extra={"attacker_extra": 1})
    sm.check_true("an envelope acknowledgement pointing at another member "
                  "does not acknowledge this one",
                  lambda: resM1 is None and any(
                      x["code"] == "MALFORMED_ENVELOPE_UNREPORTED" for x in fM1))

    def _unparse_misdirected():
        sn, rc, cs = _unparseable(ack=True)
        rec = [x for x in rc["core"]["sources"] if x["kind"] == "record"][0]
        rec["issues"][0]["at"] = {"kind": "path", "value": ".warrants/blobs/p"}
        return _project_objects(sn, rc, cs)

    resM2, fM2 = _unparse_misdirected()
    sm.check_true("...and neither does a misdirected RECORD_UNREADABLE",
                  lambda: resM2 is None and any(
                      x["code"] == "RECORD_UNREADABLE_UNREPORTED" for x in fM2))

    # the MVP must not drop a source on a producer-selected `loaded`
    snLoad, rcLoad, csLoad = ski_fixture()
    recsrc = [x for x in rcLoad["core"]["sources"] if x["kind"] == "record"][0]
    recsrc["loaded"] = False
    recsrc["issues"] = sorted(recsrc["issues"] + [
        {"code": "RECORD_UNREADABLE", "severity": "ERR",
         "at": {"kind": "path", "value": recsrc["path"]}}],
        key=lambda x: sm.jcs(x))
    rcLoad["core"].update(ok=False, errors=rcLoad["core"]["errors"] + 1)
    resLoad, fLoad = _project_objects(snLoad, rcLoad, csLoad)
    sm.check_true("a fabricated unreadable record cannot vanish from the graph",
                  lambda: resLoad is None
                  and any(x["code"] == "LOADED_MISREPORTED" for x in fLoad))

    # every ordering in the format is UTF-16, including manifest lists and
    # quad lines — codepoint order disagrees on astral-vs-BMP and both feed
    # digests
    astral, bmp = "\U00010000", "\ue000"
    sm.check_true("codepoint order really disagrees (the trap)",
                  lambda: sorted([astral, bmp]) == [bmp, astral])
    # a REAL projection carrying two unreceipted subroots with astral names
    snapO2, receiptO2, casO2 = ski_fixture()
    base_desc = {k: v for k, v in snapO2["subroots"][0].items() if k != "digest"}
    extra = []
    for name, path in ((astral, ".a/"), (bmp, ".b/")):
        files = {path + "x": name.encode()}
        casO2.update({sm.sha256_hex(v): v for v in files.values()})
        extra.append(sm.subroot_descriptor(
            name, {"name": name, "version": "0.4", "spec_digest": None},
            path, sm.seal_universe(files)))
    snapO3 = sm.snapshot_object([base_desc] + extra, [])
    resO3, fO3 = _project_objects(snapO3, receiptO2, casO2)
    sm.check_equal("astral subroot names project cleanly", fO3, [])
    sm.check_equal("unjudged_subroots is UTF-16 ordered in the manifest",
                   resO3["view_manifest"]["unjudged_subroots"], [astral, bmp])
    g_probe = Graph()
    g_probe.add("urn:s", SEV + "path", _lit(bmp))
    g_probe.add("urn:s", SEV + "path", _lit(astral))
    lines = g_probe.nquads().decode().splitlines()
    sm.check_equal("quad ordering is UTF-16 too",
                   lines, sorted(lines, key=sm.path_sort_key))

    # The honesty sentence must not carry a hardcoded count that can rot.
    # Scope is LIVE PROSE about the current state — README and CI. Round
    # ledgers and review files legitimately state counts, because each is a
    # dated claim bound to one SHA; scrubbing those would rewrite history
    # rather than keep it honest.
    _root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    _stale = []
    for rel in ("README.md", ".github/workflows/model.yml"):
        with open(os.path.join(_root, rel)) as fh:
            for i, line in enumerate(fh, 1):
                # \S* so hyphenated and prefixed forms cannot slip past:
                # "56 self-vectors" survived the first cleanup precisely
                # because the pattern demanded "vectors" immediately
                if re.search(r"\b\d+\s+\S*vectors?\b", line):
                    _stale.append("%s:%d" % (rel, i))
    sm.check_equal("no hardcoded vector count can go stale in prose or CI",
                   _stale, [])

    # ---- round 13 countervectors -------------------------------------
    def _record_fixture(env, sigs=None, issues=None, reasons=None,
                        policy=None, warnings=0, errors=0):
        """Seal one record envelope and build a receipt around it."""
        raw = _json.dumps(env, indent=2, sort_keys=True).encode() + b"\n"
        wid = sm.sha256_hex(sm.jcs(env["body"]))
        path = ".warrants/records/%s.json" % wid
        files = {path: raw, ".warrants/blobs/p": b"policy"}
        cs = {sm.sha256_hex(v): v for v in files.values()}
        un = sm.seal_universe(files)
        dd = sm.subroot_descriptor("warrant",
                                   {"name": "warrant", "version": "0.4",
                                    "spec_digest": sm.sha256_hex(b"spec")},
                                   ".warrants/", un)
        sn = sm.snapshot_object([dd], [])
        bp = {e["path"]: e["sha256"] for e in un}
        entries = sm.envelope_signature_entries(env)[0]
        srcs = sorted([
            {"kind": "blob", "path": ".warrants/blobs/p",
             "entry_digest": bp[".warrants/blobs/p"], "loaded": True,
             "issues": []},
            {"kind": "record", "path": path, "entry_digest": bp[path],
             "loaded": True, "claimed_wid": wid, "computed_wid": wid,
             "id_sound": True, "settlement": [],
             "signatures": (sigs if sigs is not None else
                            [{"sig_digest": d, "multiplicity": m, "actor": a,
                              "key": k, "valid": True,
                              "binding": "unverified"}
                             for d, m, a, k, _i in entries]),
             "issues": issues or [], "reasons": reasons or []}],
            key=lambda x: (sm.path_sort_key(x["path"]), x["entry_digest"]))
        cr = {"subroot_descriptor_digest": sm.subroot_descriptor_digest(dd),
              "grade": "base", "trust_config_digest": None,
              "execution_policy": {"runtimes": policy or []},
              "ok": errors == 0, "errors": errors, "warnings": warnings,
              "global_issues": [], "sources": srcs}
        return sn, {"receipt": "warrant.verification-receipt@v0", "core": cr,
                    "producer": {"impl": "x", "artifact_digest": None,
                                 "spec": "0.4", "report_digest": "f" * 64,
                                 "local_notes": []}}, cs

    def _upstream_env():
        return _json.loads(open(UPSTREAM_ACCEPT, "rb").read())

    # (2) an INVALID_SIGNATURE must name the index that actually failed
    def _two_sigs(bad, reported, drop_issue=False):
        env = _upstream_env()
        env["sigs"] = [dict(env["sigs"][0]),
                       dict(env["sigs"][0], sig="e" * 128)]
        entries = sm.envelope_signature_entries(env)[0]
        sigs = sorted([{"sig_digest": d, "multiplicity": m, "actor": a,
                        "key": k, "valid": i != bad,
                        "binding": "unverified"}
                       for i, (d, m, a, k, _oi) in enumerate(entries)],
                      key=lambda x: (x["sig_digest"], x["multiplicity"]))
        issues = ([] if drop_issue else
                  [{"code": "INVALID_SIGNATURE", "severity": "WARN",
                    "at": {"kind": "json-pointer",
                           "value": "/sigs/%d" % reported}}])
        # the record's committed reason must still be accounted for
        rob = env["body"]["because"][0]
        reasons = [{"ptr": "/because/0", "kind": "check",
                    "runtime": rob["runtime"],
                    "reason_digest": sm.sha256_hex(sm.jcs(rob)),
                    "outcome": {"re_execution": "not-applicable",
                                "claimed_verdict": rob["verdict"],
                                "observed_verdict": None,
                                "observed_result": None, "atp_spent": None,
                                "failure_code": None}}]
        return _record_fixture(env, sigs=sigs, issues=issues,
                               reasons=reasons, warnings=len(issues))

    sm.check_equal("a signature failure reported at its own index is valid",
                   _project_objects(*_two_sigs(bad=1, reported=1))[1], [])
    _rS, _fS = _project_objects(*_two_sigs(bad=1, reported=0))
    sm.check_true("a failure at /sigs/1 reported at /sigs/0 is refused twice",
                  lambda: _rS is None
                  and any(x["code"] == "INVALID_SIG_UNREPORTED_AT" for x in _fS)
                  and any(x["code"] == "INVALID_SIG_REPORTED_AT_SOUND"
                          for x in _fS))
    # each direction isolated on its own
    _rS2, _fS2 = _project_objects(*_two_sigs(bad=1, reported=1, drop_issue=True))
    sm.check_true("an unreported signature failure is refused",
                  lambda: _rS2 is None and any(
                      x["code"] == "INVALID_SIG_UNREPORTED_AT" for x in _fS2))
    _rS3, _fS3 = _project_objects(*_two_sigs(bad=None, reported=0))
    sm.check_true("a signature reported failed while sound is refused",
                  lambda: _rS3 is None and any(
                      x["code"] == "INVALID_SIG_REPORTED_AT_SOUND"
                      for x in _fS3))

    # (3) body version and schema are checked with NO check reasons present
    def _reasonless(mutate):
        env = _upstream_env()
        env["body"]["because"] = []      # NO check reasons at all
        mutate(env["body"])
        return _record_fixture(env)

    sm.check_equal("a reason-free record with a sound body is valid",
                   _project_objects(*_reasonless(lambda b: None))[1], [])
    for label, mut, code in [
            ("an unknown body version", lambda b: b.update(warrant="9.9"),
             "UNKNOWN_BODY_VERSION"),
            ("an unknown body member", lambda b: b.update(smuggled=1),
             "BODY_SCHEMA_INVALID"),
            ("an unknown decision", lambda b: b.update(decision="maybe"),
             "BAD_DECISION")]:
        _rB, _fB = _project_objects(*_reasonless(mut))
        sm.check_true("a reason-free record with %s is refused" % label,
                      lambda _rB=_rB, _fB=_fB, code=code:
                      _rB is None and any(x["code"] == code for x in _fB))

    # (4) cmd@v1 is never declared and never reported as executed
    snP, rcP, csP = fixture()
    rcP["core"]["execution_policy"]["runtimes"] = [
        {"runtime": "cmd@v1", "semantics": "container",
         "semantics_digest": sm.sha256_hex(b"c"), "budget_unit": "atp",
         "ceiling": 1}]
    resP, fP = _project_objects(snP, rcP, csP)
    sm.check_true("declaring cmd@v1 in an execution policy is refused",
                  lambda: resP is None and any(
                      x["code"] == "NON_EXECUTABLE_RUNTIME_DECLARED"
                      for x in fP))
    snQ, rcQ, csQ = fixture()
    [x for x in rcQ["core"]["sources"]
     if x["kind"] == "record"][0]["reasons"][0]["outcome"].update(
        re_execution="matched", observed_verdict="pass",
        observed_result="e" * 64, atp_spent=1)
    resQ, fQ = _project_objects(snQ, rcQ, csQ)
    sm.check_true("reporting a cmd@v1 re-execution is refused",
                  lambda: resQ is None and any(
                      x["code"] == "NON_EXECUTABLE_RUNTIME_EXECUTED"
                      for x in fQ))

    # (5) MISSING_BLOB is refutable when the committed check is available
    snR, rcR, csR = ski_fixture()
    srcR = [x for x in rcR["core"]["sources"] if x["kind"] == "record"][0]
    srcR["reasons"][0]["outcome"].update(
        re_execution="unverified", observed_verdict=None,
        observed_result=None, atp_spent=None, failure_code="MISSING_BLOB")
    srcR["issues"] = sorted(srcR["issues"] + [
        {"code": "REASON_UNVERIFIED", "severity": "WARN",
         "at": {"kind": "json-pointer", "value": "/because/0"}}],
        key=lambda x: sm.jcs(x))
    rcR["core"].update(warnings=rcR["core"]["warnings"] + 1)
    resR, fR = _project_objects(snR, rcR, csR)
    sm.check_true("MISSING_BLOB over an available blob is refused",
                  lambda: resR is None and any(
                      x["code"] == "MISSING_BLOB_BUT_PRESENT" for x in fR))

    # ---- round 16: an illegal reason runtime is honest negative evidence
    def _bad_runtime_record(version, runtime, ack=True):
        """A body whose reason runtime the schema forbids, honestly flagged."""
        env = _upstream_env()
        env["body"]["warrant"] = version
        env["body"]["because"] = [{"kind": "check", "runtime": runtime,
                                   "check": sm.sha256_hex(b"policy"),
                                   "verdict": "pass"}]
        issues = ([{"code": "BODY_SCHEMA_INVALID", "severity": "ERR",
                    "at": {"kind": "path",
                           "value": ".warrants/records/%s.json"
                                    % sm.sha256_hex(sm.jcs(env["body"]))}}]
                  if ack else [])
        return _record_fixture(env, issues=issues, errors=len(issues))

    # the two illegalities are DIFFERENT and keep different names: an
    # unknown runtime violates the closed enum (a shape defect), while
    # ski@v1 in a "0.1" body is well-shaped but reserved for that version
    for label, version, runtime, code in [
            ("an unknown runtime in a 0.2 body", "0.2", "evil@v1",
             "BAD_REASON_SHAPE"),
            ("ski@v1 in a 0.1 body", "0.1", "ski@v1",
             "REASON_RUNTIME_NOT_IN_VERSION")]:
        _rA, _fA = _project_objects(*_bad_runtime_record(version, runtime))
        sm.check_equal("%s, acknowledged, is a valid receipt" % label, _fA, [])
        sm.check_true("...and the record is excluded, never a graph node",
                      lambda _rA=_rA: _rA["view_manifest"]["sources_excluded"] == 1
                      and b"urn:wrt:record:" not in _rA["nquads"])
        _rB, _fB = _project_objects(*_bad_runtime_record(version, runtime,
                                                         ack=False))
        sm.check_true("...while unacknowledged it is refused as %s" % code,
                      lambda _fB=_fB, _rB=_rB, code=code: _rB is None
                      and any(x["code"] == code for x in _fB))

    # the legal counterpart still projects
    _rC, _fC = _project_objects(*_bad_runtime_record("0.2", "ski@v1", ack=False))
    sm.check_true("ski@v1 in a 0.2 body is legal at the schema level",
                  lambda: not any(x["code"] == "REASON_RUNTIME_NOT_IN_VERSION"
                                  for x in _fC))

    # an acknowledged invalid body owes no account of its reasons
    _snD, _rcD, _csD = _bad_runtime_record("0.2", "evil@v1")
    _recD = [x for x in _rcD["core"]["sources"] if x["kind"] == "record"][0]
    _recD["reasons"] = [{"ptr": "/because/0", "kind": "check",
                         "runtime": "evil@v1", "reason_digest": "a" * 64,
                         "outcome": {"re_execution": "not-applicable",
                                     "claimed_verdict": "pass",
                                     "observed_verdict": None,
                                     "observed_result": None,
                                     "atp_spent": None, "failure_code": None}}]
    _rD, _fD = _project_objects(_snD, _rcD, _csD)
    sm.check_true("reporting reasons over an invalid body is refused",
                  lambda: _rD is None and any(
                      x["code"] == "REASONS_OVER_INVALID_BODY" for x in _fD))

    # ---- round 15: the exported surface is byte-first, entirely ------
    import sev_projector as _self

    sm.check_true("the object projector is not a public name",
                  lambda: not hasattr(_self, "project"))
    sm.check_equal("the module declares exactly one exported entry point",
                   getattr(_self, "__all__", None), ["project_bytes"])

    _public = sorted(n for n in dir(_self)
                     if not n.startswith("_")
                     and callable(getattr(_self, n))
                     and getattr(getattr(_self, n), "__module__", "")
                     == "sev_projector")
    # fixtures and the harness are test scaffolding, not product surface;
    # what matters is that no PROJECTOR other than the byte one is exported
    _projectors = [n for n in _public if "project" in n]
    sm.check_equal("the only exported projector is the byte-first one",
                   _projectors, ["project_bytes"])

    # and the duplicate-key countervector is run against every exported
    # callable that takes a (snapshot, receipt, cas)-shaped triple
    # a duplicate that COLLAPSES to a valid document: the second copy wins
    # and the object path sees a perfectly ordinary receipt, which is what
    # makes the laundering real rather than merely theoretical
    _dupe_raw = (sm.jcs(receipt)[:-1] + b',"producer":'
                 + sm.jcs(receipt["producer"]) + b'}')
    _dupe_obj = _json.loads(_dupe_raw.decode())
    for _name in _projectors:
        _fn = getattr(_self, _name)
        _res, _find = _fn(sm.jcs(snap), _dupe_raw, cas)
        sm.check_true("exported %s refuses duplicate-key bytes" % _name,
                      lambda _res=_res, _find=_find: _res is None
                      and [x["code"] for x in _find] == ["DUPLICATE_MEMBER"])
    sm.check_true("...and the private object path is the only one that "
                  "would have laundered them",
                  lambda: _project_objects(snap, _dupe_obj, cas)[0] is not None)

    # ---- round 14 countervectors -------------------------------------
    # (1) the PRODUCT is byte-first too: objects cannot launder duplicates
    _s_raw, _r_raw = sm.jcs(snap), sm.jcs(receipt)
    sm.check_equal("project_bytes accepts the fixture bytes",
                   project_bytes(_s_raw, _r_raw, cas)[1], [])
    _dup = _r_raw[:-1] + b',"core":1}'
    _rD, _fD = project_bytes(_s_raw, _dup, cas)
    sm.check_true("a duplicate member cannot be projected",
                  lambda: _rD is None
                  and [x["code"] for x in _fD] == ["DUPLICATE_MEMBER"])
    sm.check_true("...and the object door is private, not public",
                  lambda: not hasattr(sm, "validate_warrant_receipt"))

    # (2) an index-shifting malformed entry must not relabel a failure
    def _shifted_sigs(reported):
        env = _upstream_env()
        env["sigs"] = [7, dict(env["sigs"][0], sig="e" * 128)]
        entries = sm.envelope_signature_entries(env)[0]
        sigs = [{"sig_digest": d, "multiplicity": m, "actor": a, "key": k,
                 "valid": False, "binding": "unverified"}
                for d, m, a, k, _i in entries]
        issues = sorted([
            {"code": "INVALID_SIGNATURE", "severity": "WARN",
             "at": {"kind": "json-pointer", "value": "/sigs/%d" % reported}},
            {"code": "MALFORMED_SIGNATURE", "severity": "ERR",
             "at": {"kind": "json-pointer", "value": "/sigs/0"}},
            {"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
             "at": {"kind": "path",
                    "value": ".warrants/records/%s.json"
                             % sm.sha256_hex(sm.jcs(env["body"]))}}],
            key=lambda x: sm.jcs(x))
        rob = env["body"]["because"][0]
        reasons = [{"ptr": "/because/0", "kind": "check",
                    "runtime": rob["runtime"],
                    "reason_digest": sm.sha256_hex(sm.jcs(rob)),
                    "outcome": {"re_execution": "not-applicable",
                                "claimed_verdict": rob["verdict"],
                                "observed_verdict": None,
                                "observed_result": None, "atp_spent": None,
                                "failure_code": None}}]
        return _record_fixture(env, sigs=sigs, issues=issues,
                               reasons=reasons, warnings=1, errors=2)

    _rI, _fI = _project_objects(*_shifted_sigs(reported=0))
    sm.check_true("a malformed entry cannot shift a failure's index",
                  lambda: _rI is None and any(
                      x["code"] == "INVALID_SIG_UNREPORTED_AT" for x in _fI))
    sm.check_equal("...while the true index /sigs/1 is accepted",
                   _project_objects(*_shifted_sigs(reported=1))[1], [])

    # (3) the body schema is the WHOLE schema
    for label, mut, code in [
            ("a subject without a hash",
             lambda b: b.update(subject={}), "BAD_SUBJECT"),
            ("an empty `under`", lambda b: b.update(under=[]), "BAD_UNDER"),
            ("an actor without an id",
             lambda b: b.update(actor={}), "BAD_ACTOR"),
            ("a non-hex evidence entry",
             lambda b: b.update(evidence=["nope"]), "BAD_EVIDENCE"),
            ("a negative ts", lambda b: b.update(ts=-1), "BAD_TS"),
            ("a reject with no reason",
             lambda b: b.update(decision="reject", because=[]),
             "DECISION_WITHOUT_REASON")]:
        _rY, _fY = _project_objects(*_reasonless(mut))
        sm.check_true("a record with %s is refused" % label,
                      lambda _rY=_rY, _fY=_fY, code=code: _rY is None
                      and any(x["code"] == code for x in _fY))
    # ...and acknowledged, an invalid body is valid negative evidence
    _snZ, _rcZ, _csZ = _reasonless(lambda b: b.update(subject={}))
    _recZ = [x for x in _rcZ["core"]["sources"] if x["kind"] == "record"][0]
    _recZ["issues"] = [{"code": "BODY_SCHEMA_INVALID", "severity": "ERR",
                        "at": {"kind": "path", "value": _recZ["path"]}}]
    _rcZ["core"].update(ok=False, errors=1)
    _rZ, _fZ = _project_objects(_snZ, _rcZ, _csZ)
    sm.check_equal("an acknowledged invalid body is valid evidence", _fZ, [])
    sm.check_true("...and the record is excluded",
                  lambda: _rZ["view_manifest"]["sources_excluded"] == 1)
    _snZ2, _rcZ2, _csZ2 = _reasonless(lambda b: None)
    _recZ2 = [x for x in _rcZ2["core"]["sources"] if x["kind"] == "record"][0]
    _recZ2["issues"] = [{"code": "BODY_SCHEMA_INVALID", "severity": "ERR",
                         "at": {"kind": "path", "value": _recZ2["path"]}}]
    _rcZ2["core"].update(ok=False, errors=1)
    _rZ2, _fZ2 = _project_objects(_snZ2, _rcZ2, _csZ2)
    sm.check_true("claiming an invalid body over a sound one is refused",
                  lambda: _rZ2 is None and any(
                      x["code"] == "SPURIOUS_BODY_SCHEMA_INVALID" for x in _fZ2))

    # (4) cmd@v1 cannot be "unverified" either
    snU4, rcU4, csU4 = fixture()
    srcU4 = [x for x in rcU4["core"]["sources"] if x["kind"] == "record"][0]
    srcU4["reasons"][0]["outcome"].update(
        re_execution="unverified", failure_code="ORACLE_UNAVAILABLE")
    srcU4["issues"] = [{"code": "REASON_UNVERIFIED", "severity": "WARN",
                        "at": {"kind": "json-pointer", "value": "/because/0"}}]
    rcU4["core"].update(warnings=1)
    resU4, fU4 = _project_objects(snU4, rcU4, csU4)
    sm.check_true("cmd@v1 cannot be reported unverified either",
                  lambda: resU4 is None and any(
                      x["code"] == "NON_EXECUTABLE_RUNTIME_EXECUTED"
                      for x in fU4))

    # (5) a wrong sink must not be touched even on the raw refusal path
    class HostileSink(dict):
        def clear(self):
            raise RuntimeError("caller code ran")

        def update(self, *a, **k):
            raise RuntimeError("caller code ran")

    sm.check_equal("a hostile sink is refused before any parsing",
                   [x["code"] for x in sm.verify_receipt_bytes(
                       _s_raw, _dup, cas, view=HostileSink())],
                   ["BAD_VIEW_SINK"])

    # the MVP inherits the core rule: no evidence resolver, no projection
    snNo, rcNo, _csNo = ski_fixture()
    resNo, fNo = _project_objects(snNo, rcNo, None)
    sm.check_true("projecting without an evidence store is refused",
                  lambda: resNo is None
                  and [x["code"] for x in fNo] == ["CAS_REQUIRED"])

    # the shapes artifact validates itself before anything trusts it
    sm.check_equal("the shapes artifact is internally sound", _validate_shapes(), [])

    # qualified relations need an EXACT class, not just a root kind
    U, A, AT, PL, CO = ("Usage", "Association", "Attribution", "Plan",
                        "Collection")

    def _typed(node, cls):
        return "<%s> %s <http://www.w3.org/ns/prov#%s> ." % (node, T, cls)

    for label, graph, expect in [
        ("qualifiedUsage pointing at an Association", _nq(
            _typed("urn:act", "Activity"), _typed("urn:q", A),
            "<urn:act> <http://www.w3.org/ns/prov#qualifiedUsage> <urn:q> ."), True),
        ("qualifiedAssociation pointing at a Usage", _nq(
            _typed("urn:act", "Activity"), _typed("urn:q", U),
            "<urn:act> <http://www.w3.org/ns/prov#qualifiedAssociation> <urn:q> ."),
         True),
        ("qualifiedAttribution pointing at a Usage", _nq(
            _typed("urn:e", "Entity"), _typed("urn:q", U),
            "<urn:e> <http://www.w3.org/ns/prov#qualifiedAttribution> <urn:q> ."),
         True),
        # isolates the hadPlan SUBJECT class: object is a correct Plan
        ("hadPlan from a Usage to a Plan", _nq(
            _typed("urn:u", U), _typed("urn:p", PL),
            "<urn:u> <http://www.w3.org/ns/prov#hadPlan> <urn:p> ."), True),
        ("hadPlan from an Association to a plain Entity", _nq(
            _typed("urn:a", A), _typed("urn:e", "Entity"),
            "<urn:a> <http://www.w3.org/ns/prov#hadPlan> <urn:e> ."), True),
        ("hadMember from a plain Entity", _nq(
            _typed("urn:e", "Entity"), _typed("urn:f", "Entity"),
            "<urn:e> <http://www.w3.org/ns/prov#hadMember> <urn:f> ."), True),
        ("hadPlan done correctly", _nq(
            _typed("urn:a", A), _typed("urn:p", PL),
            "<urn:a> <http://www.w3.org/ns/prov#hadPlan> <urn:p> ."), False),
        ("hadMember from a Collection", _nq(
            _typed("urn:c", CO), _typed("urn:e", "Entity"),
            "<urn:c> <http://www.w3.org/ns/prov#hadMember> <urn:e> ."), False),
        ("qualifiedAttribution done correctly", _nq(
            _typed("urn:e", "Entity"), _typed("urn:q", AT),
            "<urn:e> <http://www.w3.org/ns/prov#qualifiedAttribution> <urn:q> ."),
         False),
    ]:
        sm.check_equal("qualified shape: %s" % label,
                       bool(_prov_violations(graph)), expect)

    # target-profile predicates the MVP does not emit are still validated
    for label, graph, expect in [
        ("wasDerivedFrom activity->activity", _nq(
            "<urn:a> %s <http://www.w3.org/ns/prov#Activity> ." % T,
            "<urn:b> %s <http://www.w3.org/ns/prov#Activity> ." % T,
            "<urn:a> <http://www.w3.org/ns/prov#wasDerivedFrom> <urn:b> ."), True),
        ("wasInvalidatedBy entity->entity", _nq(
            "<urn:a> %s <http://www.w3.org/ns/prov#Entity> ." % T,
            "<urn:b> %s <http://www.w3.org/ns/prov#Entity> ." % T,
            "<urn:a> <http://www.w3.org/ns/prov#wasInvalidatedBy> <urn:b> ."), True),
        ("qualifiedUsage with an entity subject", _nq(
            "<urn:a> %s <http://www.w3.org/ns/prov#Entity> ." % T,
            "<urn:u> %s <http://www.w3.org/ns/prov#Usage> ." % T,
            "<urn:a> <http://www.w3.org/ns/prov#qualifiedUsage> <urn:u> ."), True),
        ("qualifiedUsage done correctly", _nq(
            "<urn:act> %s <http://www.w3.org/ns/prov#Activity> ." % T,
            "<urn:u> %s <http://www.w3.org/ns/prov#Usage> ." % T,
            "<urn:act> <http://www.w3.org/ns/prov#qualifiedUsage> <urn:u> ."), False),
        ("hadPlan from an association to a plan", _nq(
            "<urn:assoc> %s <http://www.w3.org/ns/prov#Association> ." % T,
            "<urn:plan> %s <http://www.w3.org/ns/prov#Plan> ." % T,
            "<urn:assoc> <http://www.w3.org/ns/prov#hadPlan> <urn:plan> ."), False),
    ]:
        found = _prov_violations(graph)
        sm.check_equal("target predicate: %s" % label, bool(found), expect)

    # the MVP subset is declared in the shapes file, and it must be honest
    sm.check_true("declared MVP predicates are a subset of the target set",
                  lambda: set(SHAPES["mvp_predicates"]) <= set(PROV_SIGNATURES))
    _emitted_preds = {terms[1][0] for terms in _parse_nquads(result["nquads"])
                      if terms[1][0].startswith("http://www.w3.org/ns/prov#")}
    sm.check_equal("what the projector actually emits matches that declaration",
                   sorted(_emitted_preds - set(SHAPES["mvp_predicates"])), [])
    # ...and the other direction, which was missing: declaring a predicate no
    # fixture emits is over-declaration, the mirror of emitting an undeclared
    # one. The union is taken over fixtures chosen to reach every branch that
    # emits a PROV predicate, so "declared" cannot quietly outgrow "emitted".
    # (the both-directions half of this check lives further down, where the
    # bound-signature fixture exists: `prov:wasAttributedTo` is declared and
    # emitted only on the promotion path, so a union taken here would be
    # missing it and would report an over-declaration that is not one)

    # PROV-O's own normative wasAssociatedWith example: the agent is typed
    # Person, Agent AND Entity. A guard that rejects every multi-kind node
    # rejects normative PROV.
    _derek = _nq(
        "<urn:derek> %s <http://www.w3.org/ns/prov#Person> ." % T,
        "<urn:derek> %s <http://www.w3.org/ns/prov#Entity> ." % T,
        "<urn:act> %s <http://www.w3.org/ns/prov#Activity> ." % T,
        "<urn:act> <http://www.w3.org/ns/prov#wasAssociatedWith> <urn:derek> .")
    sm.check_equal("an Agent that is also an Entity is legal PROV",
                   _prov_violations(_derek), set())
    _derek_entity_pos = _nq(
        "<urn:derek> %s <http://www.w3.org/ns/prov#Person> ." % T,
        "<urn:derek> %s <http://www.w3.org/ns/prov#Entity> ." % T,
        "<urn:sigma:run:a> %s <https://s0fractal.dev/ns/sigma#CheckRun> ." % T,
        "<urn:sigma:run:a> <http://www.w3.org/ns/prov#used> <urn:derek> .")
    sm.check_equal("...and satisfies an Entity position too",
                   _prov_violations(_derek_entity_pos), set())

    # every Activity subclass the TARGET profile declares passes in its own
    # position — the previous hand-kept list produced false positives here
    for cls in ("https://github.com/s0fractal/oaip/ns#Execution",
                "https://github.com/s0fractal/oaip/ns#Validation",
                "https://s0fractal.dev/ns/bos#Trajectory",
                "https://s0fractal.dev/ns/wrt#Adjudication"):
        graph = _nq("<urn:act> %s <%s> ." % (T, cls),
                    "<urn:act> <http://www.w3.org/ns/prov#used> <urn:ent> .")
        sm.check_equal("target Activity subclass %s is accepted"
                       % cls.rsplit("#", 1)[-1],
                       _prov_violations(graph), set())

    # ...and a transitive subclass really resolves through its parent
    sm.check_equal("wrt:Adjudication closes to activity via wrt:Filing",
                   _kind_of_class("https://s0fractal.dev/ns/wrt#Adjudication"),
                   "activity")

    # the MVP guard vs the profile guard: everything this projector emits
    # must be a class the registry knows
    _emitted_types = {terms[2][0] for terms in
                      _parse_nquads(result["nquads"])
                      if terms[1][0] == RDF_TYPE_IRI and terms[2][1]}
    sm.check_equal("every class the MVP emits is in the profile registry",
                   sorted(t for t in _emitted_types
                          if _kind_of_class(t) is None), [])

    for label, res_ in [("upstream not-applicable", resUP),
                        ("ski matched", result),
                        ("ski unverified", resM)]:
        sm.check_equal("entailment guard (%s): every PROV domain AND range "
                       "position is correctly typed" % label,
                       _prov_violations(res_["nquads"]), set())

    # matched and mismatched DO produce a run, with its execution inputs
    sm.check_true("a matched ski@v1 outcome produces a CheckRun with prov:used",
                  lambda: b"sigma#CheckRun" in result["nquads"]
                  and b"prov#used" in result["nquads"])
    snMM, rcMM, csMM = ski_fixture()
    srcMM = [x for x in rcMM["core"]["sources"] if x["kind"] == "record"][0]
    srcMM["reasons"][0]["outcome"].update(re_execution="mismatched",
                                          observed_verdict="fail")
    srcMM["issues"] = sorted(srcMM["issues"] + [
        {"code": "REASON_MISMATCH", "severity": "WARN",
         "at": {"kind": "json-pointer", "value": "/because/0"}}],
        key=lambda x: sm.jcs(x))
    rcMM["core"].update(warnings=rcMM["core"]["warnings"] + 1)
    resMM, fMM = _project_objects(snMM, rcMM, csMM)
    sm.check_true("a mismatched outcome also produces a CheckRun",
                  lambda: fMM == [] and b"sigma#CheckRun" in resMM["nquads"])

    # switching not-applicable -> matched must change topology, not just a
    # literal: new node type, new coverage category, new loss code
    sm.check_true("not-applicable vs matched differ in topology, coverage and "
                  "losses",
                  lambda: ("sigma#CheckRun" not in nqUP)
                  and (b"sigma#CheckRun" in result["nquads"])
                  and ("check-run" not in
                       resUP["view_manifest"]["coverage"]["emitted"])
                  and ("check-run" in
                       result["view_manifest"]["coverage"]["emitted"]))

    # provenance of the vendored fixture is mechanically checked: the bytes,
    # the constant and the digest recorded in the README must agree. No
    # behavioural vector can do this — the model recomputes everything from
    # whatever bytes it is given, so edited bytes stay self-consistent.
    with open(UPSTREAM_ACCEPT, "rb") as _fh:
        _vendored = _fh.read()
    sm.check_equal("vendored upstream bytes match the pinned digest",
                   sm.sha256_hex(_vendored), UPSTREAM_DIGEST)
    with open(os.path.join(os.path.dirname(UPSTREAM_ACCEPT), "README.md")) as _fh:
        sm.check_true("...and the digest recorded in its provenance note",
                      lambda: UPSTREAM_DIGEST in _fh.read())

    # re-gate: a receipt may not contradict its own NEGATIVE claims. This
    # needs no cryptography — the contradiction is entirely inside the
    # producer-asserted core.
    def _sig_state(fn):
        sn, rc, cs = ski_fixture()
        src = [x for x in rc["core"]["sources"] if x["kind"] == "record"][0]
        fn(src, rc["core"])
        return _project_objects(sn, rc, cs)

    resA1, fA1 = _sig_state(lambda src, core: (
        src["signatures"][0].update(valid=False),
        src.__setitem__("issues", [{"code": "INVALID_SIGNATURE",
                                    "severity": "WARN",
                                    "at": {"kind": "json-pointer",
                                           "value": "/sigs/0"}}]),
        core.update(warnings=1)))
    sm.check_true("only actor signature reported invalid, WARN only -> refusal",
                  lambda: resA1 is None and any(
                      x["code"] == "NO_VALID_ACTOR_SIGNATURE_UNREPORTED"
                      for x in fA1))

    resA2, fA2 = _sig_state(lambda src, core: (
        src["signatures"][0].update(valid=False),
        src.__setitem__("issues", sorted([
            {"code": "INVALID_SIGNATURE", "severity": "WARN",
             "at": {"kind": "json-pointer", "value": "/sigs/0"}},
            {"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
             "at": {"kind": "path", "value": src["path"]}}],
            key=lambda x: sm.jcs(x))),
        core.update(ok=False, errors=1, warnings=1)))
    sm.check_equal("...reported as ERR, it is accepted", fA2, [])
    sm.check_true("...and the record is excluded",
                  lambda: resA2["view_manifest"]["sources_excluded"] == 1)

    resA3, fA3 = _sig_state(lambda src, core: (
        src["signatures"][0].update(actor="someone@else"),))
    sm.check_true("a valid signature by another actor is not the actor's",
                  lambda: resA3 is None and any(
                      x["code"] in ("SIGNATURE_FIELD_MISMATCH",
                                    "NO_VALID_ACTOR_SIGNATURE_UNREPORTED")
                      for x in fA3))

    # zero signatures at all: the envelope bijection catches the omission,
    # and the aggregate rule catches the state
    resA4, fA4 = _sig_state(lambda src, core: (src.__setitem__("signatures", []),))
    sm.check_true("zero reported signatures -> refusal",
                  lambda: resA4 is None and any(
                      x["code"] in ("SIGNATURE_MISSING",
                                    "NO_VALID_ACTOR_SIGNATURE_UNREPORTED")
                      for x in fA4))

    # the pinned upstream record: a signature the owning protocol vouches for
    snU2, rcU2, csU2 = fixture()
    resU2, fU2 = _project_objects(snU2, rcU2, csU2)
    sm.check_equal("the vendored upstream record projects cleanly", fU2, [])
    sm.check_true("...as a genuinely signed positive path",
                  lambda: resU2["view_manifest"]["sources_excluded"] == 0
                  and b"urn:wrt:record:" in resU2["nquads"])

    # The promotion rule, exercised in BOTH directions on the same fixture,
    # because a rule only ever tested on its refusing side is half a rule.
    # `bound` is the only state that licenses an agent; every weaker state
    # must fall back to the claim.
    # `valid=False, binding="bound"` is deliberately absent: the receipt core
    # refuses it outright (BINDING_WITHOUT_VALIDITY), so it is not a state a
    # projector can ever see. Asserted just below rather than assumed.
    for binding, valid, promoted in (("bound", True, True),
                                     ("unbound", True, False),
                                     ("unbound", False, False),
                                     ("unverified", True, False)):
        # a binding is reportable only under a pinned trust config, so every
        # non-`unverified` row is a settlement receipt (round 18 P1)
        snP, rcP, csP = fixture(settlement=binding != "unverified")
        srcP = [s for s in rcP["core"]["sources"] if s.get("signatures")][0]
        for sg in srcP["signatures"]:
            sg["valid"], sg["binding"] = valid, binding
        if valid is False:
            # a receipt reporting every actor signature invalid must say so
            # in its own issues, or the model refuses it
            srcP["issues"] = sorted(srcP["issues"] + [
                {"code": "INVALID_SIGNATURE", "severity": "WARN",
                 "at": {"kind": "json-pointer", "value": "/sigs/0"}},
                {"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
                 "at": {"kind": "path", "value": srcP["path"]}}],
                key=lambda x: sm.jcs(x))
            rcP["core"]["errors"] += 1
            rcP["core"]["warnings"] += 1
            rcP["core"]["ok"] = False
        resP, fP = _project_objects(snP, rcP, csP)
        label = "valid=%s binding=%s" % (valid, binding)
        if resP is None:
            sm.check_true("promotion vector projects: %s" % label, lambda: False)
            continue
        quadsP = resP["nquads"]
        sm.check_equal("agent promoted only when valid AND bound (%s)" % label,
                       b"prov#wasAttributedTo" in quadsP, promoted)
        sm.check_equal("...and the agent node is a typed prov:Agent (%s)" % label,
                       b"<http://www.w3.org/ns/prov#Agent>" in quadsP, promoted)
        sm.check_equal("...and the fallback claim is its exact complement (%s)"
                       % label, b"wrt#claimedSigner" in quadsP,
                       not promoted and b"wrt#Signature" in quadsP)

    # The state the loop cannot cover, because the contract forbids it. The
    # projector still tests `valid is True` alongside `binding == "bound"`:
    # redundant TODAY, and kept so the promotion rule reads as the profile
    # writes it instead of leaning on an invariant in another module. No
    # vector can isolate that clause — stated here, not counted.
    snQ, rcQ, csQ = fixture()
    srcQ = [s for s in rcQ["core"]["sources"] if s.get("signatures")][0]
    srcQ["signatures"][0].update(valid=False, binding="bound")
    _resQ, fQ = _project_objects(snQ, rcQ, csQ)
    sm.check_true("a bound-but-invalid signature is unrepresentable",
                  lambda: _resQ is None and any(
                      x["code"] == "BINDING_WITHOUT_VALIDITY" for x in fQ))

    # A binding needs a trust basis. Warrant makes the key→actor association
    # from key state alone: with no pinned trust config it reports
    # `unverified` for everything, and with one it reports `bound`/`unbound`.
    # The core accepted `bound` at base grade with `trust_config_digest:
    # null` — a state no verifier can produce — and the projector minted a
    # `prov:Agent` from it (round 18 P1). This amends a FROZEN contract.
    for settle, binding, expect in ((False, "bound", "BINDING_WITHOUT_TRUST"),
                                    (False, "unbound", "BINDING_WITHOUT_TRUST"),
                                    (True, "unverified", "UNVERIFIED_UNDER_TRUST"),
                                    (False, "unverified", None),
                                    (True, "bound", None),
                                    (True, "unbound", None)):
        snT, rcT, csT = fixture(settlement=settle)
        for sg in [s for s in rcT["core"]["sources"]
                   if s.get("signatures")][0]["signatures"]:
            sg["binding"] = binding
        resT, fT = _project_objects(snT, rcT, csT)
        label = "%s/%s" % ("settlement" if settle else "base", binding)
        if expect is None:
            sm.check_equal("a reachable binding state projects (%s)" % label,
                           fT, [])
        else:
            sm.check_true("an unreachable binding state is refused (%s)" % label,
                          lambda fT=fT, expect=expect, resT=resT:
                          resT is None and any(x["code"] == expect for x in fT))

    # The matrix is scoped to `valid: true`, as the round specified, and the
    # boundary is asserted rather than left implicit: an INVALID signature
    # reported `unbound` at base grade is still accepted. Whether it should
    # be is an open question — Warrant without key state reports `unverified`
    # for everything, so `unbound` may be unreachable there too regardless of
    # validity — and it is forwarded rather than decided here, because
    # widening a frozen invariant beyond what was reviewed is not mine to do.
    snB, rcB, csB = fixture()
    srcB = [s for s in rcB["core"]["sources"] if s.get("signatures")][0]
    for sg in srcB["signatures"]:
        sg["valid"], sg["binding"] = False, "unbound"
    srcB["issues"] = sorted(srcB["issues"] + [
        {"code": "INVALID_SIGNATURE", "severity": "WARN",
         "at": {"kind": "json-pointer", "value": "/sigs/0"}},
        {"code": "NO_VALID_ACTOR_SIGNATURE", "severity": "ERR",
         "at": {"kind": "path", "value": srcB["path"]}}],
        key=lambda x: sm.jcs(x))
    rcB["core"]["errors"] += 1
    rcB["core"]["warnings"] += 1
    rcB["core"]["ok"] = False
    _resB2, fB2 = _project_objects(snB, rcB, csB)
    sm.check_equal("the matrix is scoped to valid signatures, and says so",
                   [x["code"] for x in fB2
                    if x["code"] in ("BINDING_WITHOUT_TRUST",
                                     "UNVERIFIED_UNDER_TRUST")], [])

    # The MVP declaration must be exact in BOTH directions. The existing
    # check only caught emitting something undeclared; adding
    # `prov:wasAttributedTo` — which no default fixture emits, since nothing
    # is bound there — would have over-declared silently, the mirror image of
    # the defect this repository keeps finding. The union below is taken over
    # fixtures chosen to exercise every branch that emits a PROV predicate.
    snR, rcR, csR = fixture(settlement=True)
    for _sg in [s for s in rcR["core"]["sources"] if s.get("signatures")][0]["signatures"]:
        _sg["binding"] = "bound"
    _bound_res, _ = _project_objects(snR, rcR, csR)
    _mvp_seen = set()
    for _r in (result, res_body, _bound_res):
        _mvp_seen |= {ln.split(" ")[1][1:-1] for ln in _r["nquads"].decode().splitlines()
                      if ln.split(" ")[1].startswith("<http://www.w3.org/ns/prov#")}
    sm.check_equal("every declared MVP predicate is actually emitted somewhere",
                   sorted(set(SHAPES["mvp_predicates"]) - _mvp_seen), [])

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
