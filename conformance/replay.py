#!/usr/bin/env python3
"""Replay language-neutral conformance fixtures against the model.

The fixtures are DATA (base64 bytes + expected finding codes), not Python —
a second implementation consumes the same JSON without reading the model
(round-6 R3: translation is not independence). Exit status is the verdict.
"""

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "model"))
import snapshot_model as sm  # noqa: E402


def main():
    with open(os.path.join(HERE, "parse-strict.vectors.json")) as fh:
        fixtures = json.load(fh)
    if not fixtures.get("cases"):
        print("FAIL  empty fixture set — ALL PASS over zero cases is vacuous")
        return 1
    failed = 0
    for case in fixtures["cases"]:
        raw = base64.b64decode(case["raw_b64"])
        _obj, findings = sm.parse_strict(raw)
        got = [x["code"] for x in findings]
        ok = got == case["expected_codes"]
        print("%s  %s%s" % ("PASS" if ok else "FAIL", case["name"],
                            "" if ok else "  (got %s, want %s)"
                            % (got, case["expected_codes"])))
        failed += 0 if ok else 1
    # The actor IRI contract, replayed from data for the same reason: three
    # rounds running, a defect was closed in Python while the normative
    # document still described the superseded rule — and the document is
    # what a second implementation reads.
    import sev_projector as sp
    with open(os.path.join(HERE, "actor-iri.vectors.json")) as fh:
        actor_fx = json.load(fh)
    if not actor_fx.get("cases"):
        print("FAIL  empty actor-iri fixture set — vacuous")
        return 1
    for case in actor_fx["cases"]:
        actor = base64.b64decode(case["actor_b64"]).decode("utf-8")
        got = sp.iri_actor(actor)
        ok = got == case["iri"]
        print("%s  actor-iri: %s%s" % ("PASS" if ok else "FAIL", case["name"],
                                       "" if ok else "  (got %s, want %s)"
                                       % (got, case["iri"])))
        failed += 0 if ok else 1
    # The two matrices the profile used to restate in six places. They are
    # data because prose drifted from the code in three consecutive rounds,
    # and the document is what a second implementation reads.
    #
    # Each case ships the exact snapshot bytes, receipt bytes and CAS, and is
    # PROJECTED here. The first version stored only parameters and compared
    # the data with itself; a mutation proved it bound nothing — breaking the
    # projector left the replay green. A fixture that never runs the
    # implementation is a fixture that tests a JSON file.
    import sev_projector as sp

    def _cas(case):
        return {k: base64.b64decode(v) for k, v in case["cas"].items()}

    with open(os.path.join(HERE, "judgement-identity.vectors.json")) as fh:
        ident_fx = json.load(fh)
    with open(os.path.join(HERE, "signature-promotion.vectors.json")) as fh:
        promo_fx = json.load(fh)
    for fx, name in ((ident_fx, "judgement-identity"),
                     (promo_fx, "signature-promotion")):
        if not fx.get("cases"):
            print("FAIL  empty %s fixture set — vacuous" % name)
            return 1

    for case in ident_fx["cases"]:
        res, findings = sp.project_bytes(
            base64.b64decode(case["snapshot_b64"]),
            base64.b64decode(case["receipt_b64"]), _cas(case))
        exp = case["expect"]
        if res is None:
            ok, why = False, "refused: %s" % [x["code"] for x in findings]
        else:
            quads = res["nquads"].decode()
            subj = sorted({ln.split(" ")[0][1:-1] for ln in quads.splitlines()
                           if ln.split(" ")[0][1:-1].startswith(
                               ("urn:sev:receipt:", "urn:sigma:run:",
                                "urn:sev:assess:"))})
            graphs = sorted({ln.rsplit("<", 1)[1].rstrip("> .")
                             for ln in quads.splitlines()
                             if "urn:sev:g:verify:" in ln})
            rec = res["view_manifest"]["receipts"][0]
            ok = (subj == exp["judgement_scoped_subjects"]
                  and graphs == exp["verification_graphs"]
                  and rec["judgement_digest"] == exp["judgement_digest"]
                  and rec["receipt_core_digest"] == exp["receipt_core_digest"]
                  and rec["contract"] == exp["manifest_contract"])
            why = "" if ok else "identity mismatch"
        print("%s  judgement-identity: %s%s"
              % ("PASS" if ok else "FAIL", case["name"],
                 "" if ok else "  (%s)" % why))
        failed += 0 if ok else 1
    # Completeness, derived from the RECEIPT BYTES rather than from the
    # metadata beside them. Guarding only "the rows present are consistent"
    # let a corpus be gutted and stay green: deleting every `@v1` identity
    # case made "every contract yields a distinct judgement" pass over one
    # contract (round 23 P1). A coordinate a case merely *claims* is not
    # evidence; the coordinate it *is* comes from what it ships.
    def _coord_identity(case):
        receipt = json.loads(base64.b64decode(case["receipt_b64"]).decode("utf-8"))
        res, _f = sp.project_bytes(base64.b64decode(case["snapshot_b64"]),
                                   base64.b64decode(case["receipt_b64"]),
                                   _cas(case))
        runs = res is not None and "check-run" in res["view_manifest"]["coverage"]["emitted"]
        return (receipt["receipt"], "check-run" if runs else "no-run")

    def _coord_promotion(case):
        receipt = json.loads(base64.b64decode(case["receipt_b64"]).decode("utf-8"))
        core = receipt["core"]
        sig = [s for s in core["sources"] if s.get("signatures")][0]["signatures"][0]
        return (receipt["receipt"], core["grade"], sig["valid"], sig["binding"])

    TAGS = ("warrant.verification-receipt@v0", "warrant.verification-receipt@v1")
    want_identity = {(t, r) for t in TAGS for r in ("no-run", "check-run")}
    want_promotion = {(t, g, v, b) for t in TAGS
                      for g in ("base", "settlement")
                      for v in (True, False)
                      for b in ("bound", "unbound", "unverified")}
    for fx, coord, want, name in ((ident_fx, _coord_identity, want_identity,
                                   "judgement-identity"),
                                  (promo_fx, _coord_promotion, want_promotion,
                                   "signature-promotion")):
        got = [coord(c) for c in fx["cases"]]
        # the human-readable fields beside each case are decoration, and
        # decoration that contradicts the bytes misleads whoever reads the
        # file instead of running it
        for case, c in zip(fx["cases"], got):
            claimed = (case.get("contract"), case.get("grade"),
                       (case.get("signature") or {}).get("valid"),
                       (case.get("signature") or {}).get("binding"))
            claimed = tuple(x for x in claimed if x is not None)
            derived = tuple(x for x in c if not isinstance(x, str)
                            or x not in ("no-run", "check-run"))
            if len(claimed) == len(derived) and claimed != derived:
                print("FAIL  %s: metadata contradicts its own bytes (%s)"
                      % (name, case.get("name")))
                failed += 1
        dupes = sorted({c for c in got if got.count(c) > 1})
        missing = sorted(want - set(got))
        extra = sorted(set(got) - want)
        ok = not dupes and not missing and not extra
        print("%s  %s: the corpus is the exact matrix (%d cells)"
              % ("PASS" if ok else "FAIL", name, len(want)))
        if not ok:
            print("      missing=%s extra=%s duplicated=%s"
                  % (missing[:4], extra[:4], dupes[:4]))
        failed += 0 if ok else 1

    projected_rows = 0
    for case in promo_fx["cases"]:
        res, findings = sp.project_bytes(
            base64.b64decode(case["snapshot_b64"]),
            base64.b64decode(case["receipt_b64"]), _cas(case))
        exp = case["expect"]
        if exp["receipt_refused"] is not None:
            ok = (res is None
                  and sorted({x["code"] for x in findings})
                  == exp["receipt_refused"])
        elif res is None:
            ok = False
        else:
            quads = res["nquads"].decode()
            codes = [e["code"] for e in res["loss_manifest"]["entries"]
                     if e["code"] in ("L-UNGROUNDED", "L-UNBOUND")]
            ok = (("prov#wasAttributedTo" in quads) == exp["attribution"]
                  and ("urn:wrt:actor:" in quads) == exp["actor_iri_minted"]
                  and ("wrt#claimedSigner" in quads) == exp["claimed_signer"]
                  and codes == exp["loss_codes"]
                  and (res["view_manifest"]["sources_excluded"] == 0)
                  == exp["record_projected"])
            if exp["record_projected"]:
                projected_rows += 1
        print("%s  signature-promotion: %s"
              % ("PASS" if ok else "FAIL", case["name"]))
        failed += 0 if ok else 1
    # `projected_rows >= 6` was a floor, and a floor is not a matrix — it
    # passed with a cell deleted. The exact-set check above replaces it; this
    # only keeps the harness from silently running a corpus in which nothing
    # projects at all.
    if projected_rows == 0:
        print("FAIL  signature-promotion: no row projected — vacuous")
        return 1

    if failed:
        print("FAILED: %d fixture(s)" % failed)
        return 1
    print("ALL PASS (%d parse-strict + %d actor-iri + %d judgement-identity "
          "+ %d signature-promotion fixtures)"
          % (len(fixtures["cases"]), len(actor_fx["cases"]),
             len(ident_fx["cases"]), len(promo_fx["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
