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
    distinct = {c["expect"]["judgement_digest"] for c in ident_fx["cases"]}
    ok = len(distinct) == len(ident_fx["cases"])
    print("%s  judgement-identity: every contract yields a distinct judgement"
          % ("PASS" if ok else "FAIL"))
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
    if projected_rows < 6:
        print("FAIL  signature-promotion: too few projected rows to be a matrix")
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
