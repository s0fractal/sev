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


class FixtureRefused(Exception):
    """The fixture file is not readable under its own contract."""


def load_fixtures(name, family, case_keys, root_keys=()):
    """THE strict reader for every `*.vectors.json`.

    This repository refuses a receipt for a duplicate member, a BOM, trailing
    bytes or a lone surrogate — and then read its own conformance corpus with
    `json.load`, which silently keeps the last duplicate, and
    `base64.b64decode`, which silently ignores characters outside the
    alphabet. Three independent mutations replayed as ALL PASS: a wrong
    family tag, a duplicated `vectors` member, and `!!!!` prefixed to a
    payload (round 24 P1).

    A corpus that only one implementation can read the way its author meant
    is not language-neutral evidence, and the fix is not a new parser: it is
    the strict one this repository already owns.
    """
    path = os.path.join(HERE, name)
    with open(path, "rb") as fh:
        raw = fh.read()
    obj, findings = sm.parse_strict(raw)
    fatal = [x["code"] for x in findings if x["code"] != "NOT_CANONICAL"]
    if fatal:
        raise FixtureRefused("%s: %s" % (name, fatal))
    if not isinstance(obj, dict):
        raise FixtureRefused("%s: not a JSON object" % name)
    if obj.get("vectors") != family:
        raise FixtureRefused("%s: family tag is %r, expected %r"
                             % (name, obj.get("vectors"), family))
    allowed = set(root_keys) | {"vectors", "cases", "note"}
    extra = sorted(set(obj) - allowed)
    if extra:
        raise FixtureRefused("%s: unexpected root members %s" % (name, extra))
    if not isinstance(obj.get("cases"), list) or not obj["cases"]:
        raise FixtureRefused("%s: empty or malformed case list" % name)
    for i, case in enumerate(obj["cases"]):
        if not isinstance(case, dict):
            raise FixtureRefused("%s: case %d is not an object" % (name, i))
        missing = sorted(set(case_keys) - set(case))
        if missing:
            raise FixtureRefused("%s: case %d is missing %s"
                                 % (name, i, missing))
    return obj


def b64(value, where):
    """Canonical, padded, standard-alphabet base64 — or a refusal.

    `validate=True` rejects the alphabet, and re-encoding catches the rest:
    non-canonical padding and trailing bits that decode to the same bytes but
    are not what a second implementation would emit.
    """
    if not isinstance(value, str):
        raise FixtureRefused("%s: payload is not a string" % where)
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise FixtureRefused("%s: %s" % (where, exc))
    if base64.b64encode(raw).decode("ascii") != value:
        raise FixtureRefused("%s: base64 is not canonical" % where)
    return raw


def loader_selftest():
    """Permanent negative controls for the loader itself.

    A strict reader that is never shown a bad file is indistinguishable from
    a permissive one. Each case below is a mutation that replayed as ALL PASS
    before round 24, written against a temporary copy of a real fixture so
    the control cannot drift away from the format it guards.
    """
    import tempfile
    good = os.path.join(HERE, "actor-iri.vectors.json")
    with open(good, "rb") as fh:
        raw = fh.read()
    family = "sev.actor-iri@v0"
    keys = ("name", "actor_b64", "iri")
    mutations = [
        ("a wrong family tag",
         raw.replace(b'"sev.actor-iri@v0"', b'"sev.signature-promotion@v0"', 1)),
        ("a duplicated family member",
         raw.replace(b'"vectors": "sev.actor-iri@v0",',
                     b'"vectors": "hostile", "vectors": "sev.actor-iri@v0",', 1)),
        ("an unexpected root member",
         raw.replace(b'"vectors":', b'"surprise": 1,\n  "vectors":', 1)),
        ("an empty case list", raw.replace(b'"cases": [', b'"cases": [], "unused": [', 1)),
        ("a BOM", b"\xef\xbb\xbf" + raw),
        ("trailing bytes", raw.rstrip() + b" x"),
    ]
    ok = True
    for label, blob in mutations:
        tmp = tempfile.mkdtemp()
        name = "probe.vectors.json"
        with open(os.path.join(tmp, name), "wb") as fh:
            fh.write(blob)
        saved, globals()["HERE"] = HERE, tmp
        try:
            load_fixtures(name, family, keys,
                          root_keys=("rule", "minted_only_when",
                                     "helper_totality"))
            print("FAIL  loader accepts %s" % label)
            ok = False
        except FixtureRefused:
            print("PASS  loader refuses %s" % label)
        finally:
            globals()["HERE"] = saved
    for label, payload in (("a non-alphabet character", "!!!!QUJD"),
                           ("non-canonical padding", "QUJD===="),
                           ("a non-string payload", 7)):
        try:
            b64(payload, "selftest")
            print("FAIL  base64 accepts %s" % label)
            ok = False
        except FixtureRefused:
            print("PASS  base64 refuses %s" % label)
    return ok


def main():
    if not loader_selftest():
        print("FAILED: the fixture loader is not strict")
        return 1
    try:
        fixtures = load_fixtures("parse-strict.vectors.json",
                                 "sev.parse-strict@v0",
                                 ("name", "raw_b64", "expected_codes"))
    except FixtureRefused as exc:
        print("FAIL  fixture corpus refused: %s" % exc)
        return 1
    failed = 0
    for case in fixtures["cases"]:
        raw = b64(case["raw_b64"], "parse-strict/%s" % case["name"])
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
    actor_fx = load_fixtures("actor-iri.vectors.json", "sev.actor-iri@v0",
                             ("name", "actor_b64", "iri"),
                             root_keys=("rule", "minted_only_when",
                                        "helper_totality"))
    for case in actor_fx["cases"]:
        actor = b64(case["actor_b64"], "actor-iri/%s" % case["name"]).decode("utf-8")
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
        return {k: b64(v, "%s/cas/%s" % (case["name"], k))
                for k, v in case["cas"].items()}

    ident_fx = load_fixtures("judgement-identity.vectors.json",
                             "sev.judgement-identity@v0",
                             ("name", "contract", "snapshot_b64",
                              "receipt_b64", "cas", "expect"),
                             root_keys=("rule",))
    promo_fx = load_fixtures("signature-promotion.vectors.json",
                             "sev.signature-promotion@v0",
                             ("name", "contract", "grade",
                              "trust_config_digest", "signature",
                              "snapshot_b64", "receipt_b64", "cas", "expect"),
                             root_keys=("rule", "loss_codes"))

    for case in ident_fx["cases"]:
        res, findings = sp.project_bytes(
            b64(case["snapshot_b64"], case["name"]),
            b64(case["receipt_b64"], case["name"]), _cas(case))
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
        receipt, _rf = sm.parse_strict(b64(case["receipt_b64"], case["name"]))
        res, _f = sp.project_bytes(b64(case["snapshot_b64"], case["name"]),
                                   b64(case["receipt_b64"], case["name"]),
                                   _cas(case))
        runs = res is not None and "check-run" in res["view_manifest"]["coverage"]["emitted"]
        return (receipt["receipt"], "check-run" if runs else "no-run")

    def _coord_promotion(case):
        receipt, _rf = sm.parse_strict(b64(case["receipt_b64"], case["name"]))
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
        # Required and compared EXACTLY. Filtering `None` out and comparing
        # only when the lengths matched made the fields fail-open: a lying
        # field was caught, while DELETING the same field — strictly cheaper
        # — was not (round 24 P2). The loader already refuses a case that
        # omits them; this checks the ones present are true.
        for case, c in zip(fx["cases"], got):
            if name == "signature-promotion":
                claimed = (case["contract"], case["grade"],
                           case["signature"]["valid"],
                           case["signature"]["binding"])
            else:
                claimed = (case["contract"],)
                c = c[:1]
            if claimed != c:
                print("FAIL  %s: metadata contradicts its own bytes (%s: "
                      "says %s, bytes say %s)"
                      % (name, case["name"], claimed, c))
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
            b64(case["snapshot_b64"], case["name"]),
            b64(case["receipt_b64"], case["name"]), _cas(case))
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
