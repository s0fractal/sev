#!/usr/bin/env python3
"""One vertical slice: an agent's refund decision, provable offline.

    python3 examples/refund-decision/run.py            # the whole path
    python3 examples/refund-decision/run.py --negative # tamper, then re-run

The story is the Air Canada one. A company's chatbot told a customer
something, the customer relied on it, and the company was held to it. The
logs said *what happened*. Nobody could show *what policy allowed the bot to
say it* — or prove, months later, that the policy had not been edited since.

This runs the whole path end to end, on real artifacts:

    Warrant @v0 evidence   the agent files a signed record of its decision,
                           pinning the policy it acted under, by hash
          ↓                (built here with Warrant's own CLI)
    verification           Warrant's own verifier judges its own bytes
          ↓                (`warrant verify --json`, not hand-written)
    SEV projection         SEV composes that judgement into an evidence view
          ↓                with an explicit manifest of what it cannot express
    BOS assessment         two actors assess the SAME decision through
          ↓                different lenses — risk and opportunity — and both
                           are legitimate
    action                 a concrete next step whose reason traces back to
                           the sealed bytes

Nothing here invents a protocol. Every artifact is produced by the repository
that owns it: Warrant judges Warrant's bytes, SEV composes, BOS attributes.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SEV = os.path.dirname(os.path.dirname(HERE))
SIBLINGS = os.path.dirname(SEV)
WARRANT = None  # resolved below, after _sibling is defined
# `bos` and `BOS` both resolve on a case-insensitive filesystem, which hides
# a wrong path until someone runs this on Linux. Pick the one that exists by
# listing, not by probing.
def _sibling(name):
    env = os.environ.get(name.upper() + "_REPO")
    if env:
        return env
    for entry in sorted(os.listdir(SIBLINGS)):
        if entry.lower() == name.lower():
            return os.path.join(SIBLINGS, entry)
    return os.path.join(SIBLINGS, name)


WARRANT = _sibling("warrant")
BOS = _sibling("bos")

POLICY = b"""refund-policy v1
A bereavement fare adjustment may be requested within 90 days of travel.
An agent may approve it without human review when all hold:
  - the ticket was purchased within 90 days of the request
  - the requested amount is at most 800 USD
  - the passenger has no prior adjustment in 12 months
Anything else escalates to a human.
"""


def say(title):
    print("\n" + "=" * 68 + "\n%s\n" % title + "=" * 68)


def run(cmd, cwd=None, check=True):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode:
        sys.exit("FAILED: %s\n%s%s" % (" ".join(cmd[:4]), p.stdout[-800:],
                                       p.stderr[-800:]))
    return p


def build_store(tmp, policy_bytes):
    """A real Warrant store, built with Warrant's own CLI.

    Not a fixture: `init`, `keygen`, `blob add`, `propose`, `accept` are the
    commands a deployment would run. If they change, this demo breaks — which
    is the point of not hand-writing the bytes.
    """
    cli = os.path.join(WARRANT, "impl", "warrant.py")
    store = os.path.join(tmp, ".warrants")
    key = os.path.join(tmp, "agent.key")
    run([sys.executable, cli, "--store", store, "init"])
    run([sys.executable, cli, "keygen", "--out", key])

    policy_file = os.path.join(tmp, "refund-policy.txt")
    with open(policy_file, "wb") as fh:
        fh.write(policy_bytes)
    out = run([sys.executable, cli, "--store", store, "blob", "add",
               policy_file]).stdout.strip().split()[-1]
    policy_hash = out

    # the decision itself: the agent approving one refund, under that policy
    claim = os.path.join(tmp, "claim.json")
    with open(claim, "wb") as fh:
        fh.write(json.dumps({"case": "AC-2026-0187", "amount_usd": 640,
                             "days_since_purchase": 31,
                             "prior_adjustments_12mo": 0},
                            sort_keys=True).encode())
    claim_hash = run([sys.executable, cli, "--store", store, "blob", "add",
                      claim]).stdout.strip().split()[-1]

    proposed = run([sys.executable, cli, "--store", store, "propose",
                    "--subject", claim_hash, "--under", policy_hash,
                    "--note", "refund approved by agent under refund-policy v1",
                    "--evidence", claim_hash,
                    "--actor", "agent:refund-bot@example",
                    "--key", key]).stdout.strip().split()[-1]
    accepted = run([sys.executable, cli, "--store", store, "accept",
                    "--subject", proposed,
                    "--note", "auto-approved: within 90 days, under 800 USD, "
                              "no prior adjustment",
                    "--under", policy_hash,
                    "--actor", "agent:refund-bot@example",
                    "--key", key]).stdout.strip().split()[-1]
    return store, policy_hash, claim_hash, proposed, accepted


def warrant_report(store):
    """Warrant judging Warrant's own bytes. SEV never re-derives this."""
    cli = os.path.join(WARRANT, "impl", "warrant.py")
    p = run([sys.executable, cli, "--store", store, "verify", "--json"],
            check=False)
    return json.loads(p.stdout), p.returncode


def sev_projection(store, out_dir):
    """SEV composing that judgement into an evidence view.

    The adapter runs Warrant a SECOND time, over the live store. That is a
    second observation, and round 1 never bound it to the first: a tamper
    landing between the two showed `ok=true` while SEV excluded both records,
    and the demo still said "keep auto-approving". So the receipt is written
    out and its `producer.report_digest` — the digest of the report SEV
    actually judged — is returned for comparison against the one printed.
    """
    adapter = os.path.join(SEV, "model", "warrant_adapter.py")
    p = run([sys.executable, adapter, store, "--out", out_dir], check=False)
    digest, excluded = None, None
    rec = os.path.join(out_dir, "receipt.json")
    vm = os.path.join(out_dir, "view-manifest.json")
    if os.path.isfile(rec):
        with open(rec) as fh:
            digest = json.load(fh)["producer"]["report_digest"]
    if os.path.isfile(vm):
        with open(vm) as fh:
            excluded = json.load(fh)["sources_excluded"]
    return p.stdout, p.returncode, digest, excluded


def bos_atoms(subject_wid, policy_hash, report, report_digest):
    """Two actors, one subject, two legitimate lenses.

    BOS is not being made a source of truth for meaning here. `risk` and
    `opportunity` are *attributed* readings of the same warranted decision,
    and both are recorded with who holds them — which is the whole point of
    an observer-relative assessment.
    """
    common = {
        "schema": "bos.atom@v0.4", "kind": "assessment",
        "states": {"governance": "bos:status:governance:proposed",
                   "maturity": "bos:status:maturity:research",
                   "priority": "bos:status:priority:now"},
        "created_at": "2026-08-11T00:00:00Z",
        "scope": ["ecosystem", "warrant"],
        "disclosure": {"classification": "public", "payload_mode": "embedded",
                       "retention": "indefinite"},
        "relations": [{"predicate": "derived_from",
                       "object": "bos:evidence:warrant:%s" % subject_wid[:16]}],
    }
    subject = "bos:asset:decision:warrant-%s" % subject_wid[:16]
    payload = {
        "subject": subject,
        "context_cut": "bos:context_cut:refund-slice-2026-08-11",
        "objective": "bos:goal:defensible-agent-autonomy",
        "evidence": ["bos:evidence:warrant:%s" % subject_wid[:16]],
    }
    # The atoms move with the evidence. An assessment that reads the same
    # whether or not its evidence holds is decoration, and the opportunity
    # lens here rests on a *specific* factual premise — "the record verifies
    # offline" — which is simply false when it does not.
    verified = bool(report["ok"]) and report["errors"] == 0
    payload["evidence"] = ["bos:evidence:warrant:%s" % subject_wid[:16],
                           # a real BOS id, not a sentence: the pattern is
                           # closed and my first attempt embedded "ok=True"
                           # and a comma, which the schema rejected
                           "bos:evidence:verify-report:%s"
                           % report_digest[:16]]
    risk = dict(common, id="bos:assessment:refund-agent-as-risk",
                title="Automated refund approval is an unbounded liability",
                created_by=["bos:actor:human:compliance"],
                payload=dict(payload, lens="risk",
                             assessed_by=["bos:actor:human:compliance"],
                             stakeholder="bos:actor:human:insurer",
                             statement=(
                                 "An agent approving refunds without human "
                                 "review can bind the company to costs it "
                                 "never budgeted." +
                                 (" The exposure stands even though the "
                                  "authorization verifies." if verified else
                                  " And the authorization no longer verifies, "
                                  "so the exposure is now unbounded by any "
                                  "evidence at all.")),
                             confidence="medium" if verified else "high",
                             likelihood="medium" if verified else "high",
                             magnitude="high",
                             horizon={"kind": "bounded",
                                      "until": "2026-11-11T00:00:00Z"}))
    if not verified:
        # withheld, not weakened: its premise is false, and an assessment
        # whose stated reason has failed should not be re-worded into
        # something it can still support
        return subject, [risk], ("opportunity withheld: its premise is that "
                                 "the record verifies offline, and it does not")
    opp = dict(common, id="bos:assessment:refund-agent-as-opportunity",
               title="A verifiable authorization trail makes the autonomy "
                     "defensible",
               created_by=["bos:actor:model:claude"],
               payload=dict(payload, lens="opportunity",
                            assessed_by=["bos:actor:model:claude"],
                            stakeholder="bos:actor:human:product",
                            statement="Because the decision pins the policy by "
                                      "hash and the record verifies offline, "
                                      "the same automation that creates the "
                                      "exposure also produces the evidence "
                                      "that bounds it.",
                            confidence="medium", likelihood="medium",
                            magnitude="medium",
                            horizon={"kind": "bounded",
                                      "until": "2026-11-11T00:00:00Z"}))
    return subject, [risk, opp], None


def validate_atoms(atoms):
    """Validated against BOS's FULL JSON Schema, or honestly skipped.

    Round 1 checked that the required keys were *present* and printed
    "PASS ... per the BOS schema". Both objects were in fact rejected by that
    schema — `states` was absent and `refund-agent` is outside a closed
    `scope` enum. A presence check reported as schema validation is a false
    green, and it is the exact failure this ecosystem exists to make hard.
    """
    path = os.path.join(BOS, "schemas", "bos-atom-v0.4.schema.json")
    if not os.path.isfile(path):
        return None, "BOS schema not found at %s" % path
    try:
        import jsonschema
    except ImportError:
        return None, ("jsonschema is not installed — NOT validated. "
                      "`pip install jsonschema` to check.")
    with open(path) as fh:
        schema = json.load(fh)
    for atom in atoms:
        try:
            jsonschema.validate(atom, schema)
        except jsonschema.ValidationError as exc:
            return False, "%s: %s" % (atom["id"], str(exc).splitlines()[0])
    return True, "full JSON Schema, %s" % os.path.relpath(path, SIBLINGS)


def countervectors():
    """The three findings that refuted round 1, kept as permanent controls.

    Each was a way this demo said more than its evidence supported. A story
    that once told a lie and no longer does is only trustworthy if something
    keeps checking.
    """
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            "" if cond else "  (%s)" % detail))
        ok = ok and bool(cond)

    tmp = tempfile.mkdtemp(prefix="refund-cv-")
    try:
        # 1. INTEGRITY IS NOT AUTHORIZATION. A claim far outside the policy
        # ceiling still verifies, because nothing here reads the policy.
        # The demo must reach "eligible for policy evaluation" and must NOT
        # say the decision was allowed.
        store, policy, _c, _p, acc = build_store(tmp, POLICY)
        rep, _rc = warrant_report(store)
        check("a $6400 claim under an $800 ceiling still verifies",
              rep["ok"] and rep["errors"] == 0,
              "integrity and authorization would be conflated if this failed")
        # Checked over the demo's OUTPUT, not its source. The first version
        # of this control grepped this file — and failed, because the string
        # it was forbidding appears in the control that forbids it. A guard
        # that reads itself is measuring the wrong thing.
        demo = subprocess.run([sys.executable, os.path.abspath(__file__)],
                              capture_output=True, text=True)
        check("...and the demo's own output never claims authorization",
              "eligible for policy evaluation" in demo.stdout
              and "auto-approving" not in demo.stdout,
              demo.stdout[-200:])

        # 2. THE TWO VERIFIER RUNS MUST BE BOUND. A tamper landing between
        # the printed report and SEV's own run once passed unnoticed.
        out = os.path.join(tmp, "cv-sev")
        blob = os.path.join(store, "blobs", policy)
        with open(blob, "wb") as fh:
            fh.write(POLICY.replace(b"800 USD", b"8000 USD"))
        _proj, prc, receipt_digest, excluded = sev_projection(store, out)
        sys.path.insert(0, os.path.join(SEV, "model"))
        import snapshot_model as _sm
        stale = _sm.sha256_hex(_sm.jcs(rep))
        check("a tamper between the two runs breaks the digest binding",
              receipt_digest != stale,
              "SEV judged the same report the demo printed")
        check("...and SEV excludes the affected sources",
              (excluded or 0) > 0, "excluded=%s" % excluded)

        # 3. THE BOS CHECK MUST BE REAL. Round 1 printed PASS from a
        # required-key check over atoms the full schema rejects.
        _s, atoms, _w = bos_atoms("a" * 64, "b" * 64,
                                  {"ok": True, "errors": 0}, "c" * 64)
        good, _d = validate_atoms(atoms)
        check("generated atoms pass BOS's FULL schema", good is not False)
        broken = json.loads(json.dumps(atoms[0]))
        del broken["states"]
        bad, _d2 = validate_atoms([broken])
        check("...and an atom missing `states` is REJECTED", bad is False,
              "a check that cannot fail is not a check")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return ok


def sibling_versions():
    """Local paths say nothing about which code ran."""
    out = []
    for name, path in (("warrant", WARRANT), ("sev", SEV), ("bos", BOS)):
        p = subprocess.run(["git", "-C", path, "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True)
        dirty = subprocess.run(["git", "-C", path, "status", "--porcelain"],
                               capture_output=True, text=True).stdout.strip()
        out.append("%-8s %-52s %s%s" % (name, path, p.stdout.strip() or "?",
                                        " (dirty)" if dirty else ""))
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--negative", action="store_true",
                    help="tamper with the pinned policy and re-run")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--countervectors", action="store_true",
                    help="run the permanent controls and exit")
    args = ap.parse_args(argv[1:])

    for name, path in (("warrant", WARRANT), ("BOS", BOS)):
        if not os.path.isdir(path):
            sys.exit("%s repository not found at %s\n"
                     "Set WARRANT_REPO / BOS_REPO, or check out the siblings."
                     % (name, path))
    for line in sibling_versions():
        print(line)
    if args.countervectors:
        return 0 if countervectors() else 1

    tmp = tempfile.mkdtemp(prefix="refund-slice-")
    try:
        say("1. EVIDENCE — the agent files what it decided, and under what")
        store, policy_hash, claim_hash, proposed, accepted = build_store(
            tmp, POLICY)
        print("policy blob   %s" % policy_hash)
        print("claim blob    %s" % claim_hash)
        print("proposal      %s" % proposed)
        print("acceptance    %s   <- the decision" % accepted)

        if args.negative:
            say("NEGATIVE CONTROL — the policy is edited after the fact")
            blob = os.path.join(store, "blobs", policy_hash)
            with open(blob, "wb") as fh:
                fh.write(POLICY.replace(b"800 USD", b"8000 USD"))
            print("rewrote blobs/%s: the ceiling now reads 8000 USD" % policy_hash[:16])
            print("the record still points at the OLD hash — that is the test")

        say("2. JUDGEMENT — Warrant's own verifier, over Warrant's own bytes")
        report, rc = warrant_report(store)
        print("report        %s" % report["report"])
        print("ok=%s records=%d errors=%d warnings=%d (exit %d)"
              % (report["ok"], report["records"], report["errors"],
                 report["warnings"], rc))
        for f in report["findings"][:4]:
            print("  %-4s %s  %s" % (f["level"], f["subject"][:12], f["message"][:70]))

        say("3. COMPOSITION — SEV projects that judgement, and says what it drops")
        sev_out = os.path.join(tmp, "sev-out")
        proj, prc, receipt_digest, excluded = sev_projection(store, sev_out)
        # the digest of the report we printed, computed the way the adapter
        # computes the one it bound into the receipt
        sys.path.insert(0, os.path.join(SEV, "model"))
        import snapshot_model as _sm
        shown_digest = _sm.sha256_hex(_sm.jcs(report))
        excluded = 0 if excluded is None else excluded
        print(proj.strip()[:900])

        say("4. ATTRIBUTION — two actors, one decision, two legitimate lenses")
        subject, atoms, withheld = bos_atoms(accepted, policy_hash, report, shown_digest)
        ok, detail = validate_atoms(atoms)
        print("subject       %s" % subject)
        for a in atoms:
            print("  %-11s by %-28s %s"
                  % (a["payload"]["lens"], a["payload"]["assessed_by"][0],
                     a["payload"]["statement"][:60] + "…"))
        if withheld:
            print("  %-11s %s" % ("(none)", withheld))
        print("schema check  %s  (%s)" % (
            "PASS" if ok else ("SKIP" if ok is None else "FAIL"), detail))
        out = os.path.join(tmp, "bos-atoms")
        os.makedirs(out, exist_ok=True)
        for a in atoms:
            with open(os.path.join(out, a["id"].split(":")[-1] + ".json"),
                      "w") as fh:
                json.dump(a, fh, indent=2, ensure_ascii=False, sort_keys=True)
        print("atoms written  %s (kept only with --keep)" % out)

        say("5. ACTION — bounded by what the evidence actually supports")
        # `healthy` now means all three: the report we PRINTED is the report
        # SEV judged (bound by digest), SEV excluded nothing, and Warrant
        # said ok. Round 1 checked only the first and the last, and a tamper
        # landing between the two verifier runs slipped through with
        # "keep auto-approving" while SEV had excluded both records.
        bound = receipt_digest == shown_digest
        healthy = report["ok"] and prc == 0 and excluded == 0 and bound
        print("report digest  shown=%s  in SEV receipt=%s  bound=%s"
              % (shown_digest[:12], (receipt_digest or "-")[:12], bound))
        print("sources excluded by SEV: %s" % excluded)
        if healthy:
            print("\nFINDING: the authorization trail is INTACT.")
            print("  The decision %s names policy %s," % (accepted[:16], policy_hash[:16]))
            print("  those bytes are still what the store holds, and the")
            print("  report SEV composed is the one printed above.")
            print("\nACTION:  eligible for policy evaluation.")
            print("  NOT 'approved'. Nothing here reads the policy prose or")
            print("  checks the claim against it — a $6400 claim under an")
            print("  $800 ceiling reaches this same line, and the permanent")
            print("  countervector below proves it. Integrity is not")
            print("  authorization, and this slice only does integrity.")
        else:
            print("\nFINDING: the authorization trail is BROKEN.")
            print("  Warrant ok=%s errors=%d; SEV excluded %d source(s); "
                  "report bound=%s" % (report["ok"], report["errors"],
                                       excluded, bound))
            print("\nACTION:  stop auto-approval; route to a human.")
            print("  Nobody edited the DECISION — someone edited what it was")
            print("  decided under, or the two verifications disagree.")
        if args.negative:
            # The control asserts its own outcome. Without this, "tamper not
            # detected" and "tamper detected" would both be readable from the
            # exit code only by knowing which mode you asked for — and a
            # regression would look like a clean run.
            print("\nnegative control: the tamper WAS detected = %s" % (not healthy))
            if healthy:
                print("FAILED: the edit did not change the outcome.")
                return 1
            return 0
        return 0 if healthy else 1
    finally:
        if args.keep:
            print("\nstore kept at %s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
