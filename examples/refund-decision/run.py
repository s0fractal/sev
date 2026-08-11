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


def sev_projection(store):
    """SEV composing that judgement into an evidence view."""
    adapter = os.path.join(SEV, "model", "warrant_adapter.py")
    p = run([sys.executable, adapter, store], check=False)
    return p.stdout, p.returncode


def bos_atoms(subject_wid, policy_hash, report):
    """Two actors, one subject, two legitimate lenses.

    BOS is not being made a source of truth for meaning here. `risk` and
    `opportunity` are *attributed* readings of the same warranted decision,
    and both are recorded with who holds them — which is the whole point of
    an observer-relative assessment.
    """
    common = {
        "schema": "bos.atom@v0.4", "kind": "assessment",
        "created_at": "2026-08-11T00:00:00Z",
        "scope": ["ecosystem", "refund-agent"],
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
                           "bos:evidence:verify-report:ok=%s,errors=%d"
                           % (report["ok"], report["errors"])]
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
                             magnitude="high",
                             horizon="quarter"))
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
                            confidence="medium", magnitude="medium",
                            horizon="quarter"))
    return subject, [risk, opp], None


def validate_atoms(atoms):
    """Checked against BOS's own schema file — the mechanical subset only.

    This is a required-key check against `schemas/bos-atom-v0.4.schema.json`,
    not BOS's full validator, which judges a whole atom graph in place. The
    limit is stated because a demo that says "validated" while checking
    nothing is the failure this ecosystem exists to make hard.
    """
    path = os.path.join(BOS, "schemas", "bos-atom-v0.4.schema.json")
    if not os.path.isfile(path):
        return None, "BOS schema not found at %s" % path
    with open(path) as fh:
        schema = json.load(fh)
    env_req = schema.get("required", [])
    defs = schema.get("$defs") or schema.get("definitions") or {}
    pay_req = (defs.get("assessment_payload") or {}).get("required", [])
    for atom in atoms:
        missing = [k for k in env_req if k not in atom]
        missing += ["payload.%s" % k for k in pay_req
                    if k not in atom.get("payload", {})]
        if missing:
            return False, "%s is missing %s" % (atom["id"], missing)
    return True, "envelope + assessment payload required keys, per %s" % (
        os.path.relpath(path, SIBLINGS))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--negative", action="store_true",
                    help="tamper with the pinned policy and re-run")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args(argv[1:])

    for name, path in (("warrant", WARRANT), ("BOS", BOS)):
        if not os.path.isdir(path):
            sys.exit("%s repository not found at %s\n"
                     "Set WARRANT_REPO / BOS_REPO, or check out the siblings."
                     % (name, path))
    print("warrant: %s\nsev:     %s\nbos:     %s" % (WARRANT, SEV, BOS))

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
        proj, prc = sev_projection(store)
        print(proj.strip()[:900])

        say("4. ATTRIBUTION — two actors, one decision, two legitimate lenses")
        subject, atoms, withheld = bos_atoms(accepted, policy_hash, report)
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

        say("5. ACTION — and the reason traces back to bytes")
        healthy = report["ok"] and prc == 0
        if healthy:
            print("DECISION: keep this agent auto-approving under refund-policy v1.")
            print("REASON:   the acceptance %s verifies offline," % accepted[:16])
            print("          it pins the policy as %s," % policy_hash[:16])
            print("          and those bytes are still what the store holds.")
            print("          The insurer's `risk` reading stands; the")
            print("          `opportunity` reading is what makes it insurable.")
        else:
            print("DECISION: STOP auto-approval; route refunds to a human.")
            print("REASON:   the evidence no longer supports the authorization.")
            print("          Warrant reports ok=%s, errors=%d." % (report["ok"], report["errors"]))
            print("          SEV %s." % ("refused to project"
                                         if prc else "projected with exclusions"))
            print("          Nobody edited the DECISION — someone edited what")
            print("          it was decided under, and that is visible.")
        if args.negative:
            # A negative control that cannot fail is not a control. If the
            # tamper stops flipping the verdict, this must go red — otherwise
            # the demo would keep printing a reassuring story over evidence
            # that no longer holds.
            flipped = (not report["ok"]) and report["errors"] > 0
            print("\nnegative control: verdict flipped = %s" % flipped)
            if not flipped:
                print("FAILED: the tamper did not change the judgement.")
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
