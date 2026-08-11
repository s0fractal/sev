> # NOT YET USEFUL
>
> **Closed as an external artifact. Do not show this to anyone outside the
> ecosystem, and do not treat its green runs as evidence.** An independent
> gate found that the controls did not survive, and the stopping rule is
> applied literally: no third repair pass.
>
> The four findings, each reproduced:
>
> 1. **The `$6400` countervector runs `$640`.** `build_store()` hard-codes
>    `amount_usd: 640`, and the control passes it no amount. The PASS line
>    names a test that never executed — the exact shape of defect the control
>    existed to prevent.
> 2. **The main detector is undefended.** Replacing
>    `healthy = report["ok"] and prc == 0 and excluded == 0 and bound` with
>    `healthy = report["ok"]` still prints **six PASS and exits 0**. The
>    digest binding and the exclusion check — the whole round-2 repair — can
>    be deleted without the suite noticing.
> 3. **"Full JSON Schema" is not full.** `jsonschema.validate()` is called
>    with no `FormatChecker`, so `created_at: "not-a-date"` validates despite
>    the schema declaring `format: date-time`.
> 4. **The authorization claim regrew.** The closing paragraph below said the
>    record shows a decision was *permitted* and *allowed* — the precise
>    claim the previous pass removed from the top of this file, reappearing
>    at the bottom of the same file.
>
> `--countervectors` now exits **non-zero** and prints this closure. That is
> not a repair: it stops a false green from being quotable. Everything else
> is left exactly as the gate found it.
>
> **What is worth keeping** is the mechanism, not the demo: content-addressed
> tamper detection works, and the `--negative` path genuinely flips. What
> failed is this *packaging* of it — a headline, a set of controls and an
> actual proof that kept drifting apart. A useful external artifact should
> not need policy semantics, a BOS graph and two verifier runs at once.

# Can you prove what your AI agent was allowed to do?

In 2024 an airline's chatbot told a grieving passenger he could claim a
bereavement discount after booking. He couldn't — the real policy said
before. He sued, and won. The airline argued the bot was "a separate legal
entity responsible for its own actions." The tribunal disagreed.

Your logs can show **what the agent said**. This shows **which policy bytes
the decision named, and whether they are still those bytes** — checkable by
someone who does not trust you, offline, months later, on their own machine.

**That is integrity, not authorization.** Nothing here reads the policy prose
or checks the claim against it. A $6400 claim under an $800 ceiling passes
this demo exactly as a $640 one does, and a permanent countervector asserts
that it does — because the moment this example implies it validated the
*decision*, it is lying about what it proved.

## Run it

```bash
python3 examples/refund-decision/run.py            # the whole path
python3 examples/refund-decision/run.py --negative # tamper with the policy first
```

Needs Python 3 and the sibling `warrant` and `BOS` checkouts. No install, no
network, no services, no configuration. Set `WARRANT_REPO` / `BOS_REPO` if
they live elsewhere; the script prints what it resolved.

## What it does

A refund bot approves a $640 claim. At the moment of the decision it files a
signed record that pins, **by hash**, the exact policy text it acted under.
Then four things happen, each done by the component that owns it:

| Step | Who | What comes out |
|---|---|---|
| **Evidence** | Warrant CLI | a signed record: decision, subject, and the policy hash it was made under |
| **Judgement** | Warrant's own verifier | `warrant.verify-report@v0` — machine-readable, produced by running the verifier, not written by hand |
| **Composition** | SEV | an evidence view over that judgement, shipped with an explicit list of what the view *cannot* express |
| **Attribution** | BOS atoms | two actors assessing the **same** decision through different lenses |
| **Action** | this script | a bounded next step — *eligible for policy evaluation*, never *approved* |

## The part that matters

Run it with `--negative`. Someone edits the refund policy after the fact —
raising the auto-approval ceiling from $800 to $8000 — and leaves the
decision record untouched.

Nothing about the decision changed. But:

- Warrant reports `blob content does not match its address`, `ok=false`;
- SEV's projection drops from 75 quads to 20 and **excludes both records**,
  carrying the reason;
- the "opportunity" assessment is **withheld**, because its stated premise —
  *"the record verifies offline"* — is now false;
- the action flips from *eligible for policy evaluation* to *stop; route to a human*.

The tamper is detected by content addressing, not by a policy engine, and it
is detected by someone who was not there when the decision was made.

## Two lenses, one decision

Compliance reads the automated refund as a **risk**: it can bind the company
to costs nobody budgeted. Product reads the same decision as an
**opportunity**: the automation that creates the exposure also produces the
evidence that bounds it.

Both readings are recorded with **who holds them**. Neither is promoted to
"the truth about the decision" — a system that forces one label onto a
contested subject loses the disagreement, and the disagreement is usually the
information.

## Hashes differ between runs, on purpose

Each run generates a fresh signing key and fresh timestamps, so the
WarrantIDs and the graph digest are new every time. What is stable is the
*relationship*: the decision pins a policy hash, and that hash is either
still the content of the store or it is not. Determinism here is within a
run, not across runs — a demo with hard-coded hashes would be a demo of a
recording.

## Run the controls

```bash
python3 examples/refund-decision/run.py --countervectors
```

Six checks, each one a way an earlier version of this demo said more than it
could support: the $6400 claim still verifying; the demo's **output** never
claiming authorization; a tamper landing *between* the two verifier runs
breaking the digest binding; SEV excluding the affected sources; the
generated atoms passing BOS's full JSON Schema; and an atom with a missing
required field being **rejected**, so the schema check cannot be a false
green.

## What this does not do

- **It is not proof that a verifier ran.** The record is signed; the
  *verification report* is not. Reliance means re-running it — which is the
  point of it being offline and dependency-free.
- **Signatures verify; bindings do not.** With no keyring configured, Warrant
  reports `binding unverified` — the signature is valid, but nothing here
  proves the key belongs to that actor. Both runs show it, and the demo does
  not paper over it.
- **It does not evaluate the policy.** See above; this is the whole reason
  the action stops at *eligible for policy evaluation*.
- **The BOS atoms validate, but the graph is not materialized.** They pass
  BOS's full JSON Schema (`jsonschema` required; the check says so honestly
  when it is absent). The actors, evidence and context-cut they reference are
  not committed atoms, so BOS's own graph validator would still object.
- **Nothing here is adopted.** All three repositories are research. This
  example composes their public contracts; it does not register or freeze
  anything.

## Why an outsider might care

Regulated deployers of AI systems have to show, after the fact, why an
automated decision was permitted. An audit log says a thing happened. A
signed record that pins its authorizing policy by hash says the decision was
*allowed*, names what allowed it, and fails loudly if that policy is edited
afterwards — including by you.
