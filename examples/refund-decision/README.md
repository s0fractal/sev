# Can you prove what your AI agent was allowed to do?

In 2024 an airline's chatbot told a grieving passenger he could claim a
bereavement discount after booking. He couldn't — the real policy said
before. He sued, and won. The airline argued the bot was "a separate legal
entity responsible for its own actions." The tribunal disagreed.

Your logs can show **what the agent said**. This shows **what it was allowed
to say** — and lets someone who does not trust you check it, offline, months
later, on their own machine.

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
| **Action** | this script | a concrete next step, and the reason traces back to the bytes |

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
- the action flips from *keep auto-approving* to *stop; route to a human*.

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

## What this does not do

- **It is not proof that a verifier ran.** The record is signed; the
  *verification report* is not. Reliance means re-running it — which is the
  point of it being offline and dependency-free.
- **Signatures verify; bindings do not.** With no keyring configured, Warrant
  reports `binding unverified` — the signature is valid, but nothing here
  proves the key belongs to that actor. Both runs show it, and the demo does
  not paper over it.
- **The BOS check is a subset.** Atoms are checked against BOS's own schema
  file for required keys, not by BOS's full graph validator.
- **Nothing here is adopted.** All three repositories are research. This
  example composes their public contracts; it does not register or freeze
  anything.

## Why an outsider might care

Regulated deployers of AI systems have to show, after the fact, why an
automated decision was permitted. An audit log says a thing happened. A
signed record that pins its authorizing policy by hash says the decision was
*allowed*, names what allowed it, and fails loudly if that policy is edited
afterwards — including by you.
