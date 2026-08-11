# Round 15 closure — Codex, target `c9ff62a` (PR #5), verdict AMEND

> **Attribution correction (round 16 P2).** This file and the ledger row
> first named the reviewer as Kimi. The round-15 findings were **Codex's**
> exact-SHA review. The delivering message carried no attribution and I
> filled one in from the recent pattern instead of leaving it unnamed —
> asserting provenance I did not have, in the ledger whose whole purpose
> is provenance. Corrected here and in `reviews/README.md`.

Reviewer: **Codex — 2 P1 + 1 P2**, all against the body-mapping branch. Every finding
reproduced by execution before any change. Closed on
`author/body-mapping`; **merge and re-gate remain the reviewer's call.**
PR #6 stays untouched — its base failed, and it is not gated until this is.

## P1-1 — the manifest contradicted the graph it shipped with

Reproduced exactly. A fixture whose N-Quads carry `wrt:claimedActor`,
`wrt:underPolicy`, `prov:qualifiedUsage` and `wrt:prior` returned:

```
not_emitted = actor, evidence, policy-plan, prior, signature, subject
```

Four of those six are in the graph. The cause is precisely as diagnosed: an
unconditional block reading *"a record exists, therefore its mapping is
missing"* — true while §4.1 was unimplemented, and a direct contradiction
once it landed. I replaced `L-NOMAP` in the loss manifest and left its twin
in `coverage` untouched.

This is the worst version of this repository's recurring defect: not a guard
covering less than it claims, but **the artifact whose entire job is
declaring what it cannot express, lying about it.**

**Disposition.** Each category is now derived from what was actually
emitted. The projection tracks two sets — `body_present` (what the committed
bodies held) and `body_mapped` (what of it reached the graph) — and
`not_emitted` is their difference. `policy-plan` correctly survives: the weak
default is emitted, the Plan promotion is not.

**The guard is now a cross-check between the two outputs**, not a restatement
of the code's intentions: for every category in `coverage.not_emitted`, its
marker predicate must be absent from the N-Quads. Restoring the original
defect fails it, naming all four categories.

## P1-2 — the frozen-boundary guard compared codes, not verdicts

Confirmed by reading: `[x["code"] for x in ...]`. A finding is `code`,
`severity` and `at`, and order is part of the verdict too. ERR→WARN or
`path:a`→`path:b` would have passed.

The irony is exact: a guard written to prove a frozen contract was untouched
was itself covering less than it claimed.

**Disposition.** Comparison is now over **JCS bytes of the ordered finding
list**. Mutants injected at `verify_receipt_bytes`, each altering the verdict
only when a view is requested:

| Mutation under view | Result |
|---|---|
| severity flipped | caught by the view guard |
| locator changed | caught by the view guard |
| code changed | caught by the view guard |
| order reversed | caught by the view guard |
| one finding dropped | caught by the view guard |

**A second weakness found while fixing it, not reported and worth stating.**
The corpus was nine byte-boundary refusals — cases that return *before* the
deep validator runs, and yield **one finding each**. So the guard's claim
("the verdict is view-independent") was tested almost entirely on paths where
the view is cleared and discarded, and order was **unobservable** because no
case ever produced two findings. Four semantic cases were added (bad counts,
unsound source, bad reason, several at once): structurally valid documents
that reach `_verdict_over_objects` and produce multiple findings.

Stated precisely, because I could not prove more: the semantic cases are the
only ones that give this guard more than one finding to compare, which is
what makes order and multiplicity observable *by it*. I could **not**
construct a mutation that only they catch — other vectors in the suite
overlap on every deep-path defect I tried. So they widen this guard's reach;
they are not load-bearing for the suite as a whole.

## P2 — the profile named an emitted predicate as never-emitted

Confirmed: the prose listed `qualifiedUsage` among target-only predicates
while §4.1 emits it and `mvp_predicates` declares it.

**Disposition — the list is deleted rather than corrected.** A prose copy of
a machine-readable set rots the moment the set moves, and correcting it just
resets the clock. `conformance/prov-shapes.json` is named as the single
source of truth, and the paragraph now describes the *discipline* instead of
duplicating the *members*.

That paragraph claims the honesty holds in both directions, which was true
only on PR #6. Rather than let the text overclaim on this branch, the
**declared − emitted = ∅** check was moved down into this PR. Over-declaring
a predicate no fixture emits now fails the suite here.

## Accepted without argument

The withdrawn `under[] → urn:wrt:blob:*` suspicion is noted as withdrawn; no
change was made and none was needed.

## Also fixed here

`resB` in the §4.1 vectors collided with a later `resB` in the same
2000-line `run_vectors`, so a check silently read a rebound value. Found
while writing PR #6, fixed here because the collision is in this branch.
Renamed to `res_body`.

## Mutation results

7 mutations of the changed detectors; 4 fail the suites, and the 3 that do
not are mutations that make an assertion **trivially true** rather than
removing coverage — the honest test for those is restoring the defect, which
is the first row:

| Mutation | Result |
|---|---|
| the original P1-1 defect restored | fails — names all four categories |
| `body_mapped` never populated | fails |
| `policy-plan` absence dropped | fails |
| guard compares codes only (P1-2 restored) | fails |

Plus the five view-guard mutants above, all caught by the guard itself.

## State

98 model + 271 projector + 11 fixtures + 29 adapter, all green, exit status
honest. Live store: 81 sources, 1081 quads, 0 errors / 16 warnings.

**Not done:** no merge, no freeze, no work on PR #6 until this branch is
re-gated clean.

---

# Round 16 closure — Codex, target `c701d91` (PR #5), verdict AMEND

**1 P1 + 1 P2.** Both reproduced before any change.

## P1 — `wrt:claimedActor` disagreed with the normative profile

Confirmed by reading both sides: the promotion table declared
`wrt:claimedActor` an **IRI**, the identity registry defines
`urn:wrt:actor:<pct-encoded actor string>`, and the projector emits
`"signer@example"` as a **literal**.

**The profile is what changes, per the reviewer's recommendation, and the
code was right.** Before a `valid && bound` signature, `body.actor.id` is a
claim the record makes, not an identity the bundle can name. Minting
`urn:wrt:actor:…` for it would let any consumer merge two records that
merely assert the same string into one referent — on the strength of
nothing. That is the same principle PR #6 builds its attribution rule on, so
the two now agree instead of contradicting: the weak default is a literal,
and the actor IRI belongs to the promotion path alone.

Both halves are vectored — `claimedActor` must be a literal, and no
`urn:wrt:actor:`, `prov:wasAssociatedWith` or `prov:Agent` may appear
without a binding. Three mutations (actor as IRI, actor IRI without
binding, agent without binding) each fail the suites.

**Known consequence, flagged not fixed.** PR #6 mints
`urn:sev:agent:<sha256(actor)>` for its attribution path, while the registry
names `urn:wrt:actor:<pct-encoded>`. That divergence is real and is #6's to
close; it is left untouched here because #6 is not gated and this branch was
to receive two narrow changes only.

## P2 — the ledger misattributed round 15

Correct, and it is my error. The delivering message carried no attribution
and I filled one in from the recent pattern rather than leaving it unnamed —
**asserting provenance I did not have, in the ledger whose entire purpose is
provenance.** Ledger row and this file both now name Codex, and the
correction is recorded above rather than applied silently.

The general lesson is recorded too: an unattributed round must be filed
unattributed until its reviewer says otherwise. A guess that happens to be
wrong is indistinguishable, in the file, from a fact.

## State

98 model + 274 projector + 11 fixtures + 29 adapter, all green. Live store
unchanged: 81 sources, 1081 quads, 0 errors / 16 warnings.
