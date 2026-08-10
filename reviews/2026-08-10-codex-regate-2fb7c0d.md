# Re-gate of `2fb7c0d9…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `2fb7c0d9dbc75907f3942c5e954e263afdbd6c93`; local branch,
origin and PR agree, CI green, baseline 64 + 71 + 9 confirmed by the
reviewer. Two new compositional P1s. No files, commits, pushes or GitHub
actions by the reviewer.

## P1-1 — an exact built-in is not yet a JSON *tree*

The new `_freeze()` rejected subclasses correctly but walked exact
`dict`/`list` with no cycle or depth guard. Self-referential containers are
ordinary exact built-ins, so they passed the type check and then blew the
stack: `receipt-cycle`, `snapshot-cycle` and deep nesting all raised
`RecursionError` out of the public `project()`, where the contract promises
bounded findings.

**Disposition.** `_freeze` now carries an active-object set (cycle
detection), an explicit `MAX_FREEZE_DEPTH` (64 — these contracts are shallow
by construction) and a node budget, and the composed verdict catches
`RecursionError` alongside `_NotFreezable`. Every such input yields exactly
one `INPUT_NOT_FREEZABLE`. Four permanent vectors: dict-cycle in the
receipt, list-cycle in the receipt, over-depth in the receipt, dict-cycle in
the snapshot — each asserting a bounded refusal, and explicitly failing the
vector if a `RecursionError` escapes.

Mutation note: the **cycle** clause alone cannot be isolated — with it
removed a cycle still terminates on the depth budget. It is kept for the
precise reason and because it becomes load-bearing if the budget is raised,
and it is **labelled unisolatable in code** rather than counted as covered.
The depth guard *is* isolatable and fails the suite when removed.

## P1-2 — coverage and losses claimed evidence the dataset never held

A valid Warrant subroot containing a single blob — no records, reasons,
signatures or settlement — projected cleanly while emitting `L-NOMAP`,
`L-SIG`, `L-SETTLE`, `L-REEXEC` and a static coverage list naming `record`,
`filing`, `reason` and `check-run`. The manifest asserted the dataset had
lost evidence that was never in the input, contradicting the profile's own
rule that a caveat on an absent fact is worse than silence.

**Disposition — dataset-relative, per the reviewer's preferred option.**
`coverage.emitted` is now derived from the categories the run actually put
in the graph; `coverage.not_emitted` from evidence the input actually held.
Every loss became conditional: `L-NOMAP` only where a record was projected,
`L-REEXEC` only where a check run was emitted, `L-SETTLE` only where
signature/settlement evidence exists, `L-CANON` only where the graph is
non-empty. The blob-only dataset now emits `coverage.emitted =
["source", "verification-receipt"]`, `not_emitted = []` and only `L-CANON`
+ `L-COMPLETE`; the record-bearing fixture still declares `L-NOMAP` and
`L-REEXEC`. Both directions are permanent vectors. The profile's §6, §8 and
§9 state the dataset-relative semantics and note that a capability list, if
ever wanted, belongs in a separate `projector_capabilities` field.

## Confirmed as holding

Uncopyable and subclass inputs fail closed; no partial view is published on
a freeze refusal; the plain-dict path still projects; the earlier profile
drift (registration of `coverage` and `L-NO*`) is formally closed.

## State after closure

64 model + 81 projector vectors + 9 fixtures, all green, exit-status honest.
Freeze criterion still unmet.
