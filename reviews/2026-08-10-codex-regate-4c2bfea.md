# Re-gate of `4c2bfea5…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `4c2bfea5b8d542ea2d1a87ef530563c0ecffe51a`. The previous
axiom fix is confirmed: `Agent ∩ Entity` accepted, `Activity ∩ Entity`
rejected. Baseline 64 + 148 + 9 green. One P1, one P2 — and a structural
recommendation for leaving the meta-loop, which is the most valuable part of
this round.

## P1 — a complete class registry beside an MVP-only predicate list

`PROV_SIGNATURES` held seven relations while the target profile normatively
uses more: `qualifiedUsage` (§4.1), `wasInvalidatedBy` (§4.2),
`wasDerivedFrom` (§4.3), plus `qualifiedAssociation`, `hadPlan`,
`wasInfluencedBy`. Graphs with impossible endpoints passed untouched:

```
wasDerivedFrom activity->activity   got=set()
wasInvalidatedBy entity->entity     got=set()
qualifiedUsage with entity subject  got=set()
```

So the claimed "profile guard vs MVP guard" split did not exist: one
function carried a target class registry and an MVP predicate registry.

**Disposition — the shapes became data.** `conformance/prov-shapes.json`
now holds classes (`class → parent`), the disjointness axioms and every
target predicate's endpoint kinds in one machine-readable artifact the guard
loads; a second implementation reads the same file rather than the Python.
The file separately declares `mvp_predicates` — the subset this projector
can emit — and vectors assert both that the declared subset really is a
subset and that the projector emits nothing outside it. `influence` was
added as a kind so qualified relations (`Usage`, `Association`,
`Attribution`) are modelled rather than guessed, and `wasInfluencedBy` is
`any → any` because PROV-O leaves it unconstrained.

Five target-predicate vectors, including the reviewer's three verbatim plus
two positive controls (`qualifiedUsage` done correctly, `hadPlan` from an
Association to a Plan).

## P2 — the profile contradicted itself

Two paragraphs still described "three disjoint PROV kinds" and a position
requiring *exactly* one kind — the rules removed from the code one round
earlier, sitting directly beneath the corrected `Agent ∩ Entity` rule. Both
were replaced by a single accurate paragraph.

## The structural recommendation, adopted

The reviewer's exit from the meta-loop is now in `README.md`: **freeze
criteria are split per artifact** — snapshot/receipt core, MVP projector,
and the full target profile — each freezing on its own clean round. A
finding in a future OAIP/BOS mapping can no longer block a snapshot core
that has been stable for a dozen rounds.

## State after closure

64 model + 155 projector vectors + 9 fixtures, all green, exit-status
honest. No artifact is frozen yet, but the criteria are now separable.
