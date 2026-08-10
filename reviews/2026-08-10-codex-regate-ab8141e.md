# Re-gate of `ab8141ea…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `ab8141ea7d6e3cf840e02162ad06640b8b59438d`. Baseline
64 + 130 + 9 green; the `ExecutionAssessment ≠ CheckRun` split confirmed
working. One P1: the new guard checked domains but not ranges.

## P1 — the Warrant record was entailed to be an Activity

The projector emitted `run prov:wasInformedBy record`. In PROV-O that
predicate has an Activity **range** as well as an Activity domain, so the
graph logically asserted that `urn:wrt:record:…` — typed `wrt:Warrant`, an
Entity — is also an Activity. The entailment guard introduced one round
earlier inspected only the *subject* of Activity-domain predicates, so it
printed PASS over exactly the graph it was meant to catch. The same shape
had already become a normative example in the profile.

**Disposition.** The run consumed the record's bytes to reach the reason, so
it now says `prov:used` (Activity → Entity); `prov:wasInformedBy` is
reserved for two genuine Activities. The guard is predicate-specific and
bidirectional:

| Predicate | subject | object |
|---|---|---|
| `prov:used` | Activity | Entity |
| `prov:wasInformedBy` | Activity | Activity |
| `prov:generated` | Activity | Entity |
| `prov:wasGeneratedBy` | Entity | Activity |
| `prov:wasAssociatedWith` | Activity | Agent |
| `prov:specializationOf` | Entity | Entity |

An Activity position requires an Activity type (`sigma:CheckRun`,
`wrt:Filing`); an Entity position forbids one, so untyped nodes pass as
Entities.

**The guard is now unit-tested against malformed graphs**, because on a
healthy dataset its range clause has nothing to catch and a mutation showed
it was vacuous otherwise: three synthetic graphs exercise an Activity-range
violation, an Activity-domain violation, and an Activity standing in an
Entity position. The profile's normative example was corrected too.

## Mutation results

| Guard | Suite when removed |
|---|---|
| reverting `prov:used` back to `prov:wasInformedBy` | fails |
| the range clause | fails — after the guard's own unit vectors were added; it was vacuous before, and the vectors were added rather than the gap accepted |

## State after closure

64 model + 133 projector vectors + 9 fixtures, all green, exit-status
honest. Freeze criterion still unmet.
