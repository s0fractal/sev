# Self-review of `39bda50d…` — Claude, 2026-08-10

> **Status caveat, stated first because it is the most important line here.**
> This is a **self-review, not an independent gate.** AGENTS.md rule 7
> defines a review round as adversarial counter-vector hunting by a *fresh*
> reviewer; the author hunting their own work does not satisfy it and cannot
> be counted toward the freeze criterion. It was run because the standing
> reviewer was unavailable and the alternative — stopping — would have left
> the branch unexamined. Everything below was reproduced by execution, but
> the round remains **unwitnessed**, and the freeze criterion (a round with
> zero P1 findings, gated by someone else) is still unmet.

## P1 — the loss manifest described caveats on facts that are absent entirely

Reproduced: a receipt carrying a `valid: true, binding: "bound"` signature
by `alice@x` projects with **zero findings**, the manifest reports
`sources_projected: 2, sources_excluded: 0`, and the graph contains no
signature node at all. Widening the probe:

| Profile §4.1 promises | In the emitted graph |
|---|---|
| actor, `under` → `prov:Plan`, subject, evidence, `prior` | absent |
| signature nodes with binding | absent |
| jurisdiction-scoped settlement | absent |
| unclaimed snapshot members | absent |

Meanwhile `L-SIG` read *"signature validity/binding are receipt-reported"*
and `L-SETTLE` *"settlement/grade not re-derivable"* — phrasings that
describe a **lossy projection of something present**. A consumer reading
that manifest concludes "everything is here, with reservations" when the
truth is "most of the profile is not projected yet". That is precisely the
failure class this repository exists to hunt — an artifact covering less
than it claims — occurring in the artifact whose entire job is declaring
what it cannot express.

**Disposition (scope-controlled: declare, do not fake).** The MVP stays
narrow; its limits become machine-readable.

- New codes emitted **only when the corresponding data actually exists** in
  the receipt/snapshot: `L-NOSIG`, `L-NOSETTLE`, `L-NOUNCLAIMED`.
- `L-NOMAP` always emitted: profile §4.1 record-body mapping (actor,
  `under`/Plan, subject, evidence, prior) is not implemented.
- `L-SIG` / `L-SETTLE` reworded to describe the real state ("where
  projected, would be…").
- The view manifest gains a `coverage` block (`emitted` / `not_emitted` /
  note) so `sources_projected` can no longer be read as completeness of the
  mapping over those sources.

## P2 — absent semantics stringified into hash material

A run whose runtime is not in `execution_policy` (an honest
`unverified` / `RUNTIME_UNAVAILABLE`) hashed the literal `"None"` into its
IRI material. Not a false assertion — the IRI is opaque — but it makes an
absence collide with a hypothetical runtime literally named `None`. Now an
empty field; digests are fixed-length, so `""` is unambiguous.

## Mutation results

| Guard | Suite when removed |
|---|---|
| `L-NOSIG` emission | fails |
| `L-NOMAP` emission | fails |
| `coverage` block | fails |

One vector of mine was wrong on first run and the guard corrected me: I
asserted `L-NOUNCLAIMED` on a fixture that pins no unclaimed bytes, and the
honest answer was "no absence code for data that is not there". The vector
now tests both directions.

## State

64 model + 67 projector vectors + 9 fixtures, all green, exit-status honest.
**Merge remains held.** The next round must be run by someone other than the
author; until then this branch has one unwitnessed round on top of eight
witnessed ones.
