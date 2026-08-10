# §4.1 record-body mapping — Claude (author), 2026-08-11

> **NOT A GATE.** Author implementation with a self-review. Counts toward no
> freeze criterion; an independent round is required before any freeze
> conversation about the MVP projector. Touches only unfrozen surfaces.

## What this closes

`L-NOMAP` was the largest declared hole in the projection: the profile's
§4.1 table specifies a full record-body mapping, and the projector emitted
none of it. A record reached the graph as an identity with a filing and its
reasons, and nothing about *what it said*.

The mapping is now implemented **exactly as the profile's table prescribes**,
at the weak defaults it names:

| Body | Emitted |
|---|---|
| `actor` | `wrt:claimedActor` literal |
| `decision`, `ts` | `wrt:verdict`, `wrt:declaredTimestamp` on the filing |
| `under[]` | `wrt:underPolicy` → `urn:wrt:blob:…`, typed `prov:Entity` |
| `prior[]` | `wrt:prior` → `urn:wrt:record:…` |
| `subject`, `evidence[]` | `prov:used` + `prov:qualifiedUsage` → minted `prov:Usage` with `prov:entity` and `sev:role` |
| `because[]` prose | `wrt:prose` literal |

On the live Warrant store this takes the graph from **811 to 1081 quads**,
and the records stop being opaque: actor, policy, lineage and the filing's
own prose are now in the evidence view.

## Three decisions worth stating

**Every fact is licensed by byte identity.** A record reaches this code only
when `computed_wid == claimed_wid`, so its body is exactly what the
WarrantID commits to. That is the strongest license available and the only
one claimed — nothing here rests on the receipt's opinion.

**No promotion.** The profile marks actor and policy "promotable". Promotion
is a claim about *identity* — that this key belongs to this actor, that this
policy governed this filing — and the receipt licenses neither. So
`L-NOMAP` is replaced by **`L-NOPROMOTE`**, which names the direction that
is missing instead of claiming nothing is mapped. `prov:Agent`,
`prov:wasAttributedTo`, `prov:Association` and `prov:hadPlan` appear nowhere,
and a vector asserts it.

**Role-keyed Usage identity.** The same blob can be a record's `subject`
*and* appear in its `evidence[]`. Keying the `prov:Usage` node on
`(filing, role, target)` keeps those two claims distinct while the underlying
entity stays one node — merging them would erase precisely the distinction
qualification exists to carry.

## Reading the committed body without re-reading the store

The mapping needs the whole body; the validated view carried only `because`.
Re-reading the CAS is forbidden (an earlier round found that a stateful
resolver could hand the projector different bytes than the verdict judged),
so the view gained a `body` channel next to `committed`.

That touches `snapshot_model.py`, whose receipt-core **contract** is frozen.
The freeze covers verdict semantics — "receipt core invariants, envelope/body
binding, counts, source union, acknowledged invalid evidence" — and an
additive output channel changes none of them. Rather than assert that, it is
now **guarded permanently**: `view_is_output_only()` runs a nine-case corpus
(valid, trailing data, BOM, truncated, non-object, duplicate member, empty,
scalar snapshot, lone surrogate) with and without a view and requires
identical findings. If any verdict ever varied with `view`, the channel would
have become an input and every future extension of it would be a silent
change to a frozen contract.

## Two defects in existing vectors, found by the change

Both were guards that passed only because the MVP emitted so little:

- *"no PROV execution relation hangs off it"* scanned the **whole document**
  for `prov#used`. The §4.1 filing uses broke it. Rewritten to the
  assessment's own triples — as its name always claimed — plus a check that
  the scoped view is non-empty, so it cannot pass by selecting nothing.
- *"a receipt-reported signature is absent from the graph"* tested the
  absence of the **actor string**. `wrt:claimedActor` legitimately puts that
  string in the graph. Rewritten to the thing actually claimed: no
  `wrt:Signature`, no `wrt:sigValid`, no `wrt:binding`, no attribution.

A third was mine, caught by mutation: I asserted
`_prov_violations(...) == []` against a function returning a **set**, which
is vacuously false — it would have "failed" on a perfectly clean graph.

## Registry correction

`prov:entity` was absent from the predicate registry, so it could not be
declared. Adding it required the PROV `Influence` splits: `prov:entity` has
domain `prov:EntityInfluence`, `prov:agent` has domain `prov:AgentInfluence`.
Registering only `Influence` would let an Association carry a `prov:entity`
and a Usage carry a `prov:agent` — the root-kind-instead-of-concrete-class
defect earlier rounds found twice. `Usage ⊑ EntityInfluence`,
`Association, Attribution ⊑ AgentInfluence`.

## Mutation results

13/15 detector mutations fail the suites: role dropped from Usage identity,
prior keyed as a blob, actor promoted, `sev:role` omitted, `qualifiedUsage`
omitted, one usage unlinked, evidence dropped, `L-NOPROMOTE` undeclared,
Usage untyped, body mapping skipped, view carries no body, verdict reads the
view, and the coarse-guard rewrite.

Two are **labelled, not counted**. The `view` deep copy is defense in depth:
the parsed envelope is local to the verdict and discarded on return, so no
second reader exists for a caller to corrupt, and removing the copy changes
no result. A vector claiming otherwise was written first and **deleted as
vacuous** — it passed with the copy and without it, because every run
re-parses from bytes anyway.

## State

98 model + 264 projector + 11 fixtures + 29 adapter, all green, exit status
honest. Live store: 81 sources, 1081 quads, 0 errors / 16 warnings.

**Still not emitted, still declared:** signatures (`L-NOSIG`), settlement
(`L-NOSETTLE`), promotion (`L-NOPROMOTE`), issues on projected sources
(`L-NOISSUE`). Signatures are the natural next step and carry their own
honesty rule — attribution only when `valid AND bound`, `wrt:claimedSigner`
otherwise.
