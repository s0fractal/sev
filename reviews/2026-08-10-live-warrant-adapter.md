# Live Warrant adapter — first run against evidence SEV did not author

> **Status, stated first.** This is **author work with a self-review, not an
> independent gate.** AGENTS.md rule 7 requires a fresh reviewer; the author
> hunting their own work does not satisfy it and **cannot be counted toward
> any freeze criterion**. Nothing here is frozen, merged, or filed upstream.
> The three findings below were reproduced by execution against a real
> `.warrants/` store (16 records, 64 blobs, 1 genesis).

## Why this exists

Every vector this repository had was written by the same understanding that
wrote the code. That is a closed loop: a contract can be wrong in a way no
self-authored fixture reveals. The adapter seals a **live** Warrant store and
projects it, so the model meets evidence it did not shape.

It found three defects on the first run. All three are the house failure
class — **an artifact claiming more than it can support** — and none were
visible to 98 + 242 + 11 green vectors.

## F1 (P1, adapter) — the receipt was quieter than the protocol it reports on

Warrant's own `verify --json` over the intact store: **0 errors, 16
warnings** (`binding unverified (no keyring)` on every record). The adapter's
receipt: **0 errors, 0 warnings**. The projected graph therefore asserted 16
filings as unqualified, while the owning protocol had qualified all 16.

Deleting a blob that record `4820ba49`'s `evidence[]` commits to made it
sharper: Warrant reported `WARN unresolved blob 00eee1ed`; the adapter
reported nothing at all, because it sealed the store *as it found it* — an
absent blob simply left the universe, and absence read as cleanliness.

**Disposition.** The adapter now ingests `warrant.verify-report@v0` and
carries every finding into the receipt, joined to the record by WarrantID; a
finding matching no sealed record becomes a global issue rather than
vanishing. `assert_not_quieter` refuses to emit any receipt whose ERR/WARN
counts fall below the protocol's own. The report is bound by digest in
`producer.report_digest` — it is what the invariant measured, not decoration.

## F2 (P1, adapter) — dropping non-normative prose merged two distinct findings

Carrying the findings surfaced the next defect immediately, and the **format
caught it rather than the tests**: projection was refused with
`ISSUES_NOT_SORTED` at `/core/sources/68/issues/1`. Warrant's messages are
non-normative prose, so the first implementation used one generic code per
level — which made `binding unverified` and `unresolved blob` on the same
record **byte-identical issues**. The receipt would have under-reported by
exactly one fact, silently, and the duplicate rule is what stopped it.

**Disposition.** An explicit, auditable `FINDING_CLASSES` table maps observed
message prefixes to stable codes. Prose is still not carried (the issue
schema is closed to `{code, severity, at}`, and importing prose into an
evidence graph would grant it standing the source SPEC never gave it). Two
fail-closed guards: an unrecognized message raises `UnclassifiedFinding`
rather than being labelled with a class SEV does not understand, and any two
findings that would collapse to one issue raise `IndistinguishableFindings`.

## F3 (P1, MVP projector) — a projected source's issues vanish, undeclared

With F1 fixed the receipt carried 16 warnings and the graph was **byte-for-
byte unchanged** (811 quads, same digest inputs). No issue reaches RDF at
all. Exclusions carry their issues verbatim in the view manifest, so the
asymmetry was invisible: a source good enough to project looked unqualified
no matter what the receipt said. Nothing in `loss_manifest` or
`coverage.not_emitted` admitted this — `not_emitted` listed actor, evidence,
policy-plan, prior, signature, subject, and said nothing about issues.

**Disposition** (established policy: *declare, do not fake*). New `L-NOISSUE`
plus `issue` in `coverage.not_emitted`, emitted **only when a projected
source actually carries issues** — scoped by the exclusion set, so issues
belonging to an excluded source never raise it. An unqualified node is now
documented as not a clean one.

## Mutation results — detector mutated, not only its inputs

| Mutation | Suite |
|---|---|
| `L-NOISSUE` emission removed | fails |
| `issue` dropped from coverage | fails |
| detector pinned False / pinned True | fails / fails |
| exclusion scoping ignored (`if True`) | fails |
| exclusion issues no longer verbatim | fails |
| report ingestion removed | fails |
| no-quieter check removed / neutered | fails / fails |
| unmapped finding dropped | fails |
| ERR downgraded to WARN | fails |
| unknown message guessed instead of refused | fails |
| merge detector removed | fails |
| all findings given one code | fails |

14/14. Two of these existed only because the first battery found the
exclusion-scoping clause and the two classification clauses **uncovered** —
the live store produces neither an ERR finding nor an orphan subject, so
without synthetic vectors those branches would have ridden along untested.

## State

98 model + 250 projector + 11 fixtures, all green, exit status honest.
Adapter selftest: 12 checks, green, and honest on a machine with no store
(it prints SKIP rather than passing vacuously).

**Not done, deliberately:** no merge, no freeze, no WRT-003. The MVP
projector remains unfrozen; F3 is a change to it, so it needs an independent
gate before any freeze conversation. F1/F2 concern adapter code that no
frozen contract covers.

**Forwarded, not acted on:** the receipt's closed issue schema cannot
represent two findings of the same class at one locator. That is arguably
correct (codes should be meaningful), but it means any producer joining a
prose-messaged report must classify or refuse — worth a sentence in the
profile if the receipt is ever proposed upstream.
