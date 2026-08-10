# Re-gate of `854ff6f8…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `854ff6f812058e7ba3923986188d3ac3f080a263`. Baseline
64 + 111 + 9 green; the decision not to implement Ed25519 in SEV was
supported. One P1 — a contradiction created by the previous round's own
honesty fix.

## P1 — the receipt reported every actor signature invalid and still said `ok: true`

After `valid: false` became the honest fixture value, the shipped state was:

```
body.actor.id = signer@example
signatures    = [{actor: signer@example, valid: false}]
issues        = [INVALID_SIGNATURE / WARN]
core          = {ok: true, errors: 0, warnings: 1}
```

→ zero findings, record projected, `sources_excluded: 0`. The record was
projected while its own receipt said nothing had validly signed it. No
cryptography is needed to see this: the contradiction is entirely inside the
producer-asserted core, since warrant SPEC §5 makes a record with no valid
actor signature an error.

**Disposition — a one-way internal-consistency rule.** If the receipt
reports no `valid: true` signature whose `actor` equals the committed
`body.actor.id`, it MUST carry an ERR `NO_VALID_ACTOR_SIGNATURE`
(`NO_VALID_ACTOR_SIGNATURE_UNREPORTED` otherwise). This does not make
`valid: true` trustworthy — SEV still verifies nothing — it only forbids a
receipt from disagreeing with its own negative claims.

**And the positive path moved onto evidence someone vouches for**, which was
the reviewer's preferred option 2. `conformance/upstream/` now vendors
`warrant/examples/accept.warrant.json` verbatim, with provenance and digest
recorded; the reviewer's observation that upstream's own reference
implementation returns `verify_sig → True` for it is recorded as provenance,
not re-derived here. The flagship `fixture()` is built on those bytes: a
record whose signature the owning protocol vouches for, whose committed
reason is a `cmd@v1` check (normatively not re-executed → `not-applicable`).
The old synthetic record survives as `ski_fixture()` for vectors that need a
projected check run, explicitly labelled as carrying a producer claim SEV
cannot verify — contract-legal precisely because the rule is one-way.

Vectors: only-actor-signature invalid with WARN only → refusal; the same
reported as ERR → accepted with the record excluded; a valid signature by a
different actor → refusal; zero reported signatures → refusal; the vendored
upstream record → clean positive projection with the record in the graph.

## Mutation results

| Guard | Suite when removed |
|---|---|
| aggregate `NO_VALID_ACTOR_SIGNATURE` rule | fails |
| vendored-fixture digest pin | *passes* behaviourally — the model recomputes everything from whatever bytes it is given, so altered bytes stay self-consistent. Closed by an explicit provenance vector instead: the bytes, the pinned constant and the digest in the provenance note must agree, and altering the vendored file now fails the suite |

## State after closure

64 model + 120 projector vectors + 9 fixtures, all green, exit-status
honest. Proposal rev 11 carries the one-way rule. Freeze criterion still
unmet.
