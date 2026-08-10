# §4.1 signatures — Claude (author), 2026-08-11

> **NOT A GATE.** Author implementation with a self-review; counts toward no
> freeze criterion. Stacked on `author/body-mapping` (PR #5), which is itself
> awaiting an independent round — **gate that one first**. Only unfrozen
> surfaces move.

## The rule this implements

The profile's §4.1 signature row is the sharpest honesty rule in the
document, and it is the whole reason this block is small:

> `prov:wasAttributedTo` the named agent **only when `valid:true` AND
> `binding:"bound"`** — validity proves *this key signed this WarrantID*, not
> *this key belongs to this actor*; valid-but-unbound emits
> `wrt:claimedSigner` instead.

So: every signature becomes a `wrt:Signature` node carrying `wrt:sigValid`,
`wrt:binding` and its multiplicity, linked from the record by
`wrt:hasSignature`. An agent node is minted **only** on the bound path — and
minted nowhere else, which is what makes minting it from the actor string
safe: the graph cannot contain an agent no binding vouched for.

Attribution attaches to the **signature**, not the record. One bound
signature establishes that this agent made this signature; claiming they
authored everything the body says is a larger claim than the evidence
carries.

## What the live store says

1081 → **1177 quads**. Every one of the 16 records now carries its
signature — and **not one agent is attributed**, because Warrant's own
verifier reports `binding unverified (no keyring)` for all of them. The
chain holds end to end: the owning protocol cannot bind keys to actors
without a keyring → the receipt copies `binding: "unverified"` → the graph
attributes nobody → `L-UNBOUND` declares exactly that.

## Loss codes: one blanket code replaced by three precise ones

`L-NOSIG` said "this MVP emits NO signature nodes at all". That is now false,
and leaving it would be a caveat on facts that are present — the failure
class this manifest exists to prevent.

| Code | Says |
|---|---|
| `L-SIG` | validity and binding are **copied** from the receipt; SEV performs no cryptography and re-derives neither |
| `L-UNBOUND` | *n* signatures are not both valid and bound, so no agent is attributed |
| `L-NOSIGNODE` | malformed signature occurrences are carried as issues, not entries, and get no node |

`coverage.not_emitted` follows: `signature` only when an occurrence really
has no node, and a new `attribution` entry whenever promotion was withheld —
otherwise `wrt:claimedSigner` reads as an oversight rather than a refusal.

## A state that cannot exist, and a clause kept anyway

`valid: false, binding: "bound"` is refused by the receipt core outright
(`BINDING_WITHOUT_VALIDITY`), so a projector can never see it. That makes the
`valid is True` half of the promotion test **redundant today**. It is kept
so the rule reads as the profile writes it rather than leaning on an
invariant in another module — and since no vector can isolate it, it is
labelled in code and **not counted**. What *is* vectored is the
unrepresentability itself, so the day that rule changes, the suite says so.

## The declaration was honest in only one direction

The existing parity check asserted *emitted − declared = ∅*. Adding
`prov:wasAttributedTo` — which no default fixture emits, since nothing is
bound there — would have **over-declared silently**: the mirror image of the
defect this repository keeps finding. A second check now asserts *declared −
emitted = ∅* over a union of fixtures chosen to exercise every
PROV-emitting branch, and a mutation adding an unemitted predicate to
`mvp_predicates` fails the suite.

## Mutation results

17/17 detector mutations fail the suites: promotion without binding,
promotion always, `claimedSigner` fallback removed, binding not copied,
`sigValid` not copied, signature untyped, agent untyped, record→signature
link cut, multiplicity dropped from the IRI, `L-SIG` / `L-UNBOUND` /
`L-NOSIGNODE` undeclared, over-declaration undetected, and the four from the
body-mapping block re-run.

Three of these existed only because the first battery found them uncovered —
duplicate-signature identity, the record→signature edge, and the agent's
type all needed vectors that the default fixture could not provide.

## One incident worth recording

`resB` in my §4.1 vectors collided with an existing `resB` later in the same
2000-line `run_vectors`, so my new check silently read a **rebound, None**
value. It surfaced as a `TypeError`, not as a wrong pass — but a shorter
distance between the two uses and it would have been a vector quietly
asserting over the wrong graph. Locals renamed to `res_body` &c.

## State

98 model + 285 projector + 11 fixtures + 29 adapter, all green, exit status
honest. Live store: 81 sources, 1177 quads, 0 errors / 16 warnings.

**Still not emitted, still declared:** settlement (`L-NOSETTLE`), promotion
(`L-NOPROMOTE`), issues on projected sources (`L-NOISSUE`), malformed
signature occurrences (`L-NOSIGNODE`).
