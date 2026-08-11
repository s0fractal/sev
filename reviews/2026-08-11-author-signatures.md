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

---

# Round 17 closure — Codex, target `5315f6a` (PR #6), verdict AMEND

**3 P1 + 1 P2 + a stack blocker.** All reproduced before any change. Base
updated rather than merged: landing #5 is a governance act, and the reviewer
offered "land or rebase" — rebasing keeps that decision where it belongs.

## Stack blocker — rebased onto `9a3df58`

Two conflicts, both resolved toward the base: the signatures branch predated
the round-15/16 coverage work and would have re-introduced the defect that
round closed. The rebase also surfaced a **duplicate**
`declared − emitted = ∅` check — one from each branch — and the base's copy
was the weaker: it took its union over `res_body` alone, so
`prov:wasAttributedTo`, emitted only on the promotion path, read as an
over-declaration. The stronger version survives.

## P1-1 — receipt judgements leaked into the default graph

Confirmed. `sigValid`, `binding`, `claimedSigner`, the agent node and the
attribution were all emitted without `vgraph`. Two honest receipts over the
same signature — one `unverified`, one `bound` — union into a single node
carrying **both bindings**, with nothing to say which `receipt_core_digest`
asserted which.

**The profile already required this** (§5: the verification graph holds
"signature validity/binding"). The implementation was in breach of it, not
ahead of it.

**Disposition.** Mechanical topology — type, multiplicity, the
record→signature edge, all derivable from the sealed bytes and identical
under every receipt — stays in the default graph. Every receipt-derived
assertion moved to `urn:sev:g:verify:<core_digest>`. The two-receipt union
vector now shows two binding statements on one node in two graphs, while the
type statement collapses to a single shared line.

**A second defect in my own fix, found by mutation.** The first guard watched
`wrt:binding` only — so `sigValid`, the agent node and the attribution
leaked past it. Checking one predicate covers one predicate. The guard now
enumerates every receipt-derived term and states the rule once over all of
them; four separate leak mutations each fail.

## P1-2 — excluded signatures counted as emitted

Confirmed on a clean `ID_UNSOUND` receipt: one signature entry, zero
signature nodes, no `L-NOSIGNODE`, `signature` absent from `not_emitted`, and
an `L-UNBOUND` describing a `wrt:claimedSigner` **that exists nowhere in the
graph**.

**Disposition.** Both are counted from nodes the projection actually emitted
(`emitted_sig_occurrences`, `unattributed_nodes`) rather than from receipt
entries. `L-UNBOUND` is scoped to signature nodes that exist — a loss
describing an absent node is a caveat on an absent fact, which is the thing
this manifest exists to prevent.

## P1-3 — code and profile minted different IRIs

Confirmed: `urn:wrt:signature:<opaque sha256>` and `urn:sev:agent:<sha256>`
against the profile's `urn:wrt:sig:<sig_digest>:<multiplicity>` and
`urn:wrt:actor:<pct-encoded>`.

**Resolved as recommended — the contract is amended where the code's
instinct was right, and the code yields everywhere else.**

- **Signature:** `urn:wrt:sig:<WID>:<sig_digest>:<multiplicity>`. The WID is
  now normative, because the same *invalid* `{actor,key,sig}` can be replayed
  into several records; without it two records share one node and each
  receipt's judgement overwrites the other's. Vectored.
- **Components stay visible.** Hashing the triple into one digest destroyed
  the join a consumer needs on `sig_digest`. A vector asserts the IRI
  component by component and that `sig_digest` survives as a substring.
- **Actor:** the code now mints `urn:wrt:actor:<pct-encoded>` per the
  profile. Encoding pinned to UTF-8 bytes with an **empty safe set** — the
  default safe set of most URL encoders is library-dependent at exactly the
  characters an actor id carries. A Cyrillic actor id with `/` and `@` is
  vectored against the exact expected octets.

## P2 — contradictory loss taxonomy

Confirmed: `L-SIG` appeared in both families and `L-UNBOUND` sat among the
absence codes while the projector appends both to `qualified`. `L-SIG` and
`L-UNBOUND` are now qualifying codes; `L-NOSIGNODE` alone is the absence,
and its text was widened to name both ways a node can be missing.

## Mutation results

16 mutations of the changed detectors; 15 fail. The one that does not
neuters an assertion into a tautology, which cannot fail without a defect
present — the honest form of that test is the four leak mutations, which all
fail.

## State

108 model + 300 projector + 11 fixtures + 29 adapter, all green. Live store:
81 sources, 1177 quads, 0 errors / 16 warnings.
