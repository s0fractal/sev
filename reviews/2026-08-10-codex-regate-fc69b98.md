# Re-gate of `fc69b989…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `fc69b9898e0217df8b92f18164f7171338f40c4e`. Previous
countervectors confirmed closed; the flagship graph is semantically clean.
Baseline 64 + 139 + 9 green. One P1, and the reviewer's explicit
instruction: stop patching locally — the next guard must be a small formal
type-closure machine.

## P1 — the guard checked membership, not type closure

`return want not in have` accepted a node whenever the wanted kind was
present, so a forbidden kind alongside it was excused:

```nquads
<urn:x> rdf:type prov:Activity .
<urn:x> rdf:type prov:Entity .
<urn:run> rdf:type sigma:CheckRun .
<urn:run> prov:used <urn:x> .
```

passed cleanly, although PROV-O declares `prov:Activity owl:disjointWith
prov:Entity`. The same hand-kept list produced the mirror defect —
false *positives*: `oaip:Execution`, `oaip:Validation`, `bos:Trajectory` and
`wrt:Adjudication` are Activity (or Activity-subclass) in this profile, and
valid target graphs using them were rejected.

**Disposition — a declarative type model, per the reviewer's closure plan.**

1. One machine-readable hierarchy `class → parent` covering the whole target
   profile, with the three disjoint PROV kinds as roots.
2. `_kind_of_class()` resolves a class through its transitive closure
   (`wrt:Adjudication → wrt:Filing → prov:Activity`).
3. **Disjointness is decided first**, over the closure: a node whose types
   close to more than one root is a `("disjoint", …)` finding before any
   position is examined.
4. A position then requires *exactly* the wanted kind (`have == {want}`),
   not mere presence.
5. Profile guard vs MVP guard made explicit: the registry describes the full
   target `sev@v0`, and a vector asserts every class the projector actually
   emits is registered.

Vectors: Activity ∩ Entity rejected (both as a disjointness finding and in
the position); each declared target Activity subclass accepted in its own
position; `wrt:Adjudication` resolving to `activity` through its parent; and
the MVP-emits-only-registered-classes check.

## Mutation results

| Guard element | Suite when removed |
|---|---|
| disjointness-first pass | fails |
| exact-kind position check (`== {want}`) | fails |
| the `wrt:Adjudication → wrt:Filing` edge | fails |
| the `oaip:Execution` edge | fails |
| the `bos:Trajectory` edge | fails |

Every subclass edge is load-bearing, which is what the reviewer asked the
design to guarantee.

## State after closure

64 model + 146 projector vectors + 9 fixtures, all green, exit-status
honest. Freeze criterion still unmet.
