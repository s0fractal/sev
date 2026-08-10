# Re-gate of `b9cd5397…` — Codex, 2026-08-10 — **artifact-scoped verdict**

Target: PR #1 head `b9cd539706e13aed392198027a87931bd518aab8`. The first
round graded per artifact, which is what the split was for:

| Artifact | Verdict |
|---|---|
| snapshot/receipt core | out of scope this round, **no new finding** |
| MVP projector | emitted graph **not refuted**; 64 + 155 + 9 PASS |
| full `sev@v0` target profile | **AMEND — P1** |

## P1 (target profile) — shapes expressed root kinds, PROV requires classes

The shapes file unified classes and predicates, but its endpoint language
`[kind, kind]` was too coarse for PROV's qualified relations. Every wrong
form was accepted:

```
Usage_hadPlan_Entity                    got=set()
Activity_qualifiedUsage_Association     got=set()
Activity_qualifiedAssociation_Usage     got=set()
Entity_qualifiedAttribution_Usage       got=set()
Entity_hadMember_Entity                 got=set()
```

PROV-O's real ranges are `qualifiedUsage → Usage`,
`qualifiedAssociation → Association`, `qualifiedAttribution → Attribution`,
`hadPlan: Association → Plan`, `hadMember: Collection → Entity`.

**Disposition.** The shape language now allows `{"kind": …}` **or**
`{"class": …}`, a class requirement being satisfied by that class or any
declared subclass; `prov:Collection` was added to the hierarchy. The machine
keeps each node's **full class ancestry** instead of reducing it to a root
kind at read time — that reduction was what made exact-class endpoints
impossible to express. The artifact now **validates itself**: dangling
parents, cycles, classes that reach no declared root, unknown endpoint
classes or kinds, empty endpoints, and MVP predicates absent from the target
set are all findings, asserted by a vector before anything trusts the file.

Ten shape vectors: the reviewer's five wrong forms, plus four positive
controls, plus one isolating the `hadPlan` **subject** class specifically
(a Usage → Plan graph, so relaxing the subject alone is detectable).

## Mutation results

| Element | Suite when removed/relaxed |
|---|---|
| exact class on `qualifiedUsage` (→ kind) | fails |
| exact class on `hadPlan` subject | fails — after the isolating vector was added; it was vacuous before |
| exact class on `hadMember` subject | fails |
| full ancestry retention | fails |
| a deliberately broken shapes artifact (dangling parent) | fails |

## State after closure

64 model + 164 projector vectors + 9 fixtures, all green, exit-status
honest. Per artifact: the snapshot/receipt core and the MVP projector
carried no finding this round; the target profile has one closed P1.
