# Re-gate of `b0a4c4f6…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `b0a4c4f6df5266e4364e52571aa8d2b8a662cd01`. Baseline
64 + 52 + 9 green; pairwise bijection, runtime uniqueness and the honest
`prov:used` rules hold. Two P1s and one P2.

## Findings → dispositions (same PR, narrow closure)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | The validated view froze only the committed `because[]`; the projector still read the caller's `receipt["core"]` (and `snapshot`) after the verdict. A two-phase mapping returning a clean core first and a poisoned one afterwards produced a graph with attacker semantics and a non-NodeHash result — the CAS TOCTOU was closed, the *object* TOCTOU was not | The composed verdict **freezes its inputs before judging them** (`_freeze`, private deep copies) and publishes them through the view (`view["snapshot"]`, `view["receipt"]`, `view["core"]`, `view["descriptor"]`, `view["committed"]`). The projector reads the view and nothing else — no receipt, no snapshot, no store |
| 2 | P1 | `CHECK_BLOB_ABSENT` tested membership in *all* source digests, so a check could "resolve" to a `.warrants/README` (`other`), to a record, or to a blob the manifest simultaneously excluded — the run asserting `prov:used` on a source the same output declared excluded | One predicate, `available_blob_digests(core)`: `kind == "blob"` **and** `loaded is True` **and** no ERR issues, within the selected subroot. Used by the verdict (`CHECK_BLOB_ABSENT`) and by the projector (`wrt:checkBlob`, `prov:used`) — one definition, one code path |
| 3 | P2 | The one-shot store test was vacuous: `OnceCAS.exhausted` was never set, so the old re-reading projector would also have passed | Replaced with `RevokedAfterVerdict`: `validate_warrant_receipt` is wrapped, the store is revoked **exactly at the verdict boundary**, and the vector asserts byte-identical output plus zero post-verdict reads |

## Mutation results (each guard, reverted individually)

| Guard | Suite when removed |
|---|---|
| input freeze (`_freeze`) | **fails** |
| projector reads the view | **fails** |
| availability: `kind == "blob"` | **fails** |
| availability: no ERR issues | **fails** |
| availability: `loaded is True` | *still passes* — see below |

The `loaded` clause cannot be isolated by any vector today: `loaded:false`
already requires an ERR issue (`UNLOADED_WITHOUT_ERR`), so the ERR clause
always fires first. It is kept as defense in depth and **labelled in the
code as unisolatable**, rather than being counted as covered — the same
no-silent-caps rule the rest of this repo applies to its gates.

The P1-1 vector was itself rewritten during closure: the first version
poisoned on the *second read* of `core`, which the view already pinned, so
it passed with the freeze removed. The honest form mutates the caller's
objects **at the verdict boundary** (the same shape as the revoked-store
test) and fails without the freeze.

## State after closure

64 model + 59 projector vectors + 9 fixtures, all green, exit-status honest.
Freeze criterion still unmet; merge stays held.
