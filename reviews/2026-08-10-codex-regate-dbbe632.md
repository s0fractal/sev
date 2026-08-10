# Re-gate of `dbbe63291…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `dbbe63291dd847a7d635e9fc9ab6ecbc309c4917`. Baseline
confirmed: 58 model + 28 projector + 9 fixtures green, and the five prior
fixes hold. Two new P1s. No GitHub write or merge actions by the reviewer.

Both defects again let the **receipt decide what the graph asserts or omits**
— the same boundary, now one level lower: not what a reason claims, but what
a *source* is.

## Findings → dispositions (same PR, narrow closure)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | Source-role confusion: `kind` was enum-checked but never derived from the Warrant store layout. A committed record could be relabelled `other` (the record vanishes, the graph asserts a generic entity, `ok:true`, `projected=2`); a blob could be called `genesis`; `claimed_wid` was free text unbound from the filename, so `records/aaaa….json` could be reported id-sound under a different WarrantID | `classify_warrant_source(path, prefix)` derives the role from the layout (`records/<hex64>.json` → record + that claim; non-wid name → record with a null claim; `blobs/*` → blob; `genesis.json` → genesis; else other). The composed verdict compares derived vs reported: `SOURCE_KIND_MISMATCH`, `CLAIMED_WID_NOT_PATH`. The receipt now *reports* a role it cannot *choose* |
| 2 | P1 | The view-manifest kept a mutable alias on `src["issues"]`, so mutating the input receipt after projection rewrote already-issued evidence (`output_changed_after_input_mutation=True`) — contradicting the declared pure-function model | Exclusions deep-copy the issue multiset at emission; vector mutates and appends to the receipt after projecting and asserts the manifest is byte-identical to what was issued |

Six permanent vectors added: three classifier unit cases, record→other,
blob→genesis, filename-WID mismatch, plus the post-projection mutation
control and a projector-level refusal (a relabelled record yields no graph
at all). One fixture had to be corrected in the process: the "honest
negative receipt" case previously set `claimed_wid: null` on a file named
`<wid>.json` — under the new rule that is itself a lie, so the fixture now
models an id-unsound record the honest way (the filename's claim stands, the
body canonicalizes elsewhere).

Profile synchronised with `projection_reason` and the generic-source
mapping.

## State after closure

64 model + 30 projector vectors + 9 fixtures, all green, exit-status honest.
The freeze criterion (a round with zero P1) is **not** met; merge stays held
pending another exact-SHA re-gate.
