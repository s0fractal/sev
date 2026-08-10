# Re-gate of `ecf7ea8c…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `ecf7ea8c827e02a2fe6bd04cacce110a1fef579d`. Baseline
confirmed honestly green (model, projector, 9 language-neutral fixtures,
GitHub checks). Three new P1s reproduced by execution; no GitHub write or
merge actions taken by the reviewer.

The layer is stable now: every finding this round is again on the
**receipt → asserted-graph** boundary — what the projection asserts versus
what the receipt actually licenses.

## Findings → dispositions (same PR, narrow closure)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | Undeclared runtime earns authority: a fully committed reason with `runtime: evil@v1` passes while `execution_policy` declares only `ski@v1`; the ceiling check was gated on `rt in runtimes`, so *absence* was not an error, and the graph asserted `evil@v1` with no `semantics_digest` and no budget | `matched`/`mismatched` now require the runtime to be declared (`RUNTIME_NOT_DECLARED`). Deliberately no `continue`: role-binding still runs, so a swapped runtime reports both the lie and the missing licence. Model + projector vectors (the projector refuses entirely — no graph) |
| 2 | P1 | Exclusions lost evidence again: the projector collapsed the ordered issue multiset into a `set` of codes, so two `ID_UNSOUND` at different occurrences became one row and locator/severity/multiplicity vanished — contradicting the profile's structured `issues[]` requirement | Exclusions carry the receipt's `issues[]` **verbatim**; the projector's own skip reason moved to a separate `projection_reason` field, never merged into them. Vectors: verbatim equality, separation, and two-occurrence survival |
| 3 | P1 | `blob`/`genesis`/`other` counted as projected but silently absent from the graph (`continue` on the non-record branch) — the same silent-truncation class on the other union branch | Every loaded non-record source now emits a generic `prov:Entity` with `sev:sourceKind` and `sev:entryDigest`, so "projected" means projected. Vector: a `kind:"other"` source appears in the graph and the counts say so |
| 4 | P2 | The empty-fixture guard had no permanent negative selftest — reverting it would leave CI green | Subprocess control: `replay.py` over an empty corpus must exit 1 and say "vacuous" |
| 5 | P2 | `profile_revision`/`projector_digest` were only shape-checked (`hex64`), which a constant satisfies | Tests now assert **equality with the real file digests**; verified non-vacuous by mutating the projector to emit `"0"*64` — the guard fails as it must |

## State after closure

58 model vectors + 28 projector vectors + 9 fixture cases, all green,
exit-status honest. Awaiting: another exact-SHA re-gate, then APPROVE, then
merge (a human act).

R7 (`protocol-ecosystem#1`) and the Warrant visibility notice
(`warrant#19`) were noted as correctly ordered but were not gated in this
pass.
