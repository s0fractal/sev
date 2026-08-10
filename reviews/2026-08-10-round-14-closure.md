# Round 14 closure — Kimi, target `f92f7ee` (PR #4 head), verdict AMEND

Reviewer verdict: **1 P1, 5 P2**, adapter-only; no frozen surface touched.
All findings reproduced by execution before any change was made. Closed on
`author/live-warrant-adapter`; **merge remains the reviewer's call**, and a
re-gate against the fix SHA is expected.

## P1 — the adapter died on exactly the evidence the frozen core exists to represent

Reproduced both stated vectors against `f92f7ee`: a record file containing
`b"{"` killed the child process (`RuntimeError` out of the subprocess), and
`b"\xff\xfe"` never survived `.decode("utf-8")`. `signature_verdicts` ran
over **every** record file before anything was parsed.

The reviewer's contrast is the part worth keeping: the frozen receipt core
*can* express this honestly — an acknowledged `RECORD_UNREADABLE`/ERR gives a
clean verdict plus an exclusion — so the first real producer of receipts
could not emit what the frozen contract accepts. Not a crash bug; a producer
that could not reach a legal state of its own format.

**Disposition.** Parsing moved first: pass 1 parses every record, pass 2 asks
Warrant only about envelopes that parsed. Verified on seven corruptions
(truncated, non-UTF-8, empty, wrong top-level shape, `sigs: 5`, `sigs: [1]`,
`because: 7`) — each now yields an honest negative receipt, clean verdict,
record excluded.

Two defects surfaced *while* fixing it, both found by the format rather than
by intent:

- `MALFORMED_ENVELOPE_UNREPORTED` at `/core/sources/65/sigs` — the model
  distinguishes `/sigs` (container not a list → `MALFORMED_ENVELOPE`) from
  `/sigs/N` (entry not an object → `MALFORMED_SIGNATURE`); one code for both
  left `sigs: 5` unreportable.
- A first attempt also reported malformed-reason pointers. It was **dead
  code**: every shape yielding `reason_malformed` also fails
  `body_schema_findings`, so the branch could not run. Removed, and the
  subsumption is now vectored — an unreachable guard that looks like coverage
  is precisely what rule 7 forbids counting.

## P2 — five, all accepted, one with the reviewer correcting the author

| # | Finding | Disposition |
|---|---|---|
| 1 | Unknown `level` silently became WARN | `UnknownFindingLevel`, fail closed. Guessing the milder judgement is the same defect as guessing a code from prose |
| 2 | `IndistinguishableFindings` refused a **legitimate** state (two unresolved blobs on one record); the "cannot represent" note was wrong — the locator union already carries `occurrence` | Reviewer is right and the note is withdrawn. Ordinals assigned; the exception is gone. Two same-class findings now survive as two distinguishable, valid locators |
| 3 | Adapter outside CI | Added; the live half prints SKIP on a runner while the classification table, locator union, fail-closed paths and not-quieter invariant still gate |
| 4 | Latent `cmd@v1` assumption | `not-applicable` is legal only for a runtime the contract says a verifier does not re-run. It was hardcoded and happened to be true of this store; the first `ski@v1` reason would have made it `NOT_APPLICABLE_BUT_EXECUTABLE`. Now derived, with `unverified` + `RUNTIME_UNAVAILABLE` + the WARN joined at that exact pointer for executable runtimes |
| 5 | Crash hygiene | `ASK_TIMEOUT`; refusals print `REFUSED <Type>: <detail>` and exit 1 instead of a traceback |

## Two things the fixes then exposed

**The classification table was parochial.** It covered the two message shapes
this machine's healthy store emits. Re-derived from every `out(level, wid,
msg)` call site in the reference implementation — 27 classes. The sweep still
missed one (`ski@v1 unverified`, emitted from the runtime-handler boundary
rather than the core reporter), and **the fail-closed path caught it**, which
is the whole argument for failing closed.

**An orphan finding had no valid locator.** Findings about `store` /
`settlement` / `genesis` / `trust` now use the union's `global` kind; a
subject matching no sealed record lands on `store` rather than being written
as a path the format rejects. The old code would have produced
`BAD_ISSUE_SHAPE`, and no vector caught it because `selftest` never validated
what the join built. It does now.

**A guard read prose instead of code.** The ownership check was a substring
scan and failed the moment a comment mentioned `verify_sig`. Rewritten over
the AST: no signature machinery imported, no verifier called.

## Mutation results

12/14 detector mutations fail the suites. The two that do not are **labelled
in code, not counted**: the subprocess timeout, and the child's per-signature
`None`. Neither is isolatable — `verify_sig` is total on every hostile
signature shape tried (bad hex, short key, non-string, missing field: all
return `False`, none raise), and nothing here can make a subprocess hang on
demand. What *is* covered is the parent's refusal to read a non-boolean
answer as `False`, which is the clause that would otherwise have SEV assert a
verdict Warrant never gave.

Ownership-boundary guard: proven by introducing the violations (importing
`warrant`, calling `verify_sig`) — both caught. Removing the guard with no
violation present cannot fail, and is not claimed as covered.

## State

98 model + 250 projector + 11 fixtures + **29 adapter** checks, all green,
exit status honest. Live store still seals and projects (81 sources, 811
quads, 0 errors / 16 warnings — matching Warrant's own report exactly).

**Not done, deliberately:** no merge, no freeze, no WRT-003.
