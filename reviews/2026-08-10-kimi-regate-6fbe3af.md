# Re-gate 7-K — Kimi, 2026-08-10

**Tree state:** commit `6fbe3afd30341b90df0f21394641f3e3b3f73a28`
(PR #1 head), working tree clean. Re-gates round 7 (`18283bf`).
**Method:** all three harnesses re-run (90 model + 172 projector + 11
fixtures, all exit 0); every round-7 finding re-probed against this head,
not taken from the closing report.

## Dispositions

- **P1-1 (parser totality) — closed, verified.** `parse_strict` returns
  `OVER_DEPTH` (finding, no host exception) for nested arrays at depth
  500 / 5000 / 200000 and for a deep object at 600. The end-to-end CAS
  path reproduces as findings (`RECORD_UNREADABLE`,
  `REASON_PTR_UNRESOLVABLE`), not a crash. The hidden defect the author
  confessed — `jcs`'s list branch dropping `_depth` — is genuinely fixed:
  both branches thread it (`snapshot_model.py:88,95`). Corpus now includes
  `over-depth` and `malformed-syntax` (11 fixtures, full refusal set).
- **P1-2 (UTF-16 ordering) — closed, verified.** `unjudged`
  (`sev_projector.py:365`) and `Graph.nquads` (`sev_projector.py:92`) both
  sort via `path_sort_key`; a permanent vector probes an astral literal
  through a real projection ("quad ordering is UTF-16 too").
- **P2-2 (fixture coverage) — closed.** `NOT_JSON` and `OVER_DEPTH` pinned
  language-neutrally.
- **P2-3 (rev anchors) — closed.** Companions deliberately unpinned with
  the same decay caveat as section numbers.
- **P2-4 (ledger) — closed.** Round 7 row records both SHAs; the response
  is appended to the round file, round and closure in one document.

## Residual finding (new, P2)

**P2-1 is only partially closed.** `README.md:34` still reads
"56 self-vectors" — the one occurrence the cleanup missed. Worse, the new
guard (`sev_projector.py:2010-2020`) cannot see it: its pattern
`\b\d+\s+vectors?\b` requires digits immediately followed by "vectors", so
the hyphenated "56 self-vectors" passes. The guard is green over prose
that still carries the stale count — the same vacuous-guard class the
author's own confession names, this time caught by reading the line rather
than trusting the vector. Fix: drop the number from the table row, and
widen the guard (e.g. `\b\d+\s+\S*vectors?\b`) or grep for `\bvectors?\b`
near any digit.

## Verdict

**Zero P1 at this head** — under the spec §7 criterion the freeze decision
is now a maintainer act with no reviewer objection from this round. The P2
residual above does not block a freeze of the *byte contract* (it touches
prose honesty, not the frozen surface), but it should be fixed before the
freeze is announced, because the announcement will quote the README.

---

## Response — P2 residue closed (author, 2026-08-10)

Confirmed by reading the line and re-running the guard: `README.md:34` did
still say "56 self-vectors", and the guard's `\b\d+\s+vectors?\b` demanded
`vectors` immediately after the number, so the hyphenated form walked past
it. The guard was green over prose containing exactly what it exists to
forbid.

- The number is gone from the contents table (not corrected — the same rule
  as the earlier cleanup: prose carries no count).
- The pattern is widened to `\b\d+\s+\S*vectors?\b`, so prefixed and
  hyphenated forms are caught.
- The guard's scope is now stated in code: **live prose only** (README, CI).
  Round ledgers and review files legitimately carry counts, because each is
  a dated claim bound to one SHA — scrubbing those would rewrite history
  instead of keeping it honest.

Mutation results:

| Mutant | Result |
|---|---|
| reintroduce "56 self-vectors" with the widened pattern | **fails** — the guard catches it |
| reintroduce it *and* narrow the pattern back | **passes** — which is precisely the blindness this round found, and the reason the widening is load-bearing |

Second time a guard of mine was green over the very thing it forbids. The
first was caught by mutation testing; this one by a reviewer reading the
line. Worth recording that mutation testing did not find it: I only mutated
the *inputs* the guard reads, never the *pattern* itself.
