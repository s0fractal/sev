# Re-gate 14-K — Kimi, 2026-08-11

**Tree state:** commit `f81aa7281fb5981865ef7d7435eaae924166f355`
(PR #4 head, `author/live-warrant-adapter`), clean tree. Re-gates round 14
(`f92f7ee`). Method: every finding re-probed by execution against this
head; nothing taken from the closing report.

**Verdict: APPROVE — PR #4 eligible for merge.** Zero P1 at this head. The
change touches only unfrozen surfaces (adapter, MVP projector), so no
freeze is implicated. Merge itself remains a maintainer act.

## Re-probe results

**P1 (adapter crash on malformed evidence) — closed, verified.** Both
original vectors plus two more, executed against a synthetic store:

| Input | Verdict | Receipt carries | Record |
|---|---|---|---|
| `b"{"` | clean | `RECORD_UNREADABLE/ERR` | excluded |
| `b"\xff\xfe"` | clean | `RECORD_UNREADABLE/ERR` | excluded |
| `sigs: 5` | clean | `MALFORMED_ENVELOPE` + 3 more ERR | excluded |
| non-canonical bytes | clean | `BODY_SCHEMA_INVALID` + 2 more ERR | excluded |

The producer now reaches the legal states of its own format — the exact
property round 14 found missing. The author's two bonus discoveries
(`/sigs` vs `/sigs/N` code split; the dead malformed-reason guard removed
with a vector on its unreachability) are consistent with what I see in the
code.

**P2 closures — all verified in code or by execution:**

- Unknown report level raises `UnknownFindingLevel` — executed, refused
  (was: silent downgrade to WARN).
- Two same-class findings on one record now yield two distinguishable
  issues via the locator `occurrence` ordinal — executed; both locators
  pass `validate_locator`. `IndistinguishableFindings` is gone; the
  "cannot represent" note is retracted in the round file.
- Adapter selftest is a CI step (`model.yml:19`); live half SKIPs honestly
  on store-less runners, fixture half gates.
- `not-applicable` is derived from `NORMATIVE_NOT_EXECUTED`; executable
  runtimes get `unverified` + `RUNTIME_UNAVAILABLE` with a joined WARN.
- Subprocess calls carry timeouts; refusals print `REFUSED <code>` and
  exit 1 — no tracebacks on the refusal paths I exercised.
- Ownership guard now parses the AST instead of grepping prose.

**Mutation honesty:** 12/14 fail the suites; the two survivors (subprocess
timeout, child-side `None` verdict) are labelled unisolatable in code and
not counted — the house's stated-not-counted discipline, correctly applied.
The meaningful half (parent refuses to read a non-bool answer as False) is
covered.

**Harnesses at this head (run by reviewer):** 98 model + 250 projector +
11 fixtures + 29 adapter, all exit 0; live store sealed and projected on
this machine during the selftest (0 SKIP), matching Warrant's own report
(0 ERR / 16 WARN).

## Note for the ledger

The one-class observation from round 14 stands as a design note, not a
finding: a non-canonical-but-parseable record is silently tolerated
(re-derived from its re-canonicalized body; `entry_digest` binds the real
bytes, so nothing is misrepresented — but the receipt does not mention the
non-canonicality). If Warrant ever makes canonical storage normative, the
adapter should surface it as an issue. Not a blocker.
