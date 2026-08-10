# Round 5 — Codex, 2026-08-10, verdict AMEND

Target: model v2 + snapshot rev 3 + receipt rev 4. Tree: unversioned
(final pre-repo state; the repository bootstrap 9fe95d7 landed the
dispositions of this round).

P1: both "total" validators crashed on hostile shapes; receipt unbound from
snapshot universe (empty sources[] vs populated subroot = silent truncation
survived); raw JSON boundary absent (duplicate members/trailing/NaN/floats/
lone surrogates invisible post-json.loads); arrays without canonical order;
CAS skipped `unclaimed`; implications not occurrence-bound (two mismatches,
one issue); sum type without domains (potato verdict, negative ATP); grade
absent from severity.
P2: locator union not validated as a union; descriptor schema not fully
closed by the model.

Disposition: model v3 — raw-byte strict parsers as sole conformance
entrypoints, total validators + seeded fuzz, composed
validate_warrant_receipt with exact bijection, normative order for all
arrays, per-occurrence joins, closed domains, grade-aware severity.
Snapshot rev 4, receipt rev 5. 56 vectors. Full table: profile appendix
"round 5".
