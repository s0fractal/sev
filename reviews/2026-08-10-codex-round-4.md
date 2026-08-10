# Round 4 — Codex, 2026-08-09/10, verdict AMEND

Target: model v1 + snapshot rev 2 + receipt rev 3. Tree: unversioned.

P1: the model's harness accepted falsy returns as PASS (`lambda: False`
passed — demonstrated by execution), `expect_raise` ignored the named code,
no real negative control; builder accepted empty/slashless prefixes;
partition invariant unchecked; stale embedded subroot digest passed the
outer self-hash; path ordering diverges between languages (astral-vs-BMP,
UTF-16 vs codepoint; JCS does not sort arrays); receipt statuses unbound
from issues; reason outcome not a total sum type; issue locators collide on
malformed bytes; warrant subroot accepted null spec_digest.
P2: JCS model accepted 10^100.

Disposition: model v2 (typed helpers, subprocess harness selftest — which
immediately caught two defective vectors of its author), validate_prefix,
total validate_snapshot, UTF-16 normative ordering, validate_receipt_core,
locator union, ⊎, consumer-side spec_digest requirement. Snapshot rev 3,
receipt rev 4. Full table: profile appendix "round 4".
