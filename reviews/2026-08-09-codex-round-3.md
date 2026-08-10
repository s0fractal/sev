# Round 3 — Codex, 2026-08-09, verdict AMEND

Target: snapshot rev 1 + receipt rev 2 + sev rev 2.1. Tree: unversioned.

P1: bare file-tree subroot allows role-confusion (same universe, different
slot, same root); `expected.closed` had no mechanical teeth
(delete-then-reseal countervector); logical-path/CAS contract undefined;
issue *set* cannot bind counts (duplicate co-signature countervector); `wid`
ambiguous on id mismatch; `sources[]` covered records only; bare
matched/mismatched/unverified insufficient for projection (observed result
absent from snapshot on mismatch).
P2: execution policy names a tag, not semantics; trust_config_digest
undefined over raw vs canonical bytes.

Disposition: snapshot rev 2 (domain-separated descriptors, path contract,
closed demotion, expectation object), receipt rev 3 (located multiset,
claimed/computed wid, discriminated union, structured outcome, semantics
anchors), model v1 born ("a small executable model beats another prose
round"). Full table: profile appendix "rev 2.1 → rev 2.2".
