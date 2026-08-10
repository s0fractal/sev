# Round 2 — Codex, 2026-08-09, verdict AMEND

Target: sev rev 2 + receipt rev 1. Tree state: unversioned (pre-repo).

P1: one `input_root` mixes protocols — a Warrant receipt must not become the
ecosystem's receipt; whole-receipt byte-reproducibility impossible
(non-normative messages; local ATP ceiling/oracle availability legitimately
vary); N2 demanded detecting the absence of what was never committed;
malformed records have no `wid`; `settlement_active` is not a global boolean
(SPEC §9 jurisdiction scoping); attribution granted on `valid` without
`bound`; note-match refusal = censorship primitive.
P2: Filing keyed by WarrantID while envelopes grow; verification graph keyed
by input_root collapses grades; "facts no one owns"; NFC contradiction;
recheck as shell string.

Disposition: `ecosystem.snapshot@v0` born (per-protocol subroots), receipt
rev 2 (core/producer split), sev rev 2.1. Full table: profile appendix
"rev 2 → rev 2.1".
