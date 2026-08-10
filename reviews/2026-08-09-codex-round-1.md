# Round 1 — Codex, 2026-08-09, verdict AMEND

Target: sev@v0 rev 1 (single-document PROV profile). Tree state: unversioned
working tree (pre-repo); no SHA exists — see README.md provenance note.

P1: TOCTOU between `warrant verify` and projector reads; verify-report@v0
lacks per-signature/per-reason data (7 aggregate fields, non-normative
messages); sorted N-Quads are not canonical bytes; `grep '_:'` has false
positives; BOS `assessed_by` is plural (per-observer graphs unrepresentable);
the verifier is not a BOS observer; over-strong PROV mappings (`ts`→endedAt,
`prior`→two relations, every record→Adjudication, unbound actor→attribution).
P2: positional signature identity; sigma-run collapse; note-prefix
OAIP↔Warrant join too weak; receipt vs input bundle conflated.

Disposition: sev rev 2 (weak-default predicates + promotion table,
per-revision graphs, skolem identities) and the birth of the
`warrant.verification-receipt` proposal. Full table: profile appendix
"rev 1 → rev 2".
