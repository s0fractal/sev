# Round 13 — receipt-core freeze gate

- **Reviewer:** Codex
- **Exact reviewed commit:** `4e09d7dacd46a293c9f1bfeb427af6b7b7defb43`
- **Verdict:** **APPROVE for `warrant.verification-receipt@v0` core freeze only**
- **Merged commit:** `1fb82d670726fa951160f65c6e459bf291ec9b08` (PR #2; content reviewed at the exact head above)

## Evidence

Fresh detached-worktree gate at `4e09d7d`:

- `python3 model/snapshot_model.py` — 98 vectors, exit 0.
- `python3 model/sev_projector.py` — 242 vectors, exit 0.
- `python3 conformance/replay.py` — 11 fixtures, exit 0.
- `git diff --check` — clean.
- GitHub Actions `model` — success for the branch and for merge commit
  `1fb82d6`.

The gate re-ran the Round 16 closure through the public byte-first projector,
not only its private test helper: acknowledged `evil@v1` in a `0.2` body and
acknowledged `ski@v1` in a `0.1` body both yield valid negative evidence and
an excluded record. An unacknowledged form is refused. The duplicate-member
receipt countervector remains refused by every exported projector entrypoint.

## Scope and non-claims

This is an artifact-scoped verdict. It freezes the receipt core described in
the proposal's frozen-surface section: its source/envelope/body binding,
counts, derived byte checks and negative-evidence representation. It does
not approve or freeze the MVP projector, the full PROV target profile, a live
Warrant adapter, Warrant's semantics, cross-implementation parity, or
upstream adoption. `WRT-003` remains unfiled.

`contract.spec_digest` remains an opaque, non-null provenance binding at this
stage, not an SEV-side pin to an external Warrant artifact. That is within
the stated ownership boundary: SEV does not claim to be a second Warrant
verifier.
