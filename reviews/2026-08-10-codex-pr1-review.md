# PR #1 review — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `f976737` (all CI checks green). Reviewer note: Kimi's
round 6 gated `9fe95d7`; the projector introduced in this PR had no
independent gate yet — this review is that gate's first pass. All three P1s
were *reproduced by execution*, not read off the code.

## Findings → dispositions (same PR, no scope expansion)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | Reason role-confusion: receipt swaps `runtime: ski@v1` → `evil@v1`; validator returns `[]`; the graph asserts the swapped runtime. The digest proves the reason bytes, not that the receipt's role fields describe them | `_resolve_reason` now binds `kind`/`runtime` (`REASON_ROLE_MISMATCH`) and `claimed_verdict` (`REASON_CLAIM_MISMATCH`) to the committed reason object; two model vectors |
| 2 | P1 | Untruthful view-manifest: an honest negative receipt (one ERR) projects, the record is skipped, but the manifest claims `projected=2, excluded=0` — silent truncation reborn in SEV's own output | Projector tracks exclusions (`ERR_ISSUES` / `NOT_LOADED` / `ID_UNSOUND` + the source's ERR codes); `projected + excluded == in_receipts` restored; vectors: negative receipt projects, counts truthful, no record node emitted |
| 3 | P1 | Non-canonical N-Quads: a runtime containing a tab passes the validator and `_lit()` emits raw `0x09` in output called canonical | `_escape()`: ECHAR set (`\\ \" \n \r \t`) + `\uXXXX` for every remaining C0 control; unit vectors + a whole-output scan (no raw byte < 0x20 except LF) |
| 4 | P2 | Empty `cases: []` yields `ALL PASS (0 fixtures)` | `replay.py` refuses an empty fixture set, exit 1 |
| 5 | P2 | View-manifest lacks `profile_revision` — the graph digest is unbound from the projector's semantics | `profile_revision` (profile doc bytes) + `projector_digest` (projector bytes) added to the manifest and to profile §9 |

## Reviewer's ordered plan (adopted)

1. Fix countervectors in the same PR — **done, this commit**.
2. Independent re-gate of the new exact SHA — Codex's act, pending.
3. Merge PR #1 only after APPROVE — human act.
4. R7 as a separate small PR in protocol-ecosystem (no submodules/pins).
5. R5 split: a Warrant *issue* now for dependency visibility; WRT-003 as a
   filed proposal only after a clean SEV gate and a frozen receipt core.

The layer this review opened is the right next one: not the snapshot model
but the **receipt → asserted-graph boundary** — what the projection claims
versus what the receipt actually licenses.
