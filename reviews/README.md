# Review rounds

One file per adversarial round: reviewer, verdict, findings, dispositions,
and the exact tree state the round ran against.

**Provenance honesty for rounds 1–5:** they predate this repository. They ran
against *unversioned working-tree states* during 2026-08-09/10, so no exact
SHA exists for them and none is claimed — the round files below are
reconstructions from the session ledger (the same content as the appendix
tables in `profiles/PROV-EVIDENCE-VIEW.md`), i.e. **asserted provenance,
recorded as such**. This is exactly the condition round 6 (Kimi, K1/K3)
called out; it cannot be repaired retroactively, only stopped. From round 6
onward every review round MUST name the exact commit it ran against, and a
round without a SHA is invalid.

| Round | Date | Reviewer | Verdict | Tree state |
|---|---|---|---|---|
| 1 | 2026-08-09 | Codex | AMEND | unversioned (pre-repo) |
| 2 | 2026-08-09 | Codex | AMEND | unversioned (pre-repo) |
| 3 | 2026-08-09 | Codex | AMEND | unversioned (pre-repo) |
| 4 | 2026-08-09/10 | Codex | AMEND | unversioned (pre-repo) |
| 5 | 2026-08-10 | Codex | AMEND | unversioned (pre-repo) |
| 6 | 2026-08-10 | Kimi | 6.7/10, R1–R8 | commit `9fe95d7` (first versioned review) |
| 6a | 2026-08-10 | Codex | AMEND | PR #1 head `f976737` |
| 6b | 2026-08-10 | Codex | AMEND | `ecf7ea8` |
| 6c | 2026-08-10 | Codex | AMEND | `dbbe632` |
| 6d | 2026-08-10 | Codex | AMEND | `f7aa39c` |
| 6e | 2026-08-10 | Codex | AMEND | `35fd27d` |
| 6f | 2026-08-10 | Codex | AMEND | `9f09505` |
| 6g | 2026-08-10 | Codex | AMEND | `b0a4c4f` |
| 6h | 2026-08-10 | **Claude (author)** | **self-review — NOT a gate** | `39bda50` |
| 6i | 2026-08-10 | Codex | AMEND | `d8f33aa` |
| 6j | 2026-08-10 | Codex | AMEND | `2fb7c0d` |
| 7 | 2026-08-10 | Kimi | AMEND | `18283bf` |
| 6k | 2026-08-10 | Codex | AMEND | `18283bf` |
| 6l | 2026-08-10 | Codex | AMEND | `2df4d0b` |
| 6m | 2026-08-10 | Codex | AMEND | `84b6d06` |
| 6n | 2026-08-10 | Codex | AMEND | `c96f72c` |
| 6o | 2026-08-10 | Codex | AMEND | `854ff6f` |
| 6p | 2026-08-10 | Codex | AMEND | `6019ff2` |
| 6q | 2026-08-10 | Codex | AMEND | `ab8141e` |
| 6r | 2026-08-10 | Codex | AMEND | `98544f2` |
| 6s | 2026-08-10 | Codex | AMEND | `fc69b98` |
| 6t | 2026-08-10 | Codex | AMEND | `0050042` |
| 6u | 2026-08-10 | Codex | AMEND | `4c2bfea` |
| 6v | 2026-08-10 | Codex | AMEND (target profile only; core + MVP clean) | `b9cd539` |
| 6w | 2026-08-10 | Codex | AMEND (core only; MVP + profile not reviewed) | `8887085` |
| 6x | 2026-08-10 | Codex | AMEND (core + MVP inherited; profile out of scope) | `85269c0` |
| 6y | 2026-08-10 | Codex | AMEND (core + MVP inherited; profile out of scope) | `f705b56` |
| 7 | 2026-08-10 | **Kimi** | AMEND — 2 P1, 4 P2 | `18283bf` (an earlier SHA; findings re-verified against `d28abd2` before closing) |
| 7-re | 2026-08-10 | Kimi | zero P1; one P2 residue (stale-count guard blind to hyphens) | `6fbe3af` |
| 8 | 2026-08-10 | Codex (+ Kimi concurring) | snapshot §7 **APPROVE for freeze**; receipt core AMEND — 1 P1 | `7935400` |
| 9 | 2026-08-10 | Codex | AMEND — 1 P1; **partial disagreement filed**: structural half fixed, prescriptive half disputed with SPEC citations | `21ee454` |
| 10 | 2026-08-10 | Codex | AMEND — 1 P1 (envelope schema); round-9 disagreement **resolved in the repo's favour** — reviewer withdrew the canonical-envelope demand | `598b60d` |
| 11 | 2026-08-10 | Codex | AMEND — 1 P1: acknowledgements joined without their locator | `7b8d86c` |
| 12 | 2026-08-10 | Codex | AMEND — 1 P1: exclusion bypassed the fixed join; source issues now scope-checked | `b21c3c3` |
| 13 | 2026-08-10 | Codex | **APPROVE — receipt core only, eligible for freeze**; no P1 | `4e09d7d` (merged unchanged as `1fb82d6`) |
| — | 2026-08-10 | **Claude (author)** | **NOT A GATE** — live-store adapter, 3 self-found P1 (2 adapter, 1 MVP projector); counts toward no freeze criterion | `d4a518d` + `author/live-warrant-adapter` |
