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
