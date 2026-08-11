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
| 14 | 2026-08-10 | Kimi | AMEND — 1 P1: adapter crashes on the malformed evidence the frozen receipt core exists to represent; projector `L-NOISSUE` clean | `f92f7ee` (PR #4 head) |
| 14-fix | 2026-08-10 | Claude (author) | closure of round 14: 1 P1 + 5 P2 closed; **reviewer's P2-2 correction accepted and the author's "cannot represent" note withdrawn**; awaiting re-gate | `f92f7ee` → `author/live-warrant-adapter` |
| 14-K | 2026-08-11 | Kimi | **APPROVE — PR #4 eligible for merge**; P1 fix verified on 4 corruption forms, all P2 closed | `f81aa72` (PR #4 head) |
| — | 2026-08-11 | **Claude (author)** | **NOT A GATE** — §4.1 record-body mapping: `L-NOMAP` → `L-NOPROMOTE`; 2 existing vectors found coarse; view gains an output-only `body` channel | `ea185fc` → `author/body-mapping` |
| 15 | 2026-08-11 | Codex | AMEND — 2 P1: `coverage` contradicted the emitted graph; the frozen-boundary guard compared codes, not verdicts | `c9ff62a` (PR #5 head) |
| 15-fix | 2026-08-11 | Claude (author) | closure of round 15: both P1 + the P2 closed; a second weakness in the view-guard corpus found and stated; awaiting exact-SHA re-gate | `c9ff62a` → `author/body-mapping` |
| 16 | 2026-08-11 | Codex | AMEND — 1 P1: `wrt:claimedActor` emitted as a literal where the profile declared an IRI; 1 P2: ledger misattributed round 15 | `c701d91` (PR #5 head) |
| 16-fix | 2026-08-11 | Claude (author) | closure of round 16: profile corrected (literal weak default, actor IRI only on promotion); attribution corrected; `urn:sev:agent` divergence in #6 flagged not fixed | `c701d91` → `author/body-mapping` |
| — | 2026-08-11 | **Claude (author)** | **NOT A GATE** — §4.1 signatures: `L-NOSIG` → `L-SIG`/`L-UNBOUND`/`L-NOSIGNODE`; MVP declaration made honest in both directions | `9a3df58` → `author/signatures` (stacked on PR #5) |
| 17 | 2026-08-11 | Codex | AMEND — 3 P1: receipt judgements in the default graph; excluded signatures counted as emitted; minted IRIs violated the profile | `5315f6a` (PR #6 head) |
| 17-fix | 2026-08-11 | Claude (author) | closure of round 17: rebased onto `9a3df58`; judgements scoped to the verification graph; counts derived from emitted nodes; signature/actor IRI contracts unified (profile amended to require the WID) | `5315f6a` → `author/signatures` |
| 18 | 2026-08-11 | Codex | AMEND — 3 P1: `bound` accepted without a trust basis; bound-path manifest contradicted its graph; actor encoding still library-defined | `f67510a` (PR #6 head) |
| 18-fix | 2026-08-11 | Claude (author) | closure of round 18: binding/grade/trust matrix added to the receipt core — **a FROZEN-contract amendment, proposed and NOT ratified**; coverage and `L-NOPROMOTE` synced; percent-encoding formalized | `f67510a` → `author/signatures` |
| 19 | 2026-08-11 | Codex | AMEND — 3 P1: trust matrix wrongly scoped to `valid:true`; the frozen-core amendment existed nowhere ratifiable; profile still carried two superseded normative texts | `43e77dd` (PR #6 head) |
| 19-fix | 2026-08-11 | Claude (author) | closure of round 19: base clause widened to every signature; **Amendment A-1 filed in the receipt contract** as PROPOSED–NOT RATIFIED; profile synced; actor IRI contract moved into language-neutral fixtures | `43e77dd` → `author/signatures` |
| 20 | 2026-08-11 | Codex | AMEND — 1 P1: A-1 changed frozen `@v0` semantics with no wire identity (same bytes, same tag, two verdicts); 2 P2 | `4243459` (PR #6 head) |
| 20-fix | 2026-08-11 | Claude (author) | closure of round 20: A-1 moved to a new wire tag `@v1` with explicit dispatch; `@v0` frozen permanently; projector refuses ungrounded promotion (`L-UNGROUNDED`); dispatch totality restored after the fuzz vector caught it | `4243459` → `author/signatures` |
| 21 | 2026-08-11 | Codex | AMEND — 3 P1: projection erased the wire tag; `unbound` not treated as ungrounded; one node carrying two contradictory loss codes | `7a6c069` (PR #6 head) |
| 21-fix | 2026-08-11 | Claude (author) | closure of round 21: judgement identity qualified by contract (content digest kept separately); ungrounded covers both directions; attribution reasons made mutually exclusive and vectored as exact code sets | `7a6c069` → `author/signatures` |
| 22 | 2026-08-11 | Codex | AMEND — 3 P1: normative texts drifted from the code for a fourth round (run identity, promotion rule, manifest schema); `L-UNBOUND` described a comparison that never happened | `b66dfc9` (PR #6 head) |
| 22-fix | 2026-08-11 | Claude (author) | closure of round 22: two matrices moved into language-neutral fixtures the harness PROJECTS — the first version stored only expectations and mutation proved it bound nothing | `b66dfc9` → `author/signatures` |
