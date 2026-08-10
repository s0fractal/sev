# Round 14 — Kimi: independent gate for PR #4 (live Warrant adapter)

**Tree state:** commit `f92f7ee06f6a7e7a0364e281ed07a6727eb6ebcf`
(branch `author/live-warrant-adapter`, PR #4 head), clean working tree.
**Reviewer:** Kimi — fresh reviewer per AGENTS.md rule 7. The author's
self-review (`2026-08-10-live-warrant-adapter.md`) is honestly marked NOT A
GATE; this round is the gate. Scope: PR #4 (`model/warrant_adapter.py`,
the `L-NOISSUE` projector change). Master state (rounds 8–16, freezes) was
spot-checked, not re-gated.

**Verdict: AMEND — 1 P1 (adapter), 5 P2.** The `L-NOISSUE` projector change
itself is clean. No frozen surface is touched: the P1 lives in adapter code
that no frozen contract covers, and the finding argues *against merging the
PR*, not against anything already frozen.

Harnesses at this head, run by the reviewer: 98 model + 248 projector +
11 fixtures + 12 adapter selftest, all exit 0 (the selftest's live half ran
against the real store on this machine — zero SKIP).

## P1-A: the adapter crashes on exactly the evidence class the frozen receipt core exists to represent

`signature_verdicts` runs over **all** record-kind files before any parsing
(warrant_adapter.py:231). Its subprocess does `json.loads(raw)` unguarded,
and the payload build does `raw.decode("utf-8")` unguarded (line 204).
Reproduced against this head with a two-file store:

- `records/bad.json = b"{"` → `RuntimeError: warrant impl refused to answer`
  (subprocess `json.loads` raises; adapter re-raises).
- `records/bad.json = b"\xff\xfe"` → `UnicodeDecodeError` escapes
  `signature_verdicts` itself.

The receipt core was frozen (PR #3) with acknowledged-invalid-evidence
semantics: an honest `RECORD_UNREADABLE/ERR` receipt validates and the
record projects into exclusions. Verified working at this very head
(acknowledged → `[]` + exclusion; unacknowledged → refused
`RECORD_UNREADABLE_UNREPORTED`). The first real receipt *producer* cannot
emit that shape: it dies with a host exception before the receipt exists,
on precisely the hostile evidence the freeze was amended to represent.
"Exit status is the verdict" is kept only in the narrow sense (nonzero via
traceback) — no findings, no receipt, no exclusion manifest.

*Fix direction:* the adapter already parses every record in
`build_receipt`'s loop — parse first, and send only well-formed envelopes
to the signature subprocess; unparseable records take the existing
`RECORD_UNREADABLE` path with `sigs` never queried. Per-record
try/except inside the subprocess as defense in depth. Vectors: a malformed
record in a *synthetic* store (the live store will never supply one — the
self-review already named this blind spot for ERR findings, and it applies
to the seal→report path too).

## P2 findings

1. **Silent level downgrade** (warrant_adapter.py:158): `"ERR" if
   finding.get("level") == "ERR" else "WARN"` — an unknown or future level
   becomes WARN silently. The adapter's own discipline (fail closed on
   unclassified messages) should apply to levels: refuse what SEV does not
   understand.
2. **`IndistinguishableFindings` refuses a legitimate store state.** Two
   unresolved blobs on one record → two same-class findings → refusal. The
   forwarded note says the issue schema "cannot represent" this — but the
   locator union already carries the `occurrence` ordinal
   (`validate_locator` accepts it; a projector vector exercises it). The
   correct statement is "does not yet represent"; the occurrence ordinal is
   the in-schema answer, and the refusal can become representation.
3. **The adapter is ungated in CI.** `.github/workflows/model.yml` runs
   three steps; `warrant_adapter.py --selftest` is not one of them. The
   selftest's fixture half is machine-independent (the live half SKIPs
   honestly), so CI can and should run it.
4. **Latent cmd@v1 assumption** (warrant_adapter.py:287): every check
   reason is emitted `re_execution: "not-applicable"`. A live store whose
   records carry `ski@v1` reasons yields `NOT_APPLICABLE_BUT_EXECUTABLE`
   and a refused projection — fail-closed but wrong by assumption. Document
   the limitation or branch on the committed runtime.
5. **Crash-hygiene nits (one class):** no subprocess timeouts
   (`warrant_report`, `signature_verdicts`); missing SPEC/impl produces raw
   `FileNotFoundError`; `report["grade"]` / `report["errors"]` are
   unguarded against report schema drift; a report at settlement grade
   would produce `TRUST_DIGEST_REQUIRED` (`trust_config_digest` is always
   None) — the adapter cannot emit settlement receipts, and that limitation
   is undocumented.

## Verified (attacks attempted / claims checked, defense holds)

- **Round-8 closure end-to-end at this head** — see P1-A above; both
  polarities behave.
- **`L-NOISSUE` scoping is correct**: keyed on `(path, entry_digest)` of
  the exclusion set; a WARN on a projected source raises it, issues on an
  excluded source do not, exclusions carry issues verbatim. All three
  vectors present in the suite.
- **Freeze honesty**: README's artifact table splits the four artifacts
  with distinct statuses; spec §7 FROZEN at `7935400` names exactly the
  candidate surface; receipt-core freeze row records the exact-SHA gate
  (`4e09d7d`, merged unchanged as `1fb82d6`). No overclaim found.
- **Ownership boundary**: the adapter performs no cryptography; signature
  validity is asked from Warrant's own implementation; the report is bound
  by digest in `producer.report_digest`; `assert_not_quieter` refuses a
  receipt cleaner than the protocol's own verdict; `FINDING_CLASSES` fails
  closed on unclassified messages.
- **Ledger honesty**: the author's adapter review is marked NOT A GATE and
  counts toward nothing; this round files the gate it awaited.

## Disposition

PR #4 should not merge before P1-A is fixed and vectored; P2-1 and P2-3
are cheap and belong in the same fix. P2-2/P2-4/P2-5 may follow as
documented limitations if the author prefers. Re-gate against the fix SHA;
this round then supports merge of an adapter that survives the evidence it
was built to meet.
