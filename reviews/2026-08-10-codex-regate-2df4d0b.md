# Re-gate of `2df4d0b3…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `2df4d0b3cf7e6e37ea182b5e4ceba180f1cf4e9b`; local/origin/PR
agree, CI green, baseline 64 + 92 + 9 confirmed. One new P1, in the
definition of the bijection itself. No files, commits, pushes or GitHub
write actions by the reviewer.

## P1 — the "exact bijection" was computed over the successfully parsed subset

Both derivation helpers silently skipped what they could not understand:
`sigs` that is not a list, a signature that is not an object, an entry that
fails JCS; and symmetrically a non-list `because` or any non-dict element.
Malformed committed evidence therefore disappeared *before* the comparison,
and an empty receipt became an exact bijection with an empty derived set.

Reproduced, both with **zero findings** and a clean projection:

- envelope `{"sigs": [7]}` (body untouched, so the WarrantID held; snapshot,
  universe digest, subroot and receipt honestly resealed) → the dataset
  claimed to hold no signature evidence: `coverage.not_emitted` had no
  `signature`, no `L-NOSIG`;
- body `{"because": [7]}` (new correct WarrantID, everything rebuilt) →
  `reasons: []` accepted, no `reason`/`check-run` anywhere.

`parse_strict` cannot help: both documents are valid I-JSON. The gap was the
absence of Warrant-schema validation *before* derivation.

**Disposition — derivation is now total.** `envelope_signature_entries()`
and `reportable_reason_pointers()` return `(entries, malformed_pointers)`,
validating warrant SPEC §3 / envelope shapes: closed key-sets, `key` hex64,
`sig` hex128, `check` hex64, `verdict ∈ {pass, fail}`, optional hex64
`transcript`, and for reasons only `kind ∈ {prose, check}`. A malformed
occurrence is not placed in `signatures[]`/`reasons[]` — but the receipt
MUST carry a precisely located issue for it, else
`MALFORMED_ENVELOPE_UNREPORTED`; the ERR-bearing source then flows into
exclusions exactly as the existing rules provide. Only a **well-formed
prose** reason is legitimately non-reportable.

Nine new vectors, matching the reviewer's list plus one: `sigs: 7`,
`sigs: [7]`, missing signature fields, wrong field type, **unknown member**
(the envelope schema is closed — an extra key is a different object),
`because: 7`, `because: [7]`, unknown reason kind, malformed check field;
a positive control (well-formed prose beside a check projects cleanly); and
an accepted case where the malformed occurrence *is* reported, which
excludes the record honestly.

## Mutation results

| Guard | Suite when removed |
|---|---|
| malformed-occurrence reporting requirement | fails |
| closed key-set on signatures (`==` → `>=`) | fails — after the unknown-member vector was added; it passed before, and the vector was added rather than the gap being accepted |
| reason shape classification | fails |

## Confirmed as holding

Omission and fabrication of well-formed signatures; omitted/extra/duplicate
well-formed check reasons; multiplicity for genuine duplicates; primitives
and keys charging the node budget; the wide-list and byte-payload ceilings;
the earlier cycle/depth refusals.

## State after closure

64 model + 103 projector vectors + 9 fixtures, all green, exit-status
honest. Proposal rev 8 and the profile state that malformed committed
evidence is evidence, not absence. Freeze criterion still unmet.
