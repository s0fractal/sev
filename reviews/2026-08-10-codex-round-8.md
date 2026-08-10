# Round 8 — Codex, 2026-08-10, artifact-scoped

Target: `79354000f4cda6ec368730d72915e82f5f55428b`.

| Artifact | Verdict |
|---|---|
| `ecosystem.snapshot@v0` §7 | **APPROVE for freeze** |
| `warrant.verification-receipt@v0` core | **AMEND — P1** |
| MVP projector | **AMEND** — inherits the receipt P1 |
| target profile | outside this decision |

Kimi (round 7 reviewer) reproduced the finding independently, byte for byte,
and concurred with the correction to her own freeze wording.

## P1 — honestly-reported malformed evidence could not be a valid receipt

For a sealed record whose bytes are `b"{"`, a receipt reporting exactly what
the new `loaded` semantics require — `loaded: true`, `RECORD_UNREADABLE/ERR`,
`computed_wid: null`, `id_sound: false`, counts consistent — was rejected:

```
validate_snapshot:       []
validate_structure_only: []
composed receipt:        ['RECORD_UNREADABLE']
projector:               refuses, no output
```

`_resolve_record()` turned the *consumer-derived* parse failure into a
defect of the **receipt**, so hostile or malformed input could not be
represented as verified negative evidence — the point of a source-oriented
receipt. Kimi sharpened the argument with the model's own inconsistency:
`ID_UNSOUND`, an equally honest ERR, projects with an exclusion, while a
parse failure killed the whole projection.

**Disposition.** The parse outcome is derived and then **joined** with the
receipt's own acknowledgement:

| Derived | Receipt says | Result |
|---|---|---|
| bytes do not parse | `RECORD_UNREADABLE/ERR` present | **valid receipt**; the ERR carries the record into exclusions, exactly like `ID_UNSOUND` |
| bytes do not parse | acknowledgement missing or wrong | `RECORD_UNREADABLE_UNREPORTED` |
| bytes parse | `RECORD_UNREADABLE` claimed | `SPURIOUS_RECORD_UNREADABLE` |

`loaded` stays `true` throughout — the bytes were obtained. Kimi's
sharpening is adopted as a rule rather than left to exclusion: an
unparseable body MUST carry `computed_wid: null` and `id_sound: false`, else
`UNREADABLE_WITH_IDENTITY_CLAIM` — no unverifiable identity residue over
bytes nobody can read.

Four vector branches, filed **with** the fix per house rule 4: acknowledged
(valid + excluded, issue verbatim), unacknowledged (refused), spurious
(refused), and identity residue (refused).

## Freeze decision, as corrected

The README row conflating `ecosystem.snapshot@v0` with the receipt core is
split into four artifacts with separate statuses. Only the **snapshot byte
core** freezes, at `7935400`, and both the README note and the spec section
state that it covers exactly the §7 surface and not a byte more. The receipt
core stays an **open draft** — not a "frozen draft" — since it had a live
P1 this round.

WRT-003 is *not* filed: the agreed plan permits filing after a clean gate
**and** a frozen receipt core, and the receipt core is neither.

## Mutation results

| Element | Suite when removed |
|---|---|
| the acknowledgement join | fails |
| `SPURIOUS_RECORD_UNREADABLE` | fails |
| the identity-residue rule | fails |
