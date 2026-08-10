# Re-gate of `f7aa39c…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `f7aa39ccd3d4fcd10b569acf7ece326587908971`. Baseline
64 + 30 + 9 green; the classifier, filename-claim binding and detached
exclusions all hold. Two new P1s. No GitHub write or merge actions by the
reviewer.

## Findings → dispositions (same PR, narrow closure)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | `computed_wid` was reported, never computed: editing the committed body (`ts:1→2`), resealing the snapshot and CAS, and leaving the old `computed_wid` in the receipt gave `[]` from the validator while the projector asserted the old Warrant IRI. Only internal equality `claimed == computed` was checked | Each loaded record is resolved and parsed **once per source**; the WarrantID is re-derived as `sha256(JCS(body))` and compared (`COMPUTED_WID_MISMATCH`; `RECORD_UNRESOLVABLE` / `RECORD_UNREADABLE` / `RECORD_BODY_UNREADABLE` for the byte-level failures). The parsed envelope is threaded into reason binding, so the CAS is read once, not once per reason |
| 2 | P1 | Two source occurrences with identical bytes merged: `.warrants/blobs/p` and `.warrants/genesis.json` holding the same digest produced a single `urn:wrt:blob:<digest>` node carrying two `sourceKind` values — path and multiplicity erased while the manifest counted both projected | Occurrence identity split from content identity: `urn:sev:source:<sha256(path‖0x00‖entry_digest)>` typed `sev:Source` with `sev:path`, `sev:sourceKind`, `sev:entryDigest`, linked by `prov:specializationOf` to the content entity (`urn:wrt:blob:<digest>`) or, for records, to `urn:wrt:record:<wid>`. Two paths with identical bytes are now two occurrences of one content |

Vectors added: body mutation with a stale receipt WID (projector refuses,
no graph), and two paths with identical bytes (three distinct `sev:Source`
nodes, one `sev:sourceKind` and one `sev:path` each, two
`specializationOf` edges to the single shared content entity).

A fixture consequence worth recording: with both the filename claim and the
body hash now derived, an id-unsound record can no longer be *asserted* — it
must be *constructed*. The fixture gained `misfiled_as`, sealing the record
under one WarrantID while its body canonicalizes to another. Two earlier
"honest negative" helpers that simply overwrote `computed_wid` became lies
under the new rule and were removed.

## State after closure

64 model + 36 projector vectors + 9 fixtures, all green, exit-status honest.
Freeze criterion (a round with zero P1) still unmet; merge stays held.
