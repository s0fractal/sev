# SEV retirement record

- **Mode:** `ABANDONED`
- **Owner decision:** 2026-09-02
- **Admission:** excluded from the default active protocol set
- **Replacement:** none

This is the first manual controlled-forgetting specimen for a whole repository
trajectory. It is deliberately a small tombstone and impact record, not a new
retirement protocol. Git history preserves the larger body on a best-effort
basis.

## Exact subject

The decision covers the SEV trajectory through both public endpoints that
existed when it was made:

| Surface | Exact revision | Role |
|---|---|---|
| public default branch | `master@33a08a60d811ef634f3ea69b868d6983197ab936` | last merged public surface |
| terminal research branch | `author/vertical-slice-refund@4453bf3ef0c93b7879ca02a2d9460a6a3e3ba832` | adds the final vertical-slice experiment and its negative closure |

The repository is abandoned as a direction, not declared false. Existing
artifact labels such as `FROZEN` still mean only that their own byte contract
stopped moving; they do not mean adopted, active, or independently validated.

## Why the trajectory stops

1. Its enabling Warrant direction did not become a contract. Warrant closed
   WRT-003 at
   `25bd44c829cb015a836e08642022412c568de16a` in favour of a Warrant-owned
   `warrant.verify-report` direction without an `ecosystem.snapshot@v0`
   dependency. WRT-004 was separately closed at
   `7f40932060ded9a1fde7e6b74e91334e73b8080e`.
2. The anticipated OAIP and BOS receipt surfaces never existed, and no external
   consumer adopted the SEV projection.
3. The terminal refund slice produced a useful negative result: its controls,
   headline, and actual proof drifted apart. Under its declared stopping rule it
   closed as `NOT YET USEFUL` rather than receiving another repair round.
4. Manifesto now carries the broader active concern — explicit loss, semantic
   hygiene, claim-credit boundaries, and controlled forgetting — without
   implementing the SEV wire format. This change of focus makes continued SEV
   development unjustified; it is not a compatibility claim or a supersession.

## Preserved results

These locators and SHA-256 digests name the small set worth retrieving first.
All paths are at terminal revision `4453bf3ef0c93b7879ca02a2d9460a6a3e3ba832`.

| Path | What survives | SHA-256 |
|---|---|---|
| `spec/ECOSYSTEM-SNAPSHOT.md` | domain-separated subroot descriptors and the logical-path/CAS snapshot byte contract | `89e48f9900ea83dfc61ab88dba324213e5ac26bd5170aa616a0f0973762653bf` |
| `model/snapshot_model.py` | executable strict parsing and snapshot invariants for that historical contract | `ef1d9fef6689f7d4d8d23ef9bcbee76457cff1ba0fde99a0f271a62a8afb7548` |
| `profiles/PROV-EVIDENCE-VIEW.md` | the projection-bound `loss_manifest` discipline | `b567dee092f969ca2e61a60cf3c46232d0a382cb1be25c9d06b354bee23fa3c0` |
| `examples/refund-decision/README.md` | the negative result and the four reproduced failures | `d4a9d67b4d5dcfad48064d1117683f02303b8cec5a16e2519832e24e87feab2a` |
| `examples/refund-decision/run.py` | the deliberately non-zero closure path for the failed controls | `44781a10c254eca5a56f1744c9944cc3622074e2b8747d6b0d60abcc3843bad4` |

The receipt proposal is preserved for provenance, not extracted as a live
contract: `proposals/WARRANT-VERIFICATION-RECEIPT.md`, SHA-256
`1c0e0c1a59fc82c655a0589c100121c8755d28467dceb7af572d23a2d13838ed`.

## Known loss and non-claims

- No replacement reproduces SEV's sealed multi-protocol snapshot or canonical
  N-Quads projection. The active ecosystem is smaller, not equivalent.
- There is no proof of completeness beyond a declared snapshot, no adopted
  per-protocol receipt set, no independent implementation, and no external
  validation credit.
- Model review rounds and green SEV-local suites do not establish adoption,
  usefulness, or cross-repository composition.
- The refund result refutes the demo's evidence packaging, not content
  addressing in general and not every possible snapshot-bound projection.
- Git and the public remote are best-effort preservation paths. This record does
  not promise permanent recoverability.

## Impact and remaining references

- `protocol-ecosystem` is the one active index changed with this specimen: SEV
  moves out of Members and live relations into a historical/abandoned entry.
- Decision Archaeology contains historical field notes and `CC-0007`, an
  `informs-only` counterclaim whose witness reads the preserved SEV profile from
  a sibling checkout. That is a real behavioral consumer of historical bytes,
  though not an integration or adoption. This specimen downgrades it to
  `records-only` with a 2026-09-02 `narrowed` relitigation note and removes SEV
  from Decision Archaeology's active owner table; the original claim and witness
  remain byte-preserved in Git history.
- No member protocol imports SEV as a package or submodule. This record does not
  claim knowledge of every unknown external clone or citation.
- Archiving the GitHub repository is a separate owner action and is not implied
  by this file or by a local commit.

## Re-adoption

Reading or copying historical bytes is not re-adoption. A future use must begin
with a new, explicit proposal that:

1. names a concrete consumer needing a sealed multi-protocol snapshot and a
   loss-explicit projection;
2. identifies current owner-defined receipt/report contracts rather than
   reviving the closed WRT-003 direction by name;
3. re-runs the preserved negative controls and adds a non-vacuous consumer gate;
4. states what is reused, what is incompatible, and which evidence does not
   transfer; and
5. receives an explicit owner decision before entering an active index.

Until then, the default interpretation is historical evidence under an
`ABANDONED` status envelope.

## Active directions

New work should start from the active concern owner rather than silently
resurrecting SEV:

- [Σ-GLYPH](https://github.com/s0fractal/sigma-glyph) — deterministic,
  addressed, resource-bounded evaluation;
- [Warrant](https://github.com/s0fractal/warrant) — authority, decisions,
  provenance, and replay;
- [Manifesto](https://github.com/s0fractal/manifesto) — semantic hygiene,
  verification-credit boundaries, evolution of concepts, and controlled
  forgetting; and
- [OAIP](https://github.com/s0fractal/oaip) — observation of actions and intent
  without collapsing execution into validation or acceptance.

This routing is by active responsibility. It does not assert that the four
repositories compose into SEV or reproduce its wire format.
