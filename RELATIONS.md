# Relations (local notes)

Authoritative map: [protocol-ecosystem](https://github.com/s0fractal/protocol-ecosystem).
This file only answers the four standard questions for THIS repo. All
statuses use the map's closed vocabulary; everything below is `research`
unless stated.

**What is this repository?** Research drafts and an executable model for
sealed ecosystem snapshots, protocol-scoped validation receipts, and
loss-explicit evidence projections. Not a protocol authority.

**Which surfaces of other repos does it consume?**

| To | Consumed surface | Status | Evidence / gate |
|---|---|---|---|
| warrant | SPEC v0.4 semantics *by reference* (JCS §4, grades §6–§7, jurisdictions §9, binding §5.1); no code, no pin | `research` | citations in `spec/` and `proposals/`; the receipt is an unadopted upstream proposal |
| sigma-glyph | Book I anchor as the `ski@v1` semantics digest in `execution_policy` | `research` | field `semantics_digest`; model vectors |
| oaip | future `oaip.validation-receipt@v0` (owned by OAIP, does not exist) | `intended` | none — L-UNJUDGED until it exists |
| BOS | future `bos.validation-receipt@v0` (owned by BOS, does not exist); observer-relative projection rules from BOS-0001 | `intended` | none — L-UNJUDGED until it exists |
| protocol-ecosystem | the relationship map, by URL only | `research` | no pin, no submodule (map rule 1–2) |

**Where is any of this checked?** `model/snapshot_model.py` (self-vectors);
`reviews/` (adversarial rounds against exact SHAs). Nothing is checked in
any other repository's CI, by design.
