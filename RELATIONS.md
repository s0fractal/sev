# Relations (local notes)

Authoritative map: [protocol-ecosystem](https://github.com/s0fractal/protocol-ecosystem).
This file records the terminal relation state for an `ABANDONED` trajectory.
All live relations are removed from the active ecosystem map; the rows below
are `historical` and do not authorize new dependencies.

**What was this repository?** Research drafts and an executable model for
sealed ecosystem snapshots, protocol-scoped validation receipts, and
loss-explicit evidence projections. It was never a protocol authority and was
never adopted.

**Which surfaces of other repos did it consume or anticipate?**

| To | Consumed surface | Status | Evidence / gate |
|---|---|---|---|
| warrant | SPEC v0.4 semantics by reference; the SEV-originated receipt direction | `historical` | Warrant closed WRT-003 at `25bd44c829cb015a836e08642022412c568de16a` in favour of a Warrant-owned report; no SEV receipt contract was adopted |
| sigma-glyph | Book I anchor as the `ski@v1` semantics digest in `execution_policy` | `historical` | field `semantics_digest`; SEV-local model vectors only |
| oaip | prospective `oaip.validation-receipt@v0` | `historical` | it did not exist; no gate or consumer was created |
| BOS | prospective `bos.validation-receipt@v0`; observer-relative projection rules from BOS-0001 | `historical` | the receipt did not exist; no gate or consumer was created |
| protocol-ecosystem | the relationship map, by URL only | `historical` | the map now carries the retirement status; no pin or submodule |

**Where was any of this checked?** `model/snapshot_model.py` (self-vectors),
the other local harnesses, and `reviews/` (model review rounds against exact
SHAs). Those checks remain reproducible evidence about preserved bytes; a
green run does not reactivate SEV or create cross-repository validation credit.
