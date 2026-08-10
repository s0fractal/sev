# Re-gate of `35fd27d9…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `35fd27d9e6967f22756bee6e87c0ca164a1d4cf3`. Baseline
64 + 36 + 9 green; WID re-derivation and path/content multiplicity
confirmed. Two P1s and one P2. No GitHub write or merge actions by the
reviewer.

The layer moved again, exactly along the predicted line: from *is the role
consistent with the bytes* to **is that role normatively permitted**, and
from *which reason* to **which execution of it**.

## Findings → dispositions (same PR, narrow closure)

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P1 | A self-consistent reason could still impersonate a CheckRun: `kind` and `runtime` were only string-compared against the committed bytes, so `kind:"prose"` or `kind:"evil"` became `sigma:CheckRun`, and a committed `check` under an attacker-named runtime passed as soon as the same receipt declared that runtime in `execution_policy` — contradicting warrant SPEC §3, where prose is not a check and an unknown runtime makes the record invalid | Closed registry keyed by **body version** (`RUNTIME_REGISTRY`: `"0.1"` → `cmd@v1`, `"0.2"` → `cmd@v1 \| ski@v1`): `reasons[]` may only reference a committed `kind:"check"` (`REASON_NOT_A_CHECK`), the committed runtime must be in the registry for that body version (`RUNTIME_NOT_IN_REGISTRY`), an unknown body version is refused (`UNKNOWN_BODY_VERSION`). `execution_policy` narrows availability; it can no longer extend the registry |
| 2 | P1 | `CheckRun` lost its semantics and its execution input: no `sigma:semanticsDigest`, no `prov:used`, no pointer, and two clean receipts differing only in `semantics_digest` produced the **same** `urn:sigma:run:…` — a named graph does not localize an IRI, so merging the datasets fuses two executions under different semantics into one `prov:Activity` | Reason and run are now different objects: `urn:wrt:reason:<sha256(wid‖ptr‖reason_digest)>` (stable fact of the record, carrying `sev:pointer`, `sigma:runtime`, `sigma:claimedVerdict` and `prov:used` the check blob) versus `urn:sigma:run:<sha256(core_digest‖wid‖ptr‖reason_digest‖semantics_digest)>` (one execution, carrying `sigma:semanticsDigest`, `sev:receiptCoreDigest`, `prov:used` both the reason and the check blob). The check blob comes from the committed bytes, which is the only place it exists |
| 3 | P2 | Source occurrences were not scoped to the subroot: two snapshots differing only in `contract.spec_digest` produced identical source IRIs, dissolving the domain separation the descriptor exists to provide — while `sourceKind` is a contract-derived assertion living in the default graph | Occurrence identity is now `sha256(subroot_descriptor_digest ‖ path ‖ entry_digest)`, and every source carries `sev:inSubroot` |

Vectors added: five committed-reason variants (prose, unknown kind,
attacker runtime, `ski@v1` in a `"0.1"` body, unknown body version), the
semantics-divergence pair (different runs, stable reason), and the
contract-divergence pair (different source IRIs, `sev:inSubroot` present),
plus a structural check that `CheckRun` actually emits semantics, `prov:used`
and a pointer.

One nuance worth recording: a committed **prose** reason is caught one step
earlier than expected — it carries no runtime at all, so a receipt cannot
name a runtime for it without already contradicting the bytes
(`REASON_ROLE_MISMATCH`). The vector asserts that honest outcome rather than
the code originally predicted.

## State after closure

64 model + 46 projector vectors + 9 fixtures, all green, exit-status honest.
Freeze criterion still unmet; merge stays held.
