# SEV — Sealed Evidence View

**Status: research, not adopted.** Nothing here is a live contract; no
protocol has accepted anything from this repository.

Snapshot-bound, receipt-aware and loss-explicit evidence views across
independent protocols. The core object is not the RDF graph — it is the
**sealed ecosystem snapshot** with protocol-scoped subroots, over which each
protocol's own verifier issues a **validation receipt** bound to exactly its
subroot. The PROV/RDF dataset is one *projection* of that pair, shipped with
a machine-readable `loss_manifest` of everything the projection cannot
express or verify. PROV is a readable shadow, never a trust boundary.

```
Sealed Ecosystem Bundle  (ecosystem.snapshot@v0)
├── bundle_root
├── warrant subroot ─→ warrant.verification-receipt@v0   (upstream proposal)
├── oaip subroot    ─→ oaip.validation-receipt@v0        (future, owned by OAIP)
└── bos subroot     ─→ bos.validation-receipt@v0         (future, owned by BOS)
                 │
                 ▼
        sev projector — pure function of (bundle bytes, receipts)
                 ▼
   SEV dataset (canonical N-Quads) + view-manifest + loss_manifest
```

## Contents

| Path | What it is |
|---|---|
| [`spec/ECOSYSTEM-SNAPSHOT.md`](spec/ECOSYSTEM-SNAPSHOT.md) | `ecosystem.snapshot@v0` — neutral sealed bundle, domain-separated subroot descriptors, logical-path/CAS contract (rev 4) |
| [`profiles/PROV-EVIDENCE-VIEW.md`](profiles/PROV-EVIDENCE-VIEW.md) | `sev@v0` — the projection profile, plus the running review ledger (5 adversarial rounds applied) |
| [`proposals/WARRANT-VERIFICATION-RECEIPT.md`](proposals/WARRANT-VERIFICATION-RECEIPT.md) | `warrant.verification-receipt@v0` — **SEV-originated design candidate for Warrant; not a Warrant contract** (see Ownership below) |
| [`model/snapshot_model.py`](model/snapshot_model.py) | Executable reference model: raw-byte strict parsers, total validators, composed receipt verdict, 56 self-vectors |
| [`model/sev_projector.py`](model/sev_projector.py) | Projector MVP (round-6 R4): verified (snapshot, receipt) → canonical N-Quads + view-manifest + loss_manifest; Warrant quadrant only; refuses on any verdict finding |
| [`conformance/`](conformance/) | Language-neutral fixtures (base64 bytes + expected codes) + replay harness — a second implementation consumes the JSON, not the Python |
| [`reviews/`](reviews/) | Adversarial review rounds 1–6 with dispositions; rounds 1–5 predate the repo and are marked as reconstructed (see `reviews/README.md`); from round 6, a review without an exact SHA is invalid |

## Run

```bash
python3 model/snapshot_model.py   # 56 vectors; exit status is the verdict
python3 model/sev_projector.py    # end-to-end projection, cross-process determinism
python3 conformance/replay.py     # language-neutral fixture replay
```

CI (`.github/workflows/model.yml`) runs all three on every push and PR —
exit-status honesty is a gate, not a habit.

The model passes its current 56 vectors. That means exactly: *56 stated
claims are checked honestly* (the harness distinguishes `True` from truthy,
requires named refusal codes, and self-tests in a subprocess). It does NOT
mean the full prose contract is covered, and no independent approval or
cross-implementation parity is claimed. Where prose and model disagree, the
disagreement is a bug in one of them and a conformance vector waiting to be
written.

## Ownership boundary

`proposals/WARRANT-VERIFICATION-RECEIPT.md` is an **upstream proposal**:
SEV-originated, not adopted by Warrant. If Warrant ever accepts it: the
normative version moves into the Warrant repository; SEV stops maintaining
a normative copy; SEV pins the Warrant artifact/version/digest; the draft
here remains as provenance, marked superseded. The same rule applies,
prospectively, to any OAIP/BOS validation receipts — SEV composes
per-protocol judgements; it never owns their semantics.

## Relations

How this repository relates to its siblings — which links are gated
contracts, which are proposals, and which do not exist — is indexed in the
[ecosystem relationship map](https://github.com/s0fractal/protocol-ecosystem).
Local notes: [`RELATIONS.md`](RELATIONS.md).

## License

Code (`model/`) is MIT. Documents (`spec/`, `profiles/`, `proposals/`) are
CC-BY-4.0. See [`LICENSE`](LICENSE).
