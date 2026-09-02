# SEV — Sealed Evidence View

> **Trajectory status: `ABANDONED` (owner decision, 2026-09-02).** SEV is no
> longer an active member of the protocol ecosystem and nothing here is a live
> contract. This is not a refutation and not a claim that another repository
> implements SEV. The frozen byte core, the loss-explicit projection work, and
> the failed refund slice remain available as historical evidence. See
> [`RETIREMENT.md`](RETIREMENT.md) before citing or reusing them.

Active work continues in
[Σ-GLYPH](https://github.com/s0fractal/sigma-glyph) for deterministic addressed
evaluation, [Warrant](https://github.com/s0fractal/warrant) for authority and
replayable decisions, and [Manifesto](https://github.com/s0fractal/manifesto)
for semantic hygiene, credit boundaries, and controlled forgetting. These are
directions for new work, not implementations of or drop-in replacements for
SEV. [OAIP](https://github.com/s0fractal/oaip) remains the separate observation
protocol where observed action is the subject.

The text below describes the terminal research state at
`author/vertical-slice-refund@4453bf3`; it is preserved rather than rewritten
as a current design.

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
| [`model/snapshot_model.py`](model/snapshot_model.py) | Executable reference model: raw-byte strict parsers, total validators, composed receipt verdict, self-vectors |
| [`model/sev_projector.py`](model/sev_projector.py) | Projector MVP (round-6 R4): verified (snapshot, receipt) → canonical N-Quads + view-manifest + loss_manifest; Warrant quadrant only; refuses on any verdict finding |
| [`model/warrant_adapter.py`](model/warrant_adapter.py) | Live adapter: seals a **real** `.warrants/` store and projects it. The only component that meets evidence this repository did not author; performs no cryptography, and asks Warrant's own implementation about Warrant's own bytes |
| [`conformance/`](conformance/) | Language-neutral fixtures (base64 bytes + expected codes) + replay harness — a second implementation consumes the JSON, not the Python |
| [`reviews/`](reviews/) | Adversarial review rounds 1–6 with dispositions; rounds 1–5 predate the repo and are marked as reconstructed (see `reviews/README.md`); from round 6, a review without an exact SHA is invalid |

## Run

```bash
python3 model/snapshot_model.py   # exit status is the verdict
python3 model/sev_projector.py    # end-to-end projection, cross-process determinism
python3 conformance/replay.py     # language-neutral fixtures: parse-strict, actor-iri,
                                  # judgement-identity, signature-promotion
python3 model/warrant_adapter.py --selftest        # adapter vectors
python3 model/warrant_adapter.py ~/path/.warrants  # project a real store
```

CI (`.github/workflows/model.yml`) runs all four on every push and PR —
exit-status honesty is a gate, not a habit. The adapter's live half needs a
Warrant store, which a runner does not have, so it prints `SKIP` there and
says so; its fixture half still gates.

The suites pass every vector they carry, and each prints its own count when
run — deliberately not repeated here, because a number in prose rots while
the honesty sentence it supports stays. That claim is exactly: *the stated
claims are checked honestly* (the harness distinguishes `True` from truthy,
requires named refusal codes, and self-tests in a subprocess). It does NOT
mean the full prose contract is covered, and no independent approval or
cross-implementation parity is claimed. Where prose and model disagree, the
disagreement is a bug in one of them and a conformance vector waiting to be
written.

## Freeze criteria, per artifact

A single shared "no P1 anywhere" gate would let a finding in a future
OAIP/BOS mapping block a snapshot core that has been stable for a dozen
rounds. The criteria are therefore split, and each artifact freezes on its
own clean round:

| Artifact | Scope | Status |
|---|---|---|
| `ecosystem.snapshot@v0` **byte core** | logical-path and prefix rules, subroot descriptor + domain-separated digest, snapshot object with its normative array orders and self-hash, `parse_strict`'s complete refusal set | **FROZEN** at `7935400` — clean §7 gate, Kimi round 7 re-gate, zero P1 |
| `warrant.verification-receipt@v0` core | receipt core invariants, envelope/body binding, counts, source union, and acknowledged invalid evidence | **FROZEN** at `1fb82d6` — exact-SHA gate of `4e09d7d`, merged unchanged through PR #2; zero P1. **This freeze is permanent, and the frozen SHA does not move.** A successor contract, `warrant.verification-receipt@v1`, is proposed in [`proposals/WARRANT-VERIFICATION-RECEIPT.md`](proposals/WARRANT-VERIFICATION-RECEIPT.md): it requires a signature's `binding` to match its trust basis. It ships on its **own wire tag** rather than as an amendment, because the same canonical bytes under one tag must never get two verdicts. Ratifying `@v1` freezes a new contract beside this one |
| MVP projector | what `model/sev_projector.py` actually emits, per `mvp_predicates` in the shapes file | **not frozen** |
| `warrant.verification-receipt@v1` | the `@v0` surface plus A-1: a signature's `binding` must match its trust basis (`BINDING_WITHOUT_TRUST`, `UNVERIFIED_UNDER_TRUST`) | **PROPOSED — not frozen.** A separate wire tag, dispatched on; `@v0` is untouched |
| Full `sev@v0` target profile | every class and predicate in `conformance/prov-shapes.json`, including the OAIP/BOS quadrants | **not frozen**, and expected to move longest |

> **What the snapshot freeze does and does not say.** It covers exactly the
> §7 surface listed above and not a byte more. It is *not* an approval of
> the receipt core, the projector, or the target profile — each carries its
> own verdict, and freezing one artifact must never read as freezing its
> neighbours. Three times now a state called clean turned out unclean in an
> adjacent layer (a reviewer's guard, this repo's guard, receipt semantics);
> the byte contract survived all three, which is the reason it freezes and
> the reason the note is this narrow.

A round is clean **for an artifact** when it produces no P1 against that
artifact. Rounds are still adversarial and still run against an exact SHA.

## Ownership boundary

`proposals/WARRANT-VERIFICATION-RECEIPT.md` is an **upstream proposal**:
SEV-originated, not adopted by Warrant. If Warrant ever accepts it: the
normative version moves into the Warrant repository; SEV stops maintaining
a normative copy; SEV pins the Warrant artifact/version/digest; the draft
here remains as provenance, marked superseded. The same rule applies,
prospectively, to any OAIP/BOS validation receipts — SEV composes
per-protocol judgements; it never owns their semantics.

## Relations

How this repository historically related to its siblings — which links were
gated contracts, which were proposals, and which never existed — is indexed in
the [ecosystem relationship map](https://github.com/s0fractal/protocol-ecosystem).
Local notes: [`RELATIONS.md`](RELATIONS.md).

## License

Code (`model/`) is MIT. Documents (`spec/`, `profiles/`, `proposals/`) are
CC-BY-4.0. See [`LICENSE`](LICENSE).
