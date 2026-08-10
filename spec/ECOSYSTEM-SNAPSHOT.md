# Sketch: `ecosystem.snapshot@v0` — a neutral sealed bundle with protocol subroots

**Status:** SKETCH **rev 4** (2026-08-10), design-only. Rev 4 (fifth review
round): the conformance entrypoint is **raw bytes** — `parse_snapshot(raw,
cas)` with strict UTF-8, duplicate-member/trailing-data/NaN/float/lone-
surrogate/BOM refusal and `jcs(parsed) == raw` canonicality — because a
decoded object cannot witness any of those; `validate_snapshot` is **total**
(hostile shapes → findings, never host exceptions; semantic passes
short-circuit after structural damage); `subroots` and `unclaimed` carry
normative strictly-increasing orders (by (protocol, prefix, digest) and by
path respectively — JCS does not sort arrays, so unordered arrays would let
two implementations emit different bundle bytes); and CAS coverage includes
`unclaimed` members (rev 3's resolver ran only inside the subroot loop). Intended home: the SEV
adapter / `protocol-ecosystem` orbit — not any member protocol repo. Rev 2
added domain-separated subroot descriptors, the logical-path/CAS contract,
and the `closed` demotion. Rev 3 applies the fourth Codex review (verdict
AMEND, aimed mostly at the executable model): formal prefix rules with
component-boundary membership, a **normative universe ordering** (ascending
UTF-16 code units), and one total `validate_snapshot()` judgement that
enforces the partition invariant and re-derives embedded descriptor digests.
The executable model is `model/snapshot_model.py` (v2 — its v1 harness
accepted falsy returns as PASS, found by executing `check("x", lambda:
False)`; v2 has typed helpers and a subprocess selftest of the harness
itself). Where this prose and that code disagree, the disagreement is a bug
in one of them and a conformance vector waiting to be written.

## 1. Subroot descriptor (rev 2: domain-separated, role-binding)

A subroot is **not** a bare file-tree hash. Rev 1's
`root = sha256(JCS([{path,sha256}…]))` committed neither protocol, contract,
prefix, nor algorithm — two slots with the same logical universe had the same
root, so a receipt binding "the warrant root" could be re-attached to another
slot with identical bytes. Rev 2 hashes a full descriptor under a domain tag:

```json
{
  "subroot": "ecosystem.subroot@v0",
  "protocol": "warrant",
  "contract": { "name": "warrant", "version": "0.4",
                "spec_digest": "<hex64 | null>" },
  "prefix": ".warrants/",
  "universe": [ {"path": ".warrants/records/…", "sha256": "<hex64>"} ]
}
```

```
subroot_descriptor_digest = sha256(ASCII("ecosystem-subroot-v0:") || JCS(descriptor))
```

Receipts MUST commit the **`subroot_descriptor_digest`** — never a bare
file-tree hash. Same universe under a different protocol, contract version,
or prefix ⇒ different digest, and the receipt no longer transfers.

## 2. Snapshot object

```json
{
  "snapshot": "ecosystem.snapshot@v0",
  "bundle_root": "<hex64: sha256(ASCII(\"ecosystem-snapshot-v0:\") || JCS(this object with bundle_root zeroed))>",
  "subroots": [ { …descriptor…, "digest": "<subroot_descriptor_digest>" } ],
  "unclaimed": [ {"path": "…", "sha256": "<hex64>"} ],
  "closed": true
}
```

- JCS-canonical I-JSON; closed schema; one type tag; integers only.
- `unclaimed` (rev 2: now actually in the schema) lists bytes present in the
  bundle that no protocol judges — pinned, explicitly un-adjudicated. May be
  empty; MUST be present.
- Prefixes MUST NOT overlap; every sealed path belongs to exactly one subroot
  or to `unclaimed`.
- **`closed` means exactly one thing (rev 2 demotion):** this manifest lists
  every byte of **this** snapshot — nothing sealed is omitted from the
  listing. It is a *self*-completeness claim and nothing more. It does NOT
  detect that a member present in some earlier snapshot has vanished: a
  verifier cannot detect the absence of what this snapshot never committed
  to. Rev 1's implication that `closed:true` made omission detectable was
  false (seal A with {X,Y}; delete Y; seal B with {X}; every root of B is
  correct).

## 3. Inter-snapshot expectations (split out, rev 2)

Omission detection *between* snapshots is a separate obligation with its own
authority question — not every deletion between two seals is an attack, so
automatic monotonicity would be wrong. Sketch:

```json
{
  "expectation": "ecosystem.universe-expectation@v0",
  "expected_paths_root": "<hex64 over the JCS-sorted expected path+digest list>",
  "scope": "warrant",
  "authorized_by": "<WarrantID of the record adopting this expectation, or an external pin>"
}
```

A consumer holding `(prior_snapshot, candidate_snapshot, expectation)`
compares candidate against the expectation and reports omissions **against
that commitment** — attributably authorized, never inferred. Without an
expectation, cross-snapshot completeness honestly stays out of reach
(sev's `L-COMPLETE`).

## 4. Logical path / CAS contract (rev 2: formal)

"Prefixes don't overlap" is not a byte contract. The logical namespace is
defined independently of any host filesystem:

A **logical path** MUST be:

- a relative POSIX path, UTF-8, addressed by **exact Unicode code points —
  no NFC/NFD normalization, no case folding** (two paths differing only in
  normalization form are two distinct paths);
- with no leading `/`, no `.` or `..` components, no empty components
  (no `//`), no trailing `/`;
- containing no `\` (backslash) and no NUL anywhere;
- unique within the snapshot by exact code-point sequence.

The **sealer** MUST:

- read only regular files — symlinks, directories-as-members, devices,
  FIFOs, sockets are rejected (a symlink is a refusal, not a traversal);
- treat hardlinked duplicates as ordinary distinct paths with identical
  digests (content addressing makes this free);
- read every file exactly once; a file whose bytes change between listing
  and reading (size/digest disagreement on re-stat is not checked — the
  single read IS the commitment) is committed as the bytes actually read;
- refuse the whole seal on any path-rule violation — no skipping.

A **prefix** (rev 3) is a valid logical path plus **exactly one** trailing
`/`. The empty prefix is refused (it captures the whole namespace), and a
prefix without the trailing slash is refused (`.x` would capture `.xyz/…`).
With prefixes validated this way, membership by string `startswith` IS
component-boundary membership — no separate boundary rule is needed, and the
model tests exactly that (`'.x/'` does not capture `'.xyz/a'`).

**Universe ordering is normative (rev 3): ascending UTF-16 code units** —
the same comparator JCS uses for member names, so one ordering serves the
whole format. This choice is load-bearing: Python's default string order is
*codepoint* order, which disagrees with UTF-16 order on astral-vs-BMP pairs
(U+10000 sorts before U+E000 in UTF-16, after it by codepoint), and since
`universe` is a JSON array, JCS does not re-sort it — two implementations
sorting "naturally" would produce different subroot bytes. The model carries
the astral countervector.

**One total judgement (rev 3):** `validate_snapshot(snapshot, cas)` is the
only public verdict over a snapshot — bounded findings, empty means valid.
It checks, in addition to the outer self-hash: descriptor schema and type
tags; prefix validity; `protocol == contract.name`; unique protocol slots;
universe path validity, digest shape (`hex64`), prefix membership, and
normative ordering; `unclaimed` validity and placement (never inside any
prefix); the **partition invariant** (every path claimed by exactly one
subroot or `unclaimed` — the builder alone cannot enforce this, and rev 2's
model accepted a path claimed by both); **re-derivation of every embedded
`digest`** (a stale wrapper digest passes the outer self-hash, because the
outer hash faithfully commits the inner contradiction — only re-derivation
catches it); and CAS resolvability when a store is supplied.
`verify_bundle_root()` alone is explicitly NOT a validity check — it is one
step of `validate_snapshot`.

The **CAS layout** stores every object at `cas/<sha256>` and a resolver MUST
recompute `sha256(bytes)` on **every** load and refuse on mismatch — the
layout is a cache of the manifest, never an authority.

## 5. What it fixes (unchanged from rev 1, restated against rev 2 fields)

1. **Per-protocol judgement boundaries** — each `*.validation-receipt@v0`
   binds to its own `subroot_descriptor_digest`; SEV composes receipts and
   never launders one protocol's judgement into another's bytes.
2. **Receipt identity for consumers** — a downstream artifact names
   `(bundle_root, subroot_descriptor_digest, receipt_core_digest)`.
3. **Omission** — post-seal tamper is a root mismatch; pre-seal omission is
   detectable only against a `universe-expectation` (§3); `closed` claims
   only self-completeness (§2).

## 6. Non-goals (unchanged)

No trust semantics (receipts carry judgement, the snapshot only co-presence);
no governance (a bundle claims nothing on members' behalf); no
registry/service (a snapshot is a file; SCITT-shaped concerns stay
deliberately unclaimed).

## 7. Open questions

1. `contract.spec_digest` — **resolved in rev 3, split by layer**: the
   ecosystem format keeps it nullable (a null is honest for protocols without
   anchored specs), but a null is a fact the *consumer* judges — the Warrant
   receipt (rev 4) MUST refuse a warrant-slot descriptor whose `spec_digest`
   is null, because "0.4" is a human name while the SPEC bytes can move under
   it. The descriptor digest alone proves nothing if the consumer does not
   check the semantic role of its fields (model:
   `validate_warrant_descriptor_role`).
2. Should `unclaimed` entries be allowed under a subroot's `prefix`
   (protocol-adjacent junk), or must they live outside every prefix? Drafted
   as outside-only — inside-prefix junk should be the protocol verifier's
   problem, reported as its issues, not silently unclaimed.
3. Is per-subroot `closed` needed after the §2 demotion? Current answer: no —
   `closed` now describes the manifest, not member expectations, so one flag
   suffices; per-scope expectations live in §3 objects.
