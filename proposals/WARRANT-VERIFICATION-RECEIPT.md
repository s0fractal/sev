# Proposal: `warrant.verification-receipt@v0` — a snapshot-bound verification receipt

> **Ownership: SEV-originated design candidate. Not a Warrant contract and
> not adopted by Warrant.** If Warrant ever accepts this proposal, the
> normative version moves into the Warrant repository, SEV stops maintaining
> a normative copy and instead pins the Warrant artifact/version/digest, and
> this document remains here as provenance, marked superseded.

**Status:** PROPOSAL SKETCH **rev 5** (2026-08-10), design-only, not filed.
Rev 5 (fifth Codex review, AMEND — compositional layer): the public verdict
is now **`validate_warrant_receipt(snapshot, receipt, cas)`** in the model —
descriptor lookup by digest, semantic role check (incl. non-null
`spec_digest`) *inside* the composed verdict, **exact universe↔sources
bijection** (an empty `sources[]` against a populated universe is a finding,
so silent truncation is finally structurally impossible), per-source
`entry_digest` equality, and only then the internal core invariants. Both
validators are **total** (any parsed JSON → bounded findings, no host
exceptions; fuzz-tested), consume **raw bytes** through strict parsers
(duplicate members, trailing data, NaN/Infinity, floats, lone surrogates,
BOM, non-canonical bytes are refusals — object-level checks cannot see
these), every array has a **normative strictly-increasing order** (subroots
by (protocol, prefix, digest); unclaimed by path; sources by (path,
entry_digest); signatures by (sig_digest, multiplicity); reasons by ptr;
settlement by jurisdiction; policies by policy; runtimes by (runtime,
semantics_digest); issues by their JCS bytes — JCS does not sort arrays, so
unordered arrays let two conformant implementations emit different core
bytes), status→issue joins are **per-occurrence** (one WARN cannot cover two
mismatches — the join is on the exact reason `ptr`), reason domains are
closed (verdict ∈ {pass, fail}; `observed_result` hex64 for `ski@v1`;
`atp_spent` a non-negative safe integer ≤ the declared ceiling; `ptr` must
resolve in the committed record bytes to a reason hashing to
`reason_digest`; `not-applicable` only for registry-known normatively
non-executed runtimes, today `cmd@v1`), and severity is **grade-aware**
(`unverified` → WARN at base; ERR only at settlement grade on a
settlement-active record; `settlement[]` at base grade is itself a finding).

Previous history:
Target venue: `warrant/proposals/` as an ADR — a new Warrant contract.
Rev 2 narrowed the receipt to the Warrant subroot and split `core`/`producer`.
Rev 3 added the located issue multiset, `claimed_wid`/`computed_wid`, the
discriminated source union, structured reason outcomes, and semantics
anchors. Rev 4 applies the fourth Codex review (verdict AMEND): a closed
**locator union** for issue occurrences, normative **status→issue
implications** and a **total reason-outcome sum type** (both executable in
`model/snapshot_model.py: validate_receipt_core`), multiset sum notation
(`⊎`, not `∪`), and a mandatory **semantic role check** of the warrant-slot
descriptor including non-null `spec_digest`. Companions:
`ECOSYSTEM-SNAPSHOT.md` (rev 3), `PROV-EVIDENCE-VIEW.md` (sev),
`model/snapshot_model.py` (v2).

## Scope rule (unchanged)

> A Warrant verification receipt must not silently become the receipt of the
> whole ecosystem.

The receipt binds to exactly one Warrant subroot of a sealed
`ecosystem.snapshot@v0` bundle — specifically to its
**`subroot_descriptor_digest`** (rev 3: the domain-separated descriptor hash,
which commits protocol, contract version, prefix, and universe together —
never the bare file-tree hash, which transfers between identically-shaped
slots).

▲ **Rev 4 — the digest is not enough; the roles must be checked.** A Warrant
receipt producer and every consumer MUST verify the descriptor *semantically*
before trusting anything bound to its digest:

```
descriptor.protocol       == "warrant"
descriptor.contract.name  == "warrant"
descriptor.contract.version == the SPEC version the verifier implements
descriptor.contract.spec_digest is a non-null hex64
```

`spec_digest` nullable at the ecosystem layer stays nullable there; for the
Warrant slot a null is a refusal — `"0.4"` is a human name and the SPEC bytes
can change under it. Executable form: `validate_warrant_descriptor_role` in
the model, with a refusal vector for the null case.

## Core / producer split (unchanged from rev 2)

`core` is byte-reproducible across implementations *relative to* (snapshot,
trust, grade, declared execution policy); `receipt_core_digest =
sha256(JCS(core))` is the citable identity. `producer` is host-local and
carries no cross-implementation agreement.

## The receipt object (sketch, rev 3)

JCS-canonical I-JSON per warrant SPEC §4; closed schemas; one type tag.

```json
{
  "receipt": "warrant.verification-receipt@v0",
  "core": {
    "subroot_descriptor_digest": "<hex64 — the ecosystem.subroot@v0 identity>",
    "grade": "base | settlement",
    "trust_config_digest": "<hex64 over the RAW trust-config bytes as read | null iff base>",
    "execution_policy": {
      "runtimes": [
        { "runtime": "ski@v1",
          "semantics": "sigma-book-i@v0.5",
          "semantics_digest": "<hex64 — e.g. the Book I SpecAnchor atom>",
          "budget_unit": "atp",
          "ceiling": 100000000 }
      ]
    },
    "ok": true,
    "errors": 0,
    "warnings": 0,
    "global_issues": [
      { "code": "GENESIS_UNVERIFIED", "severity": "WARN",
        "at": { "kind": "path", "value": ".warrants/genesis.json" } }
    ],
    "sources": [
      {
        "kind": "record",
        "path": ".warrants/records/<claimed>.json",
        "entry_digest": "<hex64 of the raw bytes>",
        "loaded": true,
        "claimed_wid": "<from filename, or null>",
        "computed_wid": "<sha256(canon(body)), or null if uncomputable>",
        "id_sound": true,
        "issues": [
          { "code": "INVALID_SIGNATURE", "severity": "WARN",
            "at": { "kind": "json-pointer", "value": "/sigs/3" } },
          { "code": "INVALID_SIGNATURE", "severity": "WARN",
            "at": { "kind": "json-pointer", "value": "/sigs/4" } }
        ],
        "settlement": [
          { "jurisdiction": "<root WID>", "active": true,
            "policies": [ { "policy": "<hex64>", "threshold_satisfied": true } ] }
        ],
        "signatures": [
          { "sig_digest": "<hex64: sha256(JCS({actor,key,sig}))>",
            "multiplicity": 0,
            "actor": "<id>", "key": "<hex64>",
            "valid": true,
            "binding": "bound | unbound | unverified" }
        ],
        "reasons": [
          { "ptr": "/because/0",
            "kind": "check", "runtime": "ski@v1",
            "reason_digest": "<hex64>",
            "outcome": {
              "re_execution": "matched | mismatched | unverified | not-applicable",
              "claimed_verdict": "pass",
              "observed_verdict": "fail | null",
              "observed_result": "<NodeHash | null>",
              "atp_spent": 42,
              "failure_code": "OVER_BUDGET | MISSING_BLOB | MALFORMED_CHECK | RUNTIME_UNAVAILABLE | ORACLE_UNAVAILABLE | null"
            } }
        ]
      },
      { "kind": "blob",    "path": ".warrants/blobs/<hex64>", "entry_digest": "<hex64>",
        "loaded": true, "issues": [] },
      { "kind": "genesis", "path": ".warrants/genesis.json",  "entry_digest": "<hex64>",
        "loaded": true, "issues": [] },
      { "kind": "other",   "path": ".warrants/README",        "entry_digest": "<hex64>",
        "loaded": true, "issues": [] }
    ]
  },
  "producer": {
    "impl": "<free identifier>",
    "artifact_digest": "<hex64 | null>",
    "spec": "0.4",
    "report_digest": "<hex64: sha256 of the verify-report@v0 from the same run>",
    "local_notes": []
  }
}
```

## Design rules (rev 3 deltas marked ▲)

- ▲ **Issues are a located, ordered multiset — never a set.** Each issue is
  `{code, severity, at}`. Deduplicating `{code, severity}` pairs broke the
  counts: two invalid co-signatures are two WARN issues, and a set holds
  one — reintroducing, inside the new contract, exactly the
  counts-unbound-from-findings defect the receipt exists to fix. Normative
  invariants (executable: `validate_receipt_core`):

  ```
  errors   == count(all issues where severity == ERR)
  warnings == count(all issues where severity == WARN)
  ok       == (errors == 0)
  ```

  where *all issues* = `global_issues[] ⊎ every sources[].issues[]` — a
  **multiset sum** (rev 4: `∪` was set union, the exact operation that
  destroys the counts).

  ▲ **`at` is a closed locator union (rev 4)** — a bare JSON pointer cannot
  name occurrences in malformed bytes (invalid UTF-8 has no pointers) and
  cannot distinguish three duplicate members all pointing at `/body/actor`:

  ```json
  {"kind": "json-pointer", "value": "/sigs/3"}
  {"kind": "byte-range",   "start": 1024, "end": 1027}
  {"kind": "path",         "value": ".warrants/genesis.json"}
  {"kind": "global",       "value": "settlement"}
  ```

  plus an OPTIONAL `occurrence` ordinal (0-based) for issues whose locator
  is otherwise identical. Issue identity is `(source, at, occurrence, code)`;
  ordering is by that tuple.
- ▲ **`global_issues[]`** carries store- and settlement-level problems that
  belong to no single source file (invalid threshold policy, unverified
  genesis, missing jurisdiction root).
- ▲ **`claimed_wid` / `computed_wid`, both nullable.** For
  `records/<claimed>.json` whose body canonicalizes to a different WarrantID,
  rev 2's single `wid` was ambiguous (filename claim? recomputation?
  envelope?). Now: `claimed_wid` from the path (null if the filename is not
  wid-shaped), `computed_wid` from the body (null if uncomputable),
  `id_sound == (claimed_wid == computed_wid != null)`. Source identity
  remains `(path, entry_digest)` regardless.
- ▲ **Discriminated union over the whole universe.** `sources[]` covers
  **every** universe member of the Warrant subroot — records, blobs,
  `genesis.json`, and `other` — not records only; rev 2's completeness claim
  silently excluded malformed or wrong-digest blobs. `settlement`,
  `signatures`, `reasons` are permitted only on `kind:"record"`; a
  wrong-digest blob is a `kind:"blob"` source with an ERR issue.
- ▲ **Reason outcome is a TOTAL sum type (rev 4).** A bare
  `matched|mismatched|unverified` cannot feed the projection (on a mismatch
  the observed result exists nowhere in the snapshot), and rev 3's prose left
  the field combinations open — a receipt could claim `matched` while
  carrying observed `fail` for claimed `pass`. The matrix is now closed and
  executable (`validate_receipt_core`):

  | `re_execution` | `observed_verdict` / `observed_result` / `atp_spent` | `failure_code` | extra constraint |
  |---|---|---|---|
  | `matched` | all non-null | null | `observed_verdict == claimed_verdict` |
  | `mismatched` | all non-null | null | `observed_verdict != claimed_verdict`; a `REASON_MISMATCH` WARN issue MUST exist |
  | `unverified` | all null | non-null, closed enum | code consistent with `execution_policy` (`RUNTIME_UNAVAILABLE` impossible for a policy-listed runtime; `OVER_BUDGET` impossible for an unlisted one); a `REASON_UNVERIFIED` issue MUST exist — WARN at base, ERR when the record is settlement-active |
  | `not-applicable` | all null | null | permitted ONLY for runtimes the verifier normatively does not execute (not in `execution_policy.runtimes`) |

  Closed failure codes: `OVER_BUDGET | MISSING_BLOB | MALFORMED_CHECK |
  RUNTIME_UNAVAILABLE | ORACLE_UNAVAILABLE`. Additionally the reason `ptr`
  MUST resolve inside the computed body to bytes matching `reason_digest`,
  and `observed_result` carries a runtime-specific shape (for `ski@v1`: a
  Σ-GLYPH NodeHash).

- ▲ **Status→issue implications are normative (rev 4).** Counts bound to
  issues were not enough — the semantic statuses could still contradict them
  (an `ok:true, errors:0` core with `id_sound:false` was expressible).
  Closed implication set, executable in `validate_receipt_core`:

  ```
  loaded:false                      => >=1 ERR issue on that source
  id_sound:false (loaded record)    => >=1 ERR issue on that source
  id_sound == (claimed_wid == computed_wid != null)
  signature valid:false             => a matching INVALID_SIGNATURE WARN occurrence
  signature valid:false             => binding != "bound"  (bound implies a valid
                                       signature by a currently-bound key; an
                                       invalid one cannot be bound)
  outcome mismatched                => REASON_MISMATCH WARN
  outcome unverified                => REASON_UNVERIFIED WARN (base) / ERR
                                       (settlement-active record)
  invalid policy / threshold        => scoped issue on the settlement entry
  ```

  JSON Schema cannot express these; the executable validator is part of the
  contract, and its refusal vectors (including the fully contradictory core
  that motivated this rule) are conformance vectors.
- ▲ **Runtime semantics are anchored.** `runtimes_available: ["ski@v1"]`
  named a tag, not semantics. Each entry now pins `semantics` +
  `semantics_digest` (for `ski@v1`: the Σ-GLYPH Book I anchor), plus
  `budget_unit` and `ceiling`. Two verifiers agreeing on the tag but running
  different Book I revisions now produce visibly different cores instead of
  silently incomparable ones.
- ▲ **`trust_config_digest` is over the RAW bytes as read** — not over a
  canonicalized semantic trust object. Rationale: the fail-closed rule (SPEC
  §7/§12.3) is about the exact configuration consumed; two syntactically
  different but semantically equal configs are two different verification
  inputs, and pretending otherwise requires a canonical trust semantics that
  no contract defines. The cost — semantically-equal configs yield different
  cores — is accepted and documented.
- **Unchanged from rev 2:** signature identity `sha256(JCS({actor,key,sig}))`
  + `multiplicity`; reason identity `(computed_wid, ptr, reason_digest)`;
  jurisdiction-scoped `settlement[]` (SPEC §9); binding vocabulary
  `bound|unbound|unverified` (SPEC §5.1); `ok` binds `errors`; no wall-clock
  anywhere; fail-closed on unconstructable trust.

## What this proposal is not (unchanged)

Not a transparency log, not SCITT, not countersigned; authority = independent
re-derivability of `core` given the same snapshot + declared execution
policy. Not implemented. Conformance vectors' refusal halves now include:
issue set-dedup (two same-code issues collapsed) ⇒ counts mismatch ⇒
non-conformant; `settlement` as boolean ⇒ schema-invalid; a `kind:"record"`
field on a blob source ⇒ schema-invalid; `observed_result` present with
`re_execution:"unverified"` ⇒ schema-invalid; receipt bound to a bare
file-tree hash ⇒ not this contract.

## v0 freeze candidate (round-6 R6)

Candidate frozen surface: `core`/`producer` split with
`receipt_core_digest`; the counts invariants (`errors`/`warnings`/`ok` bound
to the issue multiset); the universe↔sources bijection; source identity
`(path, entry_digest)` with `claimed_wid`/`computed_wid`; the reason-outcome
sum type. Extension points until separately frozen: the issue-code registry,
locator grammar details, `execution_policy` runtime entries beyond `ski@v1`,
settlement entry internals. Freeze happens on the first review round with
zero P1 findings — a maintainer act, not this document's.

## Open questions

1. `universe` no longer appears in `core` (it lives in the subroot
   descriptor, which the digest commits). Should the receipt still inline it
   for self-containment, at the cost of duplication with the snapshot?
   Leaning no — one authority per fact; the snapshot is required context.
2. Issue-code registry granularity (unchanged).
3. ~~Byte offsets for non-JSON sources~~ — resolved in rev 4 by the closed
   locator union (`byte-range` kind + optional `occurrence` ordinal).
4. `producer.artifact_digest` MUST-for-released-artifacts (unchanged).
