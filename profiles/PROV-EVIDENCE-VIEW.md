# Profile: PROV Evidence View (sev@v0) — rev 2.2

**Status:** DRAFT rev 2.2, non-normative, unplaced, research draft — **not
adoptable until `warrant.verification-receipt@v0` (rev 3),
`ecosystem.snapshot@v0` (rev 2), AND per-protocol OAIP/BOS validation
receipts exist**. The blocking is per-quadrant: a Warrant receipt licenses
projecting the Warrant quadrant only; OAIP and BOS quadrants stay
L-UNJUDGED (bytes pinned, nothing asserted) until their own protocols
define and produce receipts — a sev dataset never upgrades one protocol's
judgement into another's.
Rev 2 applied the first Codex review (sealed snapshot, weak-default
predicates, per-bundle graphs, content-addressed skolems, canonical
encoder). Rev 2.1 applies the second (verdict AMEND on rev 2): per-protocol
receipts composed over a neutral snapshot, attribution requires
valid+bound, note-only joins can no longer block export, Filing identity
from the snapshot entry, verification graphs named by receipt core digest,
no NFC on source-derived strings. Written against warrant SPEC v0.4, OAIP
SPEC v0.1, BOS-0001 rev 4, Σ-GLYPH v0.6.7. Section numbers decay; re-check
before relying.

> **PROV-O here is a readable projection, not a trust boundary.** The graph
> proves nothing by itself; verification lives in `warrant verify`, OAIP's
> bridge refusal, and Σ-GLYPH re-execution, and is *witnessed* by the
> verification receipt. On any divergence between the graph and the
> content-addressed stores it was derived from, the stores win.

The value statement this profile serves (Codex, 2026-08-09):

> We turn *asserted* provenance into provenance with verifiable identity,
> authority state, settlement receipt, and re-executable claims.

Semantica-class systems already export PROV-O. What they cannot emit — and
what this view carries as data — is: settlement grade, key-bound signature
state, a re-execution verdict distinct from "was not executed",
observer-relative assessments that never deduplicate, and a machine-readable
list of what the graph *cannot* express (`loss_manifest`, §8).

---

## 0. Pipeline

```
Sealed Ecosystem Bundle  (ecosystem.snapshot@v0)
├── bundle_root
├── warrant_root ─→ warrant.verification-receipt@v0   (exists as rev-2 proposal)
├── oaip_root    ─→ oaip.validation-receipt@v0        (future, owned by OAIP)
└── bos_root     ─→ bos.validation-receipt@v0         (future, owned by BOS)
                 │
                 ▼
        sev projector  (pure function of bundle bytes + all applicable receipts)
                 ▼
    SEV Dataset (canonical N-Quads) + view-manifest + loss_manifest
```

**Each protocol judges only its own subroot.** The Warrant verifier
understands Warrant records, trust, and Warrant runtimes — it can pin OAIP or
BOS bytes but has no right to call them verified, and its receipt binds to
`warrant_root` only. The projector composes per-protocol receipts over the
neutral snapshot; it never launders one protocol's judgement into another's
bytes. Subroots with no receipt project as *unadjudicated* (loss L-UNJUDGED).
The projector performs no verification and no filesystem re-reads: it
consumes the sealed bundle exactly once. Any root mismatch ⇒ refuse (named
error, non-zero exit).

## 1. Input rules

- **R1 (receipt-bound, MUST).** Input is (sealed bundle, set of per-protocol
  receipts). The projector recomputes each **subroot descriptor digest**
  (domain-separated, committing protocol+contract+prefix+universe — see
  `ECOSYSTEM-SNAPSHOT.md` §1) from the bytes it actually read and requires
  each receipt's `core.subroot_descriptor_digest` to match. A receipt bound
  to a bare file-tree hash is not accepted — same-shaped universes under
  different protocol slots must not exchange receipts. The projector never
  runs a verifier and never trusts a judgement that isn't descriptor-bound.
  TOCTOU between verify and project is thereby a hash mismatch, not a
  possibility.
- **R2 (grade stamping, MUST).** Per receipt: `grade`, `ok`, `errors`,
  `warnings` and the `receipt_core_digest` are copied into the view manifest
  and graph. `ok:true` means "no §6 error at the requested grade"; the
  projection MUST NOT paraphrase it as "trustworthy".
- **R3 (cardinal rule, proof-gated in both directions, MUST).** Mirroring
  OAIP §4 (*execution success ≠ validation success ≠ acceptance*):
  - The projector **asserts** an adjudication→claim link only on a
    content-addressed join — the accept's `evidence[]` contains the digest of
    the claim's canonical record bytes (`record:claim` artifact) — **and**
    the claim's subroot carries an OAIP validation receipt covering it. The
    `subject.note = "oaip-claim:<id>"` prefix asserts nothing: an event id is
    not content-addressed. (Content-addressed joins need an OAIP SPEC §3
    bridge amendment; until then most accepts project with L-JOIN and no
    asserted link.)
  - The projector **refuses** to export only on the same proof grade: a
    content-addressed join to a receipt-covered claim whose
    `validation.verdict != "pass"` aborts export with a named error.
  - A note-only match — in either direction — produces **only** a
    loss-manifest entry (L-JOIN): no edge, no refusal. Rev 2 let a note-match
    trigger global refusal, which handed anyone able to drop a fail-claim
    with a matching event id into an optional `oaip/` directory a veto over
    projecting an honest Warrant receipt — suspicion-keyed refusal is a
    censorship primitive, not a safety property.
- **R4 (id-soundness, MUST).** Only sources the Warrant receipt marks
  `id_sound` with no ERR-severity issues become Warrant graph nodes.
  Malformed sources (`loaded:false`, `wid:null`) and excluded records are
  counted in the view manifest with their structured `issues[]` codes — never
  silently dropped, never given record IRIs.

## 2. Identity: hash-derived IRIs, zero blank nodes

Everything is skolemized; the dataset contains no blank node in any term
position (checked per §10 N4 — an encoder invariant plus an independent
parse, **not** a grep: the substring `_:` may legitimately occur inside
literal prose).

| Thing | IRI template |
|---|---|
| Warrant record | `urn:wrt:record:<WarrantID>` |
| Warrant blob | `urn:wrt:blob:<sha256>` |
| Filing activity | `urn:wrt:filing:<entry_digest>` — the digest of the envelope bytes in the snapshot (`sources[].entry_digest`), NOT the WarrantID: the WarrantID identifies the body, while the envelope grows under co-signatures; each sealed envelope occurrence is one filing |
| Signature | `urn:wrt:sig:<sha256(JCS({actor,key,sig}))>:<multiplicity>` |
| Actor | `urn:wrt:actor:<pct-encoded actor string>` |
| Σ-GLYPH node | `urn:sigma:node:<NodeHash>` |
| Source occurrence | `urn:sev:source:<sha256(subroot_descriptor_digest ‖ 0x00 ‖ path ‖ 0x00 ‖ entry_digest)>` — `sourceKind` is contract-derived, so the occurrence is scoped to the descriptor that derived it |
| Reason (stable fact of a record) | `urn:wrt:reason:<sha256(WID ‖ 0x00 ‖ JSON-pointer ‖ 0x00 ‖ reason_digest)>` — an Entity. Carries `sev:pointer`, `sigma:runtime`, `sigma:claimedVerdict`, `wrt:checkRef` (literal digest) and, when that blob is sealed in the same subroot, `wrt:checkBlob`. **Never `prov:used`** — that predicate's domain is an Activity |
| Check run (one execution of a reason) | `urn:sigma:run:<sha256(receipt_core_digest ‖ 0x00 ‖ WID ‖ 0x00 ‖ JSON-pointer ‖ 0x00 ‖ reason_digest ‖ 0x00 ‖ semantics_digest)>` — an Activity. Two verifications of the same reason under different declared semantics are two runs; keying on the reason alone fused them once datasets merged, and a named graph scopes statements without localizing IRIs |
| OAIP record | `urn:oaip:record:<sha256 of JCS-canonical record bytes>` |
| OAIP blob/artifact | `urn:oaip:blob:<sha256>` |
| BOS atom (semantic id) | `urn:bos:atom:<pct-encoded bos id>` |
| BOS revision (content id) | `urn:bos:rev:<sha256>` |
| Qualified node | `urn:sev:q:<sha256(parentIRI ‖ 0x00 ‖ role ‖ 0x00 ‖ ordinal)>` |
| Named graph | see §5 — one per source assertion bundle |

Rev 2 identity fixes (both were unstable in rev 1):

- **Signatures** are identified by the digest of their canonical bytes plus a
  multiplicity index for exact duplicates — never by array position. The
  envelope is not hashed or signed (warrant SPEC §5): co-signatures append
  without moving the WarrantID and no canonical `sigs` order exists, so
  positional identity breaks under legitimate envelope growth.
- **Σ-GLYPH runs** are identified per *occurrence*: WarrantID + JSON pointer
  + canonical-reason-bytes digest (all three present in the receipt's
  `reasons[]` entries). Two occurrences of one check blob in one record —
  even with different claimed verdicts — are two nodes.

OAIP event records (intent/execution/effect/attribution/claim) are minted
from their **canonical record bytes** (the `record:<type>` artifact kind
names this blob); the ledger-local event `id` is a plain property
`oaip:eventId`, never identity. BOS atoms get two linked IRIs:
`urn:bos:rev:… prov:specializationOf urn:bos:atom:…`. No other aliasing
exists; in particular BOS `equivalent_to` NEVER becomes `owl:sameAs` (§4.3).

## 3. Namespaces

```
@prefix prov:  <http://www.w3.org/ns/prov#> .
@prefix sev:   <https://s0fractal.dev/ns/sev#>
@prefix wrt:   <https://s0fractal.dev/ns/wrt#>
@prefix oaip:  <https://github.com/s0fractal/oaip/ns#>
@prefix bos:   <https://s0fractal.dev/ns/bos#>
@prefix sigma: <https://s0fractal.dev/ns/sigma#>
```

Every class is `rdfs:subClassOf` a PROV class: a generic PROV consumer sees
valid PROV and ignores extensions. The `oaip:` vocabulary must be ratified in
the OAIP repo before this profile leaves DRAFT — it is their lexicon.

## 4. Mapping

**Rev 2 principle — start weak, promote on evidence.** Rev 1 mapped Warrant
fields onto strong PROV relations the records do not actually establish. Rev 2
defaults every claim-shaped field to a weak `wrt:` predicate and promotes to a
PROV relation only when the receipt licenses it:

| Weak default (always emitted) | Promotes to | Iff the receipt shows |
|---|---|---|
| `wrt:claimedActor` (IRI) | `prov:qualifiedAssociation` + `prov:wasAssociatedWith` | at least one signature with `valid:true`, `binding:"bound"`, `actor == body.actor` |
| `wrt:declaredTimestamp` (literal from `ts`) | — never — | `ts` is a declared number; nothing proves activity timing |
| `wrt:prior` (record→record) | `prov:wasDerivedFrom` | — deferred; Warrant defines no semantics for `prior` beyond DAG ancestry, so rev 2 emits only the weak edge (rev 1 emitted both `wasInformedBy` and `wasDerivedFrom`; neither is warranted) |
| `wrt:Filing ⊑ prov:Activity` (every record) | `wrt:Adjudication ⊑ wrt:Filing` | `decision ∈ {accept, reject, supersede}`; `propose` is not an adjudication (the enum is `propose\|accept\|reject\|supersede`) |

The record entity `prov:wasGeneratedBy` its `wrt:Filing` — filing is the act
of producing the record bytes. The decision verdict is an attribute of the
filing (`wrt:verdict`), signatures are separate entities (§4.1): rev 1's
single "adjudication generated the record" conflated filing, signing, and
deciding into one activity; rev 2 keeps them apart.

### 4.1 Warrant → PROV

| Warrant | PROV (weak defaults per table above) |
|---|---|
| record (canonical body bytes) | `wrt:Warrant ⊑ prov:Entity`, `prov:wasGeneratedBy` its filing |
| filing | `wrt:Filing ⊑ prov:Activity`; `wrt:verdict`, `wrt:declaredTimestamp` |
| `actor` | `wrt:claimedActor`, promotable per table |
| `under[]` | each → `prov:Plan` (`urn:wrt:blob:…`) via `prov:hadPlan` on the (promoted) association; where unpromoted, `wrt:underPolicy` |
| `subject` / `evidence[]` | `prov:Entity` + `prov:qualifiedUsage` with `sev:role "subject"` / `"evidence"` |
| `because[]` prose | `wrt:prose` literal |
| `because[]` check | reason-occurrence activity, §4.4 |
| `prior[]` | `wrt:prior` |
| `sigs` | `wrt:Signature ⊑ prov:Entity`; `wrt:sigValid`, `wrt:binding` (`bound`/`unbound`/`unverified` — SPEC §5.1's own triple, no invented states) copied from the receipt; `prov:wasAttributedTo` the named agent **only when `valid:true` AND `binding:"bound"`** — validity proves *this key signed this WarrantID*, not *this key belongs to this actor*; valid-but-unbound emits `wrt:claimedSigner` instead |
| settlement / threshold | one skolem `wrt:SettlementStatus` node per `(record, jurisdiction root)` pair with `wrt:jurisdiction`, `wrt:active`, and per-policy `wrt:thresholdSatisfied` — copied from the receipt's scoped `settlement[]`. Never a global boolean: SPEC §9 makes adoption jurisdiction-scoped (active for root A, inactive for root B, same store). The graph never claims to demonstrate quorum (L-THRESH) |

### 4.2 OAIP → PROV

Base table adopted from OAIP SPEC §9.1 verbatim; extensions marked ✚:

| OAIP | PROV |
|---|---|
| `execution` | `oaip:Execution ⊑ prov:Activity`; `oaip:exitCode`, `oaip:status` |
| `artifact`, `state`, blobs | `prov:Entity` |
| actors | `prov:Agent` + ✚ `oaip:unauthenticated true` (OAIP actor strings are declared, not authenticated — omitting the flag would launder attribution) |
| `attribution` | qualified `prov:Attribution` + ✚ `oaip:confidencePpm` (≤ 999999 by design), `oaip:method` |
| `effect` | `prov:wasGeneratedBy` / `prov:wasInvalidatedBy` per kind |
| `intent` | ✚ `oaip:Intent ⊑ prov:Entity` via `oaip:declaredFor`; "no PROV equivalent" per OAIP's own table; loss L-INTENT. Deliberately NOT `prov:hadPlan` — that slot carries *policies* (§4.1), and an unauthenticated goal must not be confusable with an authority-bearing plan |
| `claim` | ✚ `oaip:ClaimCandidate ⊑ prov:Entity`; its `validation{…}` becomes ✚ `oaip:Validation ⊑ prov:Activity` (`prov:used` check blob, `prov:generated` transcript, `oaip:verdict`) |
| acceptance | not an OAIP node — it is a warrant adjudication; linked `prov:used` **only via the content-addressed join of R3** |

The cardinal rule survives structurally: three activities of three classes
(`oaip:Execution`, `oaip:Validation`, `wrt:Adjudication`), connected only by
explicit, receipt-licensed edges. A SHACL shape requires every accepting
adjudication that reaches a ClaimCandidate to reach a `pass` Validation —
noting SHACL checks shape, not truth; truth was checked at R1/R3.

### 4.3 BOS → PROV

| BOS | PROV |
|---|---|
| `actor` | `prov:Agent` (`actor_class` → `prov:Person`/`prov:SoftwareAgent`) |
| `trajectory` | `bos:Trajectory ⊑ prov:Activity`; `supplied_set`→`prov:used` + `bos:exposureOnly true` (availability, not attention); `produced`→`prov:generated` |
| `context_cut` | `bos:ContextCut ⊑ prov:Entity`; member repos with `bos:commit` |
| `assessment` | `bos:Assessment ⊑ prov:Entity` in its assertion-bundle graph (§5); scalar `bos:lens`, singular `bos:stakeholder`, `bos:objective`, `bos:horizon`; every `assessed_by` actor (the field is **plural**) → `prov:wasAttributedTo` edge |
| structural `relations[]` | direct triples: `derived_from`→`prov:wasDerivedFrom`, `observes`→`prov:used`, `produces`→`prov:wasGeneratedBy`, `changes`→`prov:wasInfluencedBy`, rest `bos:<predicate>` |
| `relation_claim` | skolem reification node `bos:RelationClaim ⊑ prov:Entity` (`sev:subject/predicate/object` + `bos:confidence`, `bos:falsifier`, `bos:observedIn`, attributed to author) — not a direct triple, not RDF-star; refutation adds nodes, never mutates endpoints |
| `equivalent_to` | a `bos:RelationClaim` like any other; **never `owl:sameAs`**; symmetric folding stays query-time |
| `evidence` | `prov:Entity` + `bos:sourceFidelity`, `bos:digest` |
| `verification_class` | literal; `adjudicated`/`research` also listed under L-VCLASS |
| governance status | six axis literals; `proposed` MUST NOT render as adopted |

### 4.4 Reason and check run → PROV

**Two objects, never one.** The reason is a fact of the record; the run is
one verification of it. This section is normative; the change ledger below
records only how it got here.

```
urn:wrt:reason:<…>  a wrt:Reason ;                 # ⊑ prov:Entity
    sev:pointer "/because/<i>" ;
    sigma:reasonDigest "<hex64>" ;
    sigma:runtime "ski@v1" ;
    sigma:claimedVerdict "pass" | "fail" ;
    wrt:checkRef "<hex64 of the committed check blob>" ;
    wrt:checkBlob urn:wrt:blob:<check> .           # ONLY if sealed in this subroot

urn:wrt:record:<WID>  wrt:hasReason  urn:wrt:reason:<…> .

urn:sigma:run:<…>  a sigma:CheckRun ;              # ⊑ prov:Activity
    prov:used urn:wrt:reason:<…> ;
    prov:used urn:wrt:blob:<check> ;               # ONLY when it actually ran
    prov:wasInformedBy urn:wrt:record:<WID> ;
    sev:receiptCoreDigest "<hex64>" ;
    sigma:semanticsDigest "<hex64 from execution_policy>" ;
    sigma:reExecution "matched" | "mismatched" | "unverified" ;
    sigma:observedVerdict "<from outcome, absent if not run>" ;
    prov:generated urn:sigma:node:<observed_result> ;   # absent if not run
    sigma:atpSpent "<int, absent if not run>"^^xsd:integer ;
    sigma:failureCode "<closed code, only when unverified>" .
```

Rules this shape enforces:

- **A Reason never carries `prov:used`.** Its PROV domain is an Activity;
  hanging the check edge on the Entity re-fuses the two objects. The Reason
  *names* its check (`wrt:checkRef`) and, only when that blob is sealed in
  the same subroot, *points at* it (`wrt:checkBlob`).
- **`prov:used` on the check blob is emitted only for `matched`/
  `mismatched`.** An `unverified` run used nothing — asserting otherwise
  describes an execution that did not happen. `MISSING_BLOB` keeps the weak
  reference and nothing more.
- **`matched`/`mismatched` require the check blob to be AVAILABLE in this
  subroot** (`CHECK_BLOB_ABSENT`): warrant SPEC §6 resolves the check as a
  blob, and §6(7) keeps "re-ran" and "could not run" observationally
  distinct, so a re-execution over an unavailable blob is an impossible
  verdict, not a detail. "Available" is a single predicate — the source is
  a `blob`, is loaded, and carries no ERR issue. A digest that exists only
  as a README (`other`), as a record, or as a blob the manifest excludes
  does **not** resolve a check reference; the verdict and the projection
  share that one definition, so the graph can never claim to have used what
  the manifest reports as excluded.

- **A producer-asserted field never relaxes a rule.** Receipt-reported
  `valid`/`binding` are claims SEV cannot verify and whose producer is not
  authenticated; they may constrain the receipt's internal consistency, but
  they may not buy a severity downgrade for anything else in it. Malformed
  signature occurrences are therefore always ERR — stricter than warrant
  SPEC §5, deliberately, because the alternative is SEV re-implementing
  Warrant's cryptography and thereby judging another protocol's bytes.
- **Acknowledgement is semantic.** A malformed occurrence counts as
  reported only when the receipt carries an issue matching the normative
  `(pointer, code, severity)` tuple; an unrelated issue at the same pointer
  legalises nothing. Presence for `coverage`/`L-NO*` is derived from the
  total derivation, so a malformed signature is signature evidence — never
  absence — even when no `signatures[]` entry exists for it.
- **Malformed committed evidence is evidence, not absence.** Derivation
  over the envelope is total: unparseable `sigs`/`because` shapes become
  located malformed occurrences the receipt must report, never an empty
  expected set. Otherwise "this dataset holds no signature evidence" could
  mean "the committed signature was malformed and nobody said so".
- **Coverage is only as honest as the receipt's completeness.** A
  dataset-relative statement (`coverage`, `L-NO*`) presupposes that the
  receipt reports everything the committed bytes contain: signatures bound
  to the envelope's `sigs[]` and one reason per committed `kind:"check"`
  entry. Without that bijection, "this dataset holds no signature evidence"
  degrades to "the receipt did not mention any".
- **Projection reads only the validated view.** The verdict freezes private
  copies of snapshot, receipt, descriptor and committed reasons, and the
  projector consumes those — never the caller's objects, never the store.
  Otherwise a caller whose objects change between the two phases gets a
  graph asserting a core the validator never saw.

Every `sigma:*` value is copied from the receipt's structured
`reasons[].outcome`, never computed by the projector — rev 2.2 note: this is
only possible because the receipt (rev 3) carries the full outcome; a bare
`matched|mismatched|unverified` cannot supply `observedResult`, which on a
mismatch exists nowhere in the snapshot. Warrant SPEC §7's rule — *"re-ran and matched" and
"was not executed" MUST NOT be observationally equivalent* — holds in-graph:
`unverified` is a distinct literal, surfaced again in the view manifest when
it touches a settlement-active record. These are data about a verification
that happened, not a verification (L-REEXEC).

## 5. Named graphs: assertion bundles, not "observers"

Rev 1 keyed graphs on a single `observerIRI`. BOS assessments have **one or
more** `assessed_by` actors (both dual-lens fixtures carry the same two), so a
singular observer does not exist and would have had to be invented. Rev 2
partitions by **source assertion bundle**:

- **Default graph:** topology and identity only — records, blobs, activities,
  structural edges. Not "facts no one owns" (rev 2's phrasing was wrong):
  the topology is the **projector's** claim about the sealed bundle, and the
  view manifest attributes it — `profile_revision` + projector identity own
  every default-graph triple. What distinguishes the default graph is that
  its claims are mechanically re-derivable from the bundle bytes by anyone,
  not that they are ownerless.
- **One named graph per BOS atom revision:**
  `urn:sev:g:bos:<revision sha256>`, a `prov:Bundle` with a
  `prov:wasAttributedTo` edge **per assessor** (plural welcome). Attribution
  is edges on the bundle, not an identity component of the graph name.
- **One verification graph per receipt core:**
  `urn:sev:g:verify:<receipt_core_digest>`, holding signature
  validity/binding, re-execution statuses, scoped settlement nodes, and the
  receipt entity, generated by a `sev:VerificationActivity` performed by a
  `prov:SoftwareAgent`. Keyed by the **core digest, not the snapshot root**:
  base vs settlement grade, different trust roots, or different execution
  policies over the same snapshot are different judgements and must not
  collapse into one graph. **The verifier is not an observer.**
  Mechanical verification and subjective appraisal are different roles;
  rev 1's framing of the verifier as "an observer too" re-mixed fact-checking
  with interpretation — exactly the confusion BOS exists to prevent. The
  partition is for scoping (two verifiers' receipts coexist without merge),
  and carries no appraisal semantics.

Two assessments of one subject — different lens, same assessors, or any other
combination — are two atoms, hence two revisions, hence **two graphs,
permanently**. No dedup, no supersession inference, no resolution: the
dataset is a source of *attribution*, never a single source of meaning
(BOS principle `attribution-not-semantic-ssot`; deliberate contrast with
semantica's "single shared intelligence layer").

## 6. What travels, what doesn't

> **`coverage` is dataset-relative, not a capability list.** Its `emitted`
> set is derived from what the run actually put in the graph and its
> `not_emitted` set from evidence the input actually held; a static list of
> what the projector *could* emit would claim categories absent from the
> input. If a capability list is ever wanted, it belongs in a separate
> `projector_capabilities` field with `supported`/`unsupported`, never here.
>
> **Target profile vs current MVP coverage.** Everything in this section
> describes the *target* `sev@v0` mapping. The reference projector
> (`model/sev_projector.py`) implements a deliberately narrow subset and
> declares the gap machine-readably — see the coverage block in §9 and the
> `L-NO*` codes in §8. Where this section says a class of evidence is
> "carried" and the MVP does not emit it, the MVP is not in violation: it is
> required to say so, and it does. A reader MUST take the emitted
> `coverage` block, not this prose, as the statement of what a given
> dataset contains.

Carried as data: `term_hash`/`result_hash`/`atp`, grade, per-signature
validity+binding, re-execution status, threshold flags, confidence_ppm,
source_fidelity, verification_class, context-cut commits, content hashes for
every entity. **Not carried, by construction:** the ability to re-verify any
of it from the graph alone. OAIP SPEC §9.1's caveat is adopted as a profile
rule: a consumer MUST NOT expect to recover JCS bytes, BOS file bytes, or
WarrantIDs from the graph; identities are recomputable only from the sealed
snapshot.

## 7. Serialization: canonical N-Quads by normative encoder

Zero blank nodes removes the *hard* part of RDF canonicalization (label
assignment) but not the lexical freedom of N-Quads — raw vs `\uXXXX`
escapes, literal escaping, datatype forms, IRI percent-encoding, duplicate
quads, numeric lexical forms. "Serialize then sort lines" does not give
cross-implementation byte equality. Therefore:

1. Output is the **canonical N-Quads form of RDFC-1.0** (its serialization
   rules for escaping and code points), with the c14n labeling step vacuous —
   there is nothing to relabel. Where this profile's encoder must choose
   beyond RDFC-1.0: UTF-8; **no Unicode normalization of any source-derived
   string, ever** — Warrant deliberately distinguishes NFC from NFD (exact
   code points, no NFC/NFD folding), so an NFC pass would change identity
   strings; rev 2 said "NFC … as produced" alongside "never re-normalize",
   which contradicted itself, and the normalization half loses. Typed
   literals in XSD canonical lexical form, no language tags, duplicate quads
   dropped before sort. Profile-minted IRIs are ASCII-only by construction,
   so the no-normalization rule costs nothing there.
2. Quads sorted by codepoint, one per line, exactly one trailing LF.
3. The export is a **pure function** of (snapshot, receipt): no run
   timestamps, no tool versions inside the graph (they live in the view
   manifest).
4. `sha256(nquads)` is the view digest — anchorable, citable as warrant
   evidence, listable in an evidence-pack manifest.
5. Turtle/JSON-LD may be derived for humans; they are presentation, carry no
   digest, and are inputs to nothing.

Until the encoder appendix is written to the last escape byte, conformance
N5b (two independent implementations, byte-identical output) is the
acceptance test that decides whether the appendix is complete.

## 8. `loss_manifest` — first-class honesty

Emitted alongside the graph as JCS-canonical JSON. Codes:

| Code | Property the graph cannot express or verify |
|---|---|
| L-SIG | Signature validity/binding are receipt-reported; Ed25519 re-verification needs envelope bytes |
| L-SETTLE | Settlement closure/grade are not re-derivable from the graph; they need `warrant verify` over the snapshot with out-of-band trust |
| L-KEYSTATE | Key rotation history is collapsed to per-signature `binding` at one DAG position |
| L-THRESH | Quorum is receipt-asserted, not demonstrable by counting graph nodes (unbound claims must not count; the graph cannot enforce this) |
| L-REEXEC | `sigma:reExecution` records a past run; the graph cannot re-execute |
| L-JOIN | An accept whose claim-join is note-prefix-only projects **without** an asserted adjudication→claim edge; the link awaits a content-addressed join (OAIP bridge amendment) |
| L-CANON | Canonical bytes (JCS, BOS raw-file, Σ-GLYPH node) are not recoverable; hashes are copied, not recomputable |
| L-INTENT | OAIP Intent has no PROV semantics; generic consumers see an opaque entity |
| L-VCLASS | `adjudicated`/`research` requirements are marked only by a literal |
| L-COMPLETE | Completeness is relative to the sealed snapshot's universe, never global (an `expected.closed` snapshot commitment upgrades omission to a detectable event — see `ECOSYSTEM-SNAPSHOT.md`) |
| L-UNJUDGED | A subroot present in the bundle carries no validation receipt from its own protocol; its bytes are pinned but unadjudicated |

**Absence codes (`L-NO*`) — what the projection does not emit at all.** The
codes above qualify facts that ARE in the graph; these declare facts that
are NOT. Emitted only when the corresponding data actually exists in the
receipt or snapshot, so a manifest never claims a loss it does not have:

| Code | Declares |
|---|---|
| L-NOSIG | The receipt carries signature results (validity/binding) and the projection emits no signature nodes at all |
| L-NOSETTLE | The receipt carries jurisdiction-scoped settlement and the projection emits no settlement nodes at all |
| L-NOUNCLAIMED | The snapshot pins `unclaimed` members that are not projected |
| L-NOMAP | The §4.1 record-body mapping (actor, `under`/Plan, subject, evidence, `prior`) is not implemented by this projector |

A caveat on an absent fact is worse than silence: it reads as
"present, with reservations". Hence the split — qualify what is there,
declare what is not.

**Every entry is dataset-relative.** This applies to the qualifying codes
too, not only the `L-NO*` family: `L-REEXEC` only where a check run was
emitted, `L-SETTLE` only where signature/settlement evidence exists,
`L-CANON` only where the graph is non-empty, `L-NOMAP` only where a record
was actually projected. A blob-only subroot therefore carries neither — a
manifest that listed record, reason and signature losses over a dataset
holding none of them would be making exactly the claim this section
forbids.

Each entry carries `code`, `affects` (IRIs or `"*"`), and `recheck` — an
**argv array** plus the digest of the tool/profile that interprets it
(`{"argv": ["warrant", "--store", "…", "verify"], "tool_digest": "<hex64>"}`),
not a shell string: a string invites injection and under-specifies which
tool's semantics apply. The manifest is the machine-readable form of "trust
the hash, not the host — and not this graph either."

## 9. View manifest — universe-bound

```json
{
  "view": "sev@v0",
  "profile_revision": "<sha256 of this document's bytes>",
  "projector_digest": "<sha256 of the projector implementation's bytes — the graph digest means nothing without knowing which semantics produced it>",
  "bundle_root": "<hex64 — the ecosystem.snapshot@v0 identity>",
  "receipts": [
    { "protocol": "warrant", "subroot": "<hex64>",
      "receipt_core_digest": "<hex64>", "grade": "settlement" }
  ],
  "unjudged_subroots": ["oaip", "bos"],
  "sources_in_receipts": 14,
  "sources_projected": 12,
  "sources_excluded": 2,
  "exclusions": [ { "path": "…", "entry_digest": "<hex64>",
                    "projection_reason": "ERR_ISSUES | NOT_LOADED | ID_UNSOUND",
                    "issues": [ {"code": "…", "severity": "ERR", "at": {"…"}} ] } ],
  "coverage": {
    "emitted": ["<categories THIS dataset actually contains>"],
    "not_emitted": ["<categories whose input evidence exists but is not projected>"],
    "note": "categories are relative to THIS dataset; sources_projected counts sources admitted to the graph, NOT completeness of the profile mapping over them"
  },
  "unverified_reasons": 0,
  "graph_digest": "<hex64>",
  "loss_manifest_digest": "<hex64>",
  "completeness": "relative-to-snapshot",
  "verdict_scope": "projection-of-verification-receipts"
}
```

`sources_projected + sources_excluded == sources_in_receipts` MUST hold;
`exclusions[]` carries the receipts' structured `issues[]` per excluded
source (malformed inputs included — they have paths and entry digests even
when no `wid` exists). Silent truncation is the recurring bug class of this
stack's own gates; the manifest makes it structurally loud.

Three rules the projector MVP had to learn the hard way, each from a
reproduced countervector:

- **Exclusion issues are carried verbatim and detached.** The receipt's
  ordered multiset is copied byte-for-byte (locators, severities and
  `occurrence` ordinals intact — collapsing to a set of codes merged two
  distinct occurrences into one row), and it is **deep-copied at emission**:
  an issued manifest must not change when its input receipt is later
  mutated. The projector's own reason for skipping a source lives in a
  separate `projection_reason` field and is never merged into the receipt's
  findings — one is a judgement by the verifier, the other a decision by the
  projector.
- **Every projected source is actually in the graph.** Non-record members
  (`blob`, `genesis`, `other`) emit a generic `prov:Entity` carrying
  `sev:sourceKind` and `sev:entryDigest`. Counting a member as projected
  while emitting nothing for it is the same silent-truncation class on the
  other branch of the union.
- **An outcome where nothing ran is not an Activity.** Every reason gets an
  `sev:ExecutionAssessment` — an **Entity** recording what the receipt says
  about executing it (`sigma:reExecution`, `sigma:failureCode`,
  `sev:receiptCoreDigest`, `sev:assesses` the reason). A `sigma:CheckRun`,
  and with it any PROV predicate whose domain is an Activity
  (`prov:used`, `prov:wasInformedBy`, `prov:generated`), is emitted **only**
  for `matched`/`mismatched`. Emitting a run for `not-applicable` or
  `unverified` made the graph assert an execution under entailment even
  without an explicit `rdf:type prov:Activity` — precisely the
  "re-ran ≠ was not executed" collapse warrant SPEC §7 forbids. Coverage
  lists `check-run` and the manifest carries `L-REEXEC` only when a run was
  actually emitted.
- **A reason is not an execution of it.** `urn:wrt:reason:<sha256(wid ‖ ptr ‖
  reason_digest)>` is a stable fact of the record; `urn:sigma:run:<sha256(
  receipt_core_digest ‖ wid ‖ ptr ‖ reason_digest ‖ semantics_digest)>` is
  one execution under one declared semantics, carrying
  `sigma:semanticsDigest`, `sev:receiptCoreDigest` and `prov:used` (the
  reason and the check blob). Keying the run on the reason alone fused two
  executions under *different* semantics into one `prov:Activity` — a named
  graph scopes a statement, it does not localize an IRI.
- **A role matching the bytes is not a role that is allowed.** Only a
  committed `kind:"check"` may become a `CheckRun`, and its runtime must be
  in the closed registry for that **body version** (warrant SPEC §3:
  `"0.1"` → `cmd@v1`; `"0.2"` → `cmd@v1 | ski@v1`; anything else invalidates
  the record). `execution_policy` narrows what a verifier will run; it never
  extends the registry.
- **Occurrence identity is distinct from content identity.** A source node
  is `urn:sev:source:<sha256(subroot_descriptor_digest ‖ path ‖
  entry_digest)>` carrying `sev:path`, `sev:sourceKind`, `sev:entryDigest`
  and `sev:inSubroot` — scoped to the descriptor, because `sourceKind` is a
  contract-derived assertion — and it
  `prov:specializationOf` the content entity (`urn:wrt:blob:<digest>`, or
  `urn:wrt:record:<wid>` for records). Keying source nodes on the digest
  alone merged two paths holding identical bytes into one node with two
  kinds — the graph silently losing a multiplicity the receipt records.
- **A source's role is derived, never reported.** `kind` and a record's
  `claimed_wid` follow from the store layout under the descriptor prefix
  (`records/<hex64>.json`, `blobs/*`, `genesis.json`, else `other`); a
  receipt that disagrees produces `SOURCE_KIND_MISMATCH` or
  `CLAIMED_WID_NOT_PATH` and no graph. Otherwise a receipt could relabel a
  committed Warrant record as `other` and make it disappear from the
  evidence view while the manifest still called it projected.

## 10. Conformance

Fixture-driven, refusal halves load-bearing:

- **N1 mutation:** flip one body field in a fixture, re-seal, re-verify,
  re-project → the N-Quads diff must equal a pre-computed expected diff.
- **N2 tamper (post-seal):** mutate or remove one file of an **already
  sealed** snapshot after its receipt exists → the projector's subroot
  recomputation mismatches and export aborts with the named error. (Rev 2
  asked the verifier to report a record deleted *before* sealing — an
  impossibility: no verifier can detect the absence of what the snapshot
  never committed to. Pre-seal omission is detectable only against an
  external commitment — a prior `expected.closed` snapshot, see
  `ECOSYSTEM-SNAPSHOT.md` — and is otherwise exactly the honesty boundary
  L-COMPLETE declares.)
- **N2b malformed:** a fixture store containing a duplicate-key JSON file and
  an invalid-UTF-8 file → both appear in `exclusions[]` with structured
  issue codes and no record IRI; a projection that either crashes or silently
  skips them fails.
- **N3 dual-lens:** the BOS fixture pair (two atoms, same two assessors,
  different lens) yields **two named graphs keyed by revision**, each with
  two attribution edges; one merged graph or node fails. (Rev 1's per-observer
  keying would have collapsed these into one graph; per-revision keying is
  what makes this test meaningful.)
- **N4 skolem:** encoder forbids blank-node terms by construction, and an
  independent parser over the output asserts zero blank-node *terms*. A grep
  for `_:` is not the check — the substring may occur inside literals.
- **N5 determinism:** run twice, byte-compare. **N5b:** a second independent
  implementation of the encoder produces byte-identical output (this test
  gates the §7 encoder appendix's completeness).
- **N6 cardinal-rule refusal:** a fixture accept over a `verdict:"fail"`
  claim (joined by note or by content) aborts export, named error, non-zero
  exit. A printed failure exiting 0 is non-conformant.
- **N7 freshness:** regenerate all expected outputs → `git diff --exit-code`.

## 11. Non-goals

- **No import.** RDF is never parsed back into warrant/OAIP/BOS records.
- **No live endpoint, no receipt service.** (The verification receipt is a
  file contract, not a service; OAIP §9.2's SCITT slot stays open.)
- **No semantic dedup.** Cross-observer entity resolution is consumer-side
  analysis, never a property of this dataset.
- **No compliance claim.** A mapping so an engineer and an auditor argue
  about the same table; nothing here makes anyone compliant.

---

## Appendix: rev 1 → rev 2 change log (review findings applied)

| Finding (Codex, 2026-08-09) | Disposition |
|---|---|
| P1 TOCTOU verify-vs-project | Sealed-snapshot pipeline (§0), R1 rewritten; receipt binds `input_root` |
| P1 verify-report lacks per-sig/per-reason data | All such fields now sourced from `warrant.verification-receipt@v0` (companion proposal); sev is blocked on it |
| P1 sorted N-Quads ≠ canonical | §7: RDFC-1.0 canonical form + normative encoder rules + N5b two-impl gate |
| P1 grep `_:` false positives | N4: encoder invariant + independent parse of term positions |
| P1 BOS `assessed_by` is plural | §5: graphs keyed by atom revision; assessors as attribution edges |
| P1 verifier is not an observer | §5: `sev:VerificationActivity` by `prov:SoftwareAgent`, mechanical, no appraisal semantics |
| P1 over-strong mappings (`ts`, `prior`, adjudication-for-propose, unbound actor, generated-by-adjudication) | §4 weak-default + promotion table; `wrt:Filing` vs `wrt:Adjudication`; `wrt:declaredTimestamp` never promotes |
| P2 positional signature identity | §2: `sha256(JCS(sig))` + multiplicity |
| P2 sigma run collapse | §2: WID + JSON pointer + reason digest per occurrence |
| P2 weak OAIP↔Warrant join | R3 asymmetric: assert on content join only, refuse on note-match; L-JOIN; upstream OAIP §3 amendment named. *(Superseded in rev 2.1 — note-match refusal was itself a defect.)* |
| P2 receipt vs input bundle conflation | §0: Source Bundle → Receipt → Dataset, three distinct objects |

## Appendix: rev 2 → rev 2.1 change log (second review applied)

| Finding (Codex, 2026-08-09, AMEND on rev 2) | Disposition |
|---|---|
| P1 one `input_root` mixes protocols — a Warrant receipt must not become the ecosystem's receipt | §0: `ecosystem.snapshot@v0` with per-protocol subroots (new companion sketch); each receipt binds to its own subroot only; L-UNJUDGED for receipt-less subroots |
| P1 byte-reproducibility impossible (non-normative messages; local ATP ceiling/oracle/runtimes legitimately vary) | Receipt rev 2: `core`/`producer` split; `execution_policy` inside `core`; reproducibility is core-only, relative to declared policy |
| P1 N2 demands the impossible (absence of what was never committed) | N2 rewritten as post-seal tamper; pre-seal omission needs an external `expected.closed` commitment; otherwise honestly L-COMPLETE |
| P1 malformed record has no `wid` | Receipt rev 2: source-oriented `sources[]` keyed by `(path, entry_digest)`, `wid:null`, plural structured `issues[]`; N2b added; view manifest counts sources, not records |
| P1 `settlement_active` is not a global boolean (SPEC §9: adoption is jurisdiction-scoped) | Receipt rev 2: `settlement[]` per jurisdiction root with per-policy threshold results; §4.1 projects skolem `wrt:SettlementStatus` nodes per (record, root) |
| P1 attribution without binding (`valid` proves the key signed, not that the key is the actor's) | §4.1: `prov:wasAttributedTo` requires `valid` AND `bound`; valid-but-unbound → `wrt:claimedSigner`; vocabulary aligned to SPEC's `bound\|unbound\|unverified` (invented `unevaluated` removed) |
| P1 optional OAIP as censorship primitive (note-match fail-claim DoS) | R3: note-only match → L-JOIN only, no edge, **no refusal**; both assertion and refusal require content join + OAIP validation receipt |
| P2 Filing identity from WarrantID (envelope grows) | §2: `urn:wrt:filing:<entry_digest>` — one sealed envelope occurrence, one filing |
| P2 verification graph keyed by `input_root` collapses grades/trust roots | §5: keyed by `receipt_core_digest` |
| P2 "facts no one owns" | §5: default graph is the projector's attributed, re-derivable claim |
| P2 NFC contradicts never-re-normalize (Warrant distinguishes NFC/NFD) | §7: no Unicode normalization of source-derived strings, ever; profile IRIs ASCII-only |
| P2 `recheck` as shell string | §8: argv array + `tool_digest` |

## Appendix: rev 2.1 → rev 2.2 change log (third review applied)

| Finding (Codex, 2026-08-09, AMEND round 3) | Disposition |
|---|---|
| P1 subroot allows role-confusion (bare file-tree hash commits no protocol/contract/prefix) | Snapshot rev 2 §1: domain-separated `ecosystem.subroot@v0` descriptor, `sha256("ecosystem-subroot-v0:" ‖ JCS(descriptor))`; R1 requires descriptor-digest binding and rejects file-tree-hash receipts |
| P1 `expected.closed` has no mechanical teeth (delete-then-reseal countervector) | Snapshot rev 2 §2–§3: `closed` demoted to self-completeness of THIS manifest; inter-snapshot omission moved to `ecosystem.universe-expectation@v0` with explicit authorization; no automatic monotonicity |
| P1 logical path/CAS contract undefined | Snapshot rev 2 §4: formal namespace (relative POSIX UTF-8, exact code points, no `.`/`..`/empty/backslash/NUL, regular files only, symlinks rejected, uniqueness by code-point sequence); CAS resolver re-hashes on every load; `unclaimed` added to the schema; executable model `model/snapshot_model.py` |
| P1 issue set cannot bind counts (duplicate co-signature countervector) | Receipt rev 3: located ordered multiset `{code,severity,at}` + `global_issues[]` + normative invariants errors/warnings == counts over all issues, ok == (errors==0) |
| P1 `wid` ambiguous on id mismatch | Receipt rev 3: `claimed_wid` (from path) + `computed_wid` (from body), both nullable; `id_sound == (claimed == computed != null)`; identity stays `(path, entry_digest)` |
| P1 `sources[]` covers records only | Receipt rev 3: discriminated union `record\|blob\|genesis\|other` over the whole universe; record-only fields gated on kind |
| P1 reason receipt insufficient for SEV output (observed result absent from snapshot on mismatch) | Receipt rev 3: structured `outcome` (observed verdict/result, atp_spent, closed failure codes); §4.4 projects from it |
| P2 execution policy names a tag, not semantics | Receipt rev 3: per-runtime `semantics` + `semantics_digest` (Book I anchor), `budget_unit`, `ceiling`; `trust_config_digest` defined as raw-bytes hash with the tradeoff documented |
| P2 SEV blocked until OAIP/BOS receipts | Status header: per-quadrant blocking made explicit; Warrant receipt licenses the Warrant quadrant only |

## Appendix: round 4 change log (model + contracts closure; profile text unchanged except this ledger)

| Finding (Codex, 2026-08-09, AMEND round 4) | Disposition |
|---|---|
| P1 harness accepts falsy as PASS (`lambda: False` passed; `expect_raise` ignored the named code; no real negative control) | Model v2: `check_true`/`check_equal`/`check_raises(exc, code)`; subprocess harness selftest (2 injected defects MUST print FAIL and exit 1). The fixed harness immediately caught two real defects in my own vectors — identical NFC/NFD literals and a FAIL-count check fooled by the word "FAIL" in vector names |
| P1 builder accepts empty/slashless prefixes | `validate_prefix()` (non-empty, exactly one trailing `/`, components pass path rules); membership via slash-terminated `startswith` IS component-boundary; `.x`-captures-`.xyz` vector |
| P1 partition invariant unchecked (same path in subroot AND unclaimed accepted) | Total `validate_snapshot(snapshot, cas)` — the single public verdict; partition, duplicate-slot, unclaimed-placement, digest-shape, schema, CAS vectors run it, not the builder |
| P1 stale embedded subroot digest passes outer self-hash | `validate_snapshot` re-derives every wrapper digest; countervector keeps `verify_bundle_root == True` while the validator reports `STALE_SUBROOT_DIGEST`; `verify_bundle_root` demoted to one step |
| P1 path ordering diverges between languages (astral-vs-BMP: UTF-16 vs codepoint order; JCS does not sort arrays) | Normative ordering: ascending UTF-16 code units (one comparator with JCS member names); astral countervector in the model; `UNIVERSE_NOT_UTF16_SORTED` finding |
| P1 receipt statuses unbound from issues (ok:true with id_sound:false expressible) | Normative status→issue implication set + `validate_receipt_core()`; Codex's contradictory core is a vector expecting exactly four findings |
| P1 reason outcome not a total sum type | Closed 4-row matrix (matched/mismatched/unverified/not-applicable) with per-row null/enum constraints, failure-code-vs-policy consistency, `not-applicable` only for normatively-unexecuted runtimes; four refusal vectors |
| P1 issue multiset still had locator collisions (no pointer for invalid UTF-8; duplicate members share a pointer) | Closed locator union `json-pointer\|byte-range\|path\|global` + optional `occurrence` ordinal; identity `(source, at, occurrence, code)`; `∪` corrected to `⊎` (multiset sum) |
| P1 warrant subroot accepts null `spec_digest` ("0.4" is a human name; SPEC bytes can move under it) | Ecosystem layer stays nullable; Warrant consumer MUST run the semantic role check (`protocol`/`contract.name`/`version`/`spec_digest` non-null) — `validate_warrant_descriptor_role` + refusal vector |
| P2 JCS model accepts non-I-JSON integers (10^100) | Safe-integer bounds ±(2^53−1) enforced, refusal vector |

Model status after round 4: 43 vectors, ALL PASS, exit-status honest,
harness self-tested in a subprocess. Item 9 of the closure order (second
independent root implementation) deliberately not started — it only makes
sense after this round's contracts survive review.

## Appendix: round 5 change log (compositional closure — model v3)

| Finding (Codex, 2026-08-10, AMEND round 5) | Disposition |
|---|---|
| P1 both "total" validators crash on hostile shapes (`subroots: null` → TypeError, `core = 7` → AttributeError, …) | Model v3: every nested access type-guarded; semantic passes short-circuit after structural findings; Codex's exact crasher list is now one vector; 300-shape + 100-byte-string deterministic fuzz over the public validators |
| P1 receipt unbound from snapshot universe (empty `sources[]` vs 100-record subroot → no findings — silent truncation survived) | Composed public verdict `validate_warrant_receipt(snapshot, receipt, cas)`: descriptor lookup by digest → role check → exact universe↔sources bijection (`SOURCE_MISSING_FOR_MEMBER` / `SOURCE_NOT_IN_UNIVERSE` / `SOURCE_DIGEST_MISMATCH`) → core invariants |
| P1 raw JSON boundary absent (duplicate members, trailing data, non-canonical bytes, NaN, floats, lone surrogates invisible after json.loads) | `parse_strict`/`parse_snapshot`/`parse_receipt` as the only conformance entrypoints; `jcs(parsed) == raw` canonicality; 8 byte-level refusal vectors |
| P1 arrays without canonical order (two valid snapshots with reversed subroots, both clean; JCS does not sort arrays) | Normative strictly-increasing keys for ALL arrays (subroots/unclaimed/sources/signatures/reasons/settlement/policies/runtimes/issues); reversed-subroots vector |
| P1 CAS skips `unclaimed` | `_cas_check` on every manifest member; missing-note vector |
| P1 implications not occurrence-bound (two mismatches, one issue → clean) | Exact join on reason `ptr` (`_join_issue`); invalid signatures counted against distinct-locator issue occurrences; two-mismatch vector |
| P1 sum type without domains (`potato` verdict, `atp_spent:-999` → clean) | Verdict enum, hex64 result for `ski@v1`, non-negative safe-int ATP ≤ declared ceiling, ptr resolution against CAS record bytes + `reason_digest` re-derivation, `not-applicable` only for registry-known non-executed runtimes |
| P1 grade absent from severity rule | `UNVERIFIED_WITHOUT_ERR` only at settlement grade on settlement-active records; base → WARN; `SETTLEMENT_IN_BASE` for settlement[] in a base receipt |
| P2 locator union not validated as a union | Exact key-sets per variant, JSON-pointer syntax, `0 <= start < end`, logical-path validity, registered global subjects, non-negative occurrence, unknown fields rejected — 6 refusal vectors |
| P2 descriptor schema not fully closed | Exact wrapper/contract key-sets, nonempty strings, hex64 digests, `protocol == contract.name`, null `spec_digest` refused in the composed verdict (not only in the helper) |

Model v3: **56 vectors, ALL PASS**, exit-status honest, harness self-tested,
fuzz deterministic (seeded). One vector was itself wrong on first run and
the harness caught it — the injected "unsorted" issue accidentally sorted
first (`"global"` < `"path"` in JCS bytes), which is exactly the class of
vacuous vector the round-4 repair exists to expose. Item "second independent
root implementation" remains the next step once this round's contracts
survive review.
