# Round 9 — Codex, 2026-08-10 — **partial disagreement, with evidence**

Target: `21ee4545dc6fafcb41b10ac15f582f3f8db3b62f`. Merge withheld on a
receipt/MVP P1. Snapshot freeze at `7935400` untouched and not disputed.

## The finding, split in two

The round makes one structural observation and one prescription. **The
observation is right and is fixed. The prescription is wrong on the merits,
and adopting it would break SEV against every real Warrant store.**

### Accepted — strict-parser findings were discarded structurally

`_resolve_record` tested only `obj`, while `parse_strict` returns
`(object, findings)` and can produce both. Any present-or-future code that
decodes yet reports would have been laundered. Readability now requires an
explicit fatal-finding list, not a truthy object.

### Disputed — envelope canonicality is not a Warrant requirement

The prescription was: non-canonical bytes → `RECORD_UNREADABLE_UNREPORTED`.
Three independent facts say otherwise.

1. **The format says the envelope is not hashed.** warrant SPEC §4:
   `WarrantID = SHA-256( canonical_json(body) )`; SPEC §5.1's migration note
   states it outright — *"the WarrantID is SHA-256 of the canonical body and
   the envelope is not hashed"*. Canonicality binds where identity is
   derived: the body, and each reason when its digest is checked. SEV
   re-canonicalizes both.
2. **Warrant's own store writes pretty-printed files, deliberately.**
   `impl/warrant.py:660` — the store's single writer emits
   `json.dumps(env, indent=2, sort_keys=True)`. Measured on the warrant
   repository's live store: **16 of 16 record files are non-canonical
   bytes.**
3. **The rule rejects the vendored upstream example this repo verifies
   against.** `conformance/upstream/warrant-accept.warrant.json` — copied
   verbatim from `warrant/examples/`, whose signature upstream vouches
   for — carries `NOT_CANONICAL`. Executed under the prescribed rule:

   ```
   project(*fixture()) -> ['RECORD_UNREADABLE_UNREPORTED',
                           'REASON_PTR_UNRESOLVABLE'], projected: False
   ```

   The flagship positive path dies, and with it the ability to read any
   genuine Warrant store.

**Closure taken:** every strict finding is fatal for record readability
**except** `NOT_CANONICAL`, with the reasoning and the three citations
recorded in the code. If this reading of the SPEC is wrong, the fix is one
line — but it should be argued against those citations rather than assumed.

## Consequence for the mutation ledger

With `NOT_CANONICAL` exempt, `parse_strict` has no remaining code that
returns an object beside a finding, so the fatal-list check **cannot be
isolated by a vector today** — reverting it to `obj is not None` leaves the
suite green. It is kept as a list and **labelled unisolatable in code**,
because the laundering was a property of the check's shape, not of the one
code that happened to take that path.

Vectors added: the upstream record is non-canonical *and* readable; and for
bytes Warrant's contract really does reject — duplicate members, trailing
data, a float, a BOM — unacknowledged is refused
(`RECORD_UNREADABLE_UNREPORTED`) while acknowledged is valid negative
evidence with the record excluded.

Mutation: making `NOT_CANONICAL` fatal fails the suite, which is the guard
that keeps this decision from being silently reverted.

## Status

Receipt core: the structural half is closed; the prescriptive half is
returned for arbitration. Merge remains the reviewer's call, and this file
is the counter-argument to weigh before it.
