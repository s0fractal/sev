# Re-gate of `d8f33aa7…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `d8f33aa767e102b8db9e462840243c11af0837d1` (local branch,
origin and PR agree; GitHub CI green; `git diff --check` clean). Reviewer
confirmed the baseline locally: 64 model, 67 projector, 9 fixtures. One new
P1 and one P2. No files, commits, pushes or merges by the reviewer.

## P1 — the freeze failed open, exactly where isolation matters most

`_freeze()` returned the caller's object when `deepcopy` raised. A mapping
whose `__deepcopy__` throws therefore stayed **shared** between the caller
and the validated view, and mutating it at the verdict boundary produced a
clean-findings graph containing a swapped `semantics_digest` and a
non-NodeHash `observed_result` — data the validator never judged. The
guarantee added one round earlier held for well-behaved inputs and opened
for hostile ones.

**Disposition.** `_freeze` never returns the original. It rebuilds from
**exact JSON built-ins only** (`type(x) is dict/list/str/int/bool` or
`None` — `isinstance` would admit subclasses, the usual carrier of
read-dependent behaviour), constructs fresh plain containers, and raises
`_NotFreezable` on anything else. The composed verdict catches it and
returns a single `INPUT_NOT_FREEZABLE` ERR **without publishing a view**, so
no consumer can mistake a partial freeze for a validated one.

Two permanent vectors: an `Uncopyable` mapping mutated at the verdict
boundary must yield a bounded refusal and no output; a plain `dict`
subclass is refused as well, while the honest plain-dict path still
projects. Mutation-tested — restoring the fail-open freeze fails the suite
on exactly these vectors.

## P2 — implementation had run ahead of the normative profile

`L-NOSIG`, `L-NOSETTLE`, `L-NOUNCLAIMED`, `L-NOMAP` and the `coverage` field
existed in the projector but in no normative table, while §6 still read as
if per-signature and settlement evidence were carried. Contract drift, not
a security break.

**Disposition.** §6 now separates the *target* profile from *current MVP
coverage* and states that a reader MUST take the emitted `coverage` block,
not the prose, as the statement of what a dataset contains. §8 registers
the `L-NO*` absence codes as a distinct family — "the codes above qualify
facts that ARE in the graph; these declare facts that are NOT" — with the
rule that each is emitted only when the corresponding data exists. §9 makes
`coverage` part of the manifest schema.

## Confirmed as holding

CAS untouched after the verdict; `available_blob_digests()` shared by
verdict and projection; `other` and ERR-bearing blobs no longer pass as
available checks; caller mutation with ordinary JSON objects isolated; the
author's self-review honestly marked as not-a-gate; the new loss/coverage
declarations materially more truthful than the previous silence.

## State after closure

64 model + 71 projector vectors + 9 fixtures, all green, exit-status honest.
Freeze criterion still unmet — the isolation boundary now fails closed, but
that is a fix, not a clean round.
