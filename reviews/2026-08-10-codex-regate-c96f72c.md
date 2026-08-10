# Re-gate of `c96f72c3…` — Codex, 2026-08-10, verdict AMEND (hold merge)

Target: PR #1 head `c96f72c3994640463d4a176e31dc5f4f1d10127f`. Baseline
64 + 110 + 9 green locally. One P1 — the deepest of the series. No files,
commits, pushes or GitHub write actions by the reviewer.

## P1 — the receipt authorised its own severity downgrade

The WARN-or-ERR branch of the malformed-signature matrix turned on
`s.get("valid") is True` — a field of the **receipt itself**, never
cryptographically checked here. The reviewer verified the shipped fixture
against warrant SPEC v0.4 (`"warrant-sig-v1:" || WarrantID_raw`, strict
Ed25519): the pair `key = cc…cc`, `sig = dd…dd` does **not** verify, yet the
receipt claimed `valid: true` — and on that claim its malformed extra
signature was accepted as a WARN, leaving the record projected with zero
findings.

So the positive control that supposedly demonstrated the SPEC §5 survivable
path demonstrated only: *if the receipt says a signature is valid, the model
believes it*. A claim was deciding how strictly its siblings were judged —
self-authorisation, and a direct contradiction of the proposal's own
"authority = independent re-derivability of core".

**Disposition — the reviewer's option 2, taken deliberately.** Verifying
Ed25519 here would make SEV a second Warrant verifier, which is exactly the
ownership boundary this repository exists to hold: each protocol judges its
own bytes, SEV composes their judgements. So:

- malformed signature occurrences are **always ERR**; the survivable §5 path
  is not available to SEV;
- the matrix is explicitly **not** called Warrant-consistent — it is
  strictly stronger and fails closed;
- the §5 path may be reinstated only on an independently verifiable basis
  (a signed receipt, or Warrant's own verifier output bound to it);
- no producer-asserted field may relax a rule applied to the same receipt —
  stated as a rule in both the proposal (rev 10) and the profile.

**The fixtures were dishonest too, and were corrected rather than
exempted.** Every fixture signature now reports `valid: false` with the
matching `INVALID_SIGNATURE` occurrences and counts to match: they are
synthetic placeholders, and claiming they verified asserted what this
repository cannot back. The only surviving `valid: true` in the tree is
inside the *fabricated-signature attack vector*, where it is the attack.

Vectors: a self-asserted valid signature no longer buys a WARN (refusal);
the honest ERR path is accepted and excludes the record.

## Mutation result

Restoring the `actor_sig_ok` downgrade fails the suite on exactly the
self-authorisation vector.

## State after closure

64 model + 111 projector vectors + 9 fixtures, all green, exit-status
honest. Freeze criterion still unmet.
