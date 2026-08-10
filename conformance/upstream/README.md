# Vendored upstream fixtures

Bytes copied verbatim from another protocol's repository, so SEV's positive
paths rest on evidence that protocol vouches for — instead of on synthetic
records whose own receipts call them unsigned.

**These are not a dependency.** No submodule, no git pin, no CI coupling
(the ecosystem map's rules 1–2). They are bytes with a recorded provenance,
and SEV does not verify them: their validity is tested upstream, by the
protocol that owns the semantics.

| File | Source | sha256 | Copied |
|---|---|---|---|
| `warrant-accept.warrant.json` | `s0fractal/warrant` → `examples/accept.warrant.json` | `bcd9765d73705a27f9273cf5e2fd2bd48ac5b1a1c02fc1e0958ede9dbdd4a88a` | 2026-08-10 |

## What is claimed about `warrant-accept.warrant.json`

- Its single signature is by `agent-b@vendor2`, the same actor as
  `body.actor.id`.
- **Upstream** verifies it: run in the warrant repository, that repo's own
  reference implementation returns `verify_sig → True` for it under
  `warrant-sig-v1`. SEV records that observation as provenance and performs
  no cryptography of its own — implementing Ed25519 here would make SEV a
  second Warrant verifier, which is precisely the ownership boundary this
  repository holds.
- Its committed reason is a `cmd@v1` check, which a Warrant verifier does
  not re-execute; a receipt over it therefore reports `not-applicable`.

If upstream re-signs its examples (as it did for the v0.4 domain-separated
message), this file becomes stale: the digest above is what a re-copy must
be checked against, and a mismatch is a fact to record, not to paper over.
