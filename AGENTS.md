# Working rules for agents (and everyone else) in this repository

Inherited from the sigma-glyph / warrant house culture; this repo exists to
practice the same discipline on its own artifacts.

1. **Never commit to `master`.** Work on a branch; `master` advances through
   review. Pushing, releasing, or renaming are outward-facing acts that need
   explicit human authorization.
2. **Status honesty.** This repository is research, not adopted. Nothing in
   a commit message, README, or review response may claim adoption,
   independent approval, or cross-implementation parity that does not exist.
   "The model passes its N vectors" is the strongest claim available, and it
   means only that N stated claims are checked honestly.
3. **Exit-status honesty.** A printed failure that exits 0 is
   non-conformant. The model's harness self-tests in a subprocess; keep it
   that way when touching it.
4. **Vectors before prose promotion.** A rule stated in `spec/` or
   `proposals/` that the model cannot yet refuse is an open item, not a
   guarantee. Where prose and model disagree, file the disagreement as a
   vector, then fix whichever side was wrong.
5. **Ownership boundary.** `proposals/` contains upstream candidates for
   other protocols. They are not this repo's contracts and never become
   normative here. On upstream adoption: pin their artifact, mark the local
   draft superseded, keep it as provenance.
6. **No submodules, no pins into member protocol repos.** References are by
   URL and by digest inside documents. The ecosystem map
   (`protocol-ecosystem`) stays a map; this repo never appears in member
   repos as a dependency.
7. **Review gates are adversarial.** A review round is counter-vector
   hunting by a fresh reviewer against an exact SHA, not a green suite. File
   rounds and responses under `reviews/`, and record verdicts in the profile
   ledger.
