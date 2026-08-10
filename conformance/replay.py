#!/usr/bin/env python3
"""Replay language-neutral conformance fixtures against the model.

The fixtures are DATA (base64 bytes + expected finding codes), not Python —
a second implementation consumes the same JSON without reading the model
(round-6 R3: translation is not independence). Exit status is the verdict.
"""

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "model"))
import snapshot_model as sm  # noqa: E402


def main():
    with open(os.path.join(HERE, "parse-strict.vectors.json")) as fh:
        fixtures = json.load(fh)
    failed = 0
    for case in fixtures["cases"]:
        raw = base64.b64decode(case["raw_b64"])
        _obj, findings = sm.parse_strict(raw)
        got = [x["code"] for x in findings]
        ok = got == case["expected_codes"]
        print("%s  %s%s" % ("PASS" if ok else "FAIL", case["name"],
                            "" if ok else "  (got %s, want %s)"
                            % (got, case["expected_codes"])))
        failed += 0 if ok else 1
    if failed:
        print("FAILED: %d fixture(s)" % failed)
        return 1
    print("ALL PASS (%d parse-strict fixtures)" % len(fixtures["cases"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
