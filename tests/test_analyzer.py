"""Validation tests. Run with:  python tests/test_analyzer.py
(or `pytest` if you have it installed).

Locks in behavior for BOTH engines:
  * intraprocedural (v1): catch in-function bugs, no false positives
  * interprocedural (v0.2): catch cross-function bugs the v1 engine can't see
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from taintpy.analyzer import analyze_file  # noqa: E402
from taintpy.interprocedural import analyze_file_interprocedural  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def test_vulnerable_all_caught():
    findings = analyze_file(os.path.join(HERE, "vulnerable_example.py"))
    assert len(findings) == 7, f"expected 7, got {len(findings)}"


def test_safe_no_false_positives():
    findings = analyze_file(os.path.join(HERE, "safe_example.py"))
    assert len(findings) == 0, (
        f"expected 0, got {len(findings)}: "
        + ", ".join(f"{f.sink}@{f.lineno}" for f in findings))


def test_interproc_blind_without_flag():
    # The v1 engine sees none of the cross-function bugs.
    findings = analyze_file(os.path.join(HERE, "interproc_example.py"))
    assert len(findings) == 0, f"expected 0 (v1 is blind), got {len(findings)}"


def test_interproc_catches_cross_function():
    findings = analyze_file_interprocedural(
        os.path.join(HERE, "interproc_example.py"))
    assert len(findings) == 2, f"expected 2 cross-function bugs, got {len(findings)}"


if __name__ == "__main__":
    test_vulnerable_all_caught()
    test_safe_no_false_positives()
    test_interproc_blind_without_flag()
    test_interproc_catches_cross_function()
    print("all tests passed")
