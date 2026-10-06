"""Marker-driven fixtures: every # BUG / # INTERPROC line must be flagged,
nothing else may be. These labels were written by the author alongside the
engine, so this is a regression check, not an accuracy measurement."""

import glob
import os
import re

from taint_helpers import HERE, lines

from taintpy.analyzer import analyze_file
from taintpy.interprocedural import analyze_file_interprocedural

FAKE_APP = os.path.join(HERE, "fake_app")
MARKER = re.compile(r"#\s*(BUG|INTERPROC|SAFE)\b")


def _planted(path):
    out = {"BUG": set(), "INTERPROC": set(), "SAFE": set()}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            m = MARKER.search(line)
            if m and line.startswith(" "):        # skip the docstring legend
                out[m.group(1)].add(n)
    return out


def _check(scan, include_interproc):
    for path in sorted(glob.glob(os.path.join(FAKE_APP, "*.py"))):
        planted = _planted(path)
        expected = set(planted["BUG"]) | (planted["INTERPROC"] if include_interproc else set())
        got = set(lines(scan(path)))
        name = os.path.basename(path)
        assert not expected - got, f"{name}: missed {sorted(expected - got)}"
        assert not got - expected, f"{name}: unexpected {sorted(got - expected)}"


def test_vulnerable_all_caught():
    assert len(analyze_file(os.path.join(HERE, "vulnerable_example.py"))) == 7


def test_safe_no_false_positives():
    assert analyze_file(os.path.join(HERE, "safe_example.py")) == []


def test_fake_app_intraprocedural():
    _check(analyze_file, include_interproc=False)


def test_fake_app_interprocedural():
    _check(analyze_file_interprocedural, include_interproc=True)
