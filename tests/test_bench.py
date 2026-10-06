"""Benchmark harness scoring. Runs without Bandit or Semgrep installed."""

import json
import os
import sys

from taint_helpers import HERE

sys.path.insert(0, os.path.join(os.path.dirname(HERE), "bench"))

import run_bench  # noqa: E402
from run_bench import Detection, parse_sarif, score  # noqa: E402


def _project(cases):
    for c in cases:
        c.setdefault("vulnerable", True)
        c["_range"] = tuple(c["lines"])
    return {"p": {"root": "/r", "cases": cases}}


def test_scoring_outcomes():
    projects = _project([
        {"id": "a", "file": "x.py", "lines": [10, 20], "cwe": 78},
        {"id": "b", "file": "x.py", "lines": [30, 40], "cwe": 89},
        {"id": "c", "file": "x.py", "lines": [50, 60], "vulnerable": False},
        {"id": "d", "file": "x.py", "lines": [70, 80], "vulnerable": False},
    ])
    dets = {"p": [Detection("x.py", 15, [78], "r"),      # hits a
                  Detection("x.py", 55, [78], "r"),      # hits safe case c
                  Detection("x.py", 99, [78], "r"),      # unlabeled
                  Detection("y.py", 15, [78], "r")]}     # other file, ignored
    totals, cases = score(projects, dets, match_category=False)
    assert {k: totals[k] for k in ("TP", "FN", "FP", "TN", "unlabeled")} == \
        {"TP": 1, "FN": 1, "FP": 1, "TN": 1, "unlabeled": 1}
    assert totals["recall"] == 0.5 and totals["false_positive_rate"] == 0.5
    assert [c["outcome"] for c in cases] == ["TP", "FN", "FP", "TN"]


def test_category_matching():
    projects = _project([{"id": "a", "file": "x.py", "lines": [1, 5], "cwe": 89}])
    dets = {"p": [Detection("x.py", 2, [78], "r")]}
    assert score(projects, dets, match_category=False)[0]["TP"] == 1
    assert score(projects, dets, match_category=True)[0]["TP"] == 0


def test_parse_sarif_reads_location_and_cwe(tmp_path):
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "py/cmd", "properties": {"tags": ["security", "external/cwe/cwe-078"]}}]}},
        "results": [{"ruleId": "py/cmd", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "pkg/a.py"}, "region": {"startLine": 7}}}]}]}]}
    (d,) = parse_sarif(sarif, str(tmp_path))
    assert (d.file, d.line, d.cwe) == ("pkg/a.py", 7, [78])


def test_function_labels_resolve_to_line_ranges(tmp_path):
    (tmp_path / "m.py").write_text("class C:\n    def f(self):\n        pass\n\n"
                                   "def g():\n    return 1\n", encoding="utf-8")
    assert run_bench.resolve_function_lines(str(tmp_path), {"file": "m.py", "function": "C.f"}) == (2, 3)
    assert run_bench.resolve_function_lines(str(tmp_path), {"file": "m.py", "function": "g"}) == (5, 6)


def test_smoke_dataset_end_to_end(tmp_path):
    gt = os.path.join(os.path.dirname(HERE), "bench", "datasets", "smoke.json")
    run_bench.main([gt, "--tools", "taintpy,taintpy-intra", "--out", str(tmp_path)])
    report = json.loads((tmp_path / "smoke.json").read_text(encoding="utf-8"))
    full, intra = report["tools"]["taintpy"], report["tools"]["taintpy-intra"]
    assert full["coverage"]["fake_app"]["files_scanned"] == 2
    assert full["totals"]["FN"] == 0 and full["totals"]["FP"] == 0
    assert intra["totals"]["FN"] == 5, "the five INTERPROC cases need the interprocedural engine"
