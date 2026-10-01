"""Validation tests. Run with:  python tests/test_analyzer.py
(or `pytest` if you have it installed).

Locks in behavior for BOTH engines:
  * intraprocedural: catch in-function bugs, no false positives
  * interprocedural: catch cross-function / cross-file bugs too
"""

import contextlib
import glob
import io
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from taintpy import rules  # noqa: E402
from taintpy.analyzer import analyze_file, analyze_source  # noqa: E402
from taintpy.cli import main  # noqa: E402
from taintpy.interprocedural import (  # noqa: E402
    analyze_file_interprocedural,
    analyze_files_interprocedural,
    analyze_module_interprocedural,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_APP = os.path.join(HERE, "fake_app")


def _lines(findings):
    return sorted(f.lineno for f in findings)


def _intra(code):
    return analyze_source(code)


def _cli(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


# --- original fixtures ------------------------------------------------------

def test_vulnerable_all_caught():
    findings = analyze_file(os.path.join(HERE, "vulnerable_example.py"))
    assert len(findings) == 7, f"expected 7, got {len(findings)}"


def test_safe_no_false_positives():
    findings = analyze_file(os.path.join(HERE, "safe_example.py"))
    assert len(findings) == 0, (
        f"expected 0, got {len(findings)}: "
        + ", ".join(f"{f.sink}@{f.lineno}" for f in findings))


def test_interproc_blind_without_flag():
    findings = analyze_file(os.path.join(HERE, "interproc_example.py"))
    assert len(findings) == 0, f"expected 0 (v1 is blind), got {len(findings)}"


def test_interproc_catches_cross_function():
    findings = analyze_file_interprocedural(
        os.path.join(HERE, "interproc_example.py"))
    assert len(findings) == 2, f"expected 2 cross-function bugs, got {len(findings)}"


# --- fake app: marker-driven benchmark ---------------------------------------

MARKER = re.compile(r"#\s*(BUG|INTERPROC|SAFE)\b")


def _planted(path):
    """Return {marker: set(line numbers)} from the # BUG / # SAFE comments."""
    out = {"BUG": set(), "INTERPROC": set(), "SAFE": set()}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            m = MARKER.search(line)
            if m and line.startswith(" "):        # skip the docstring legend
                out[m.group(1)].add(n)
    return out


def _check_fake_app(scan, include_interproc):
    for path in sorted(glob.glob(os.path.join(FAKE_APP, "*.py"))):
        planted = _planted(path)
        expected = set(planted["BUG"])
        if include_interproc:
            expected |= planted["INTERPROC"]
        got = set(_lines(scan(path)))
        name = os.path.basename(path)
        missed = expected - got
        extra = got - expected
        assert not missed, f"{name}: missed planted bugs at lines {sorted(missed)}"
        assert not extra, f"{name}: unexpected findings at lines {sorted(extra)}"
        assert not (got & planted["SAFE"]), f"{name}: flagged SAFE lines"


def test_fake_app_intraprocedural():
    _check_fake_app(analyze_file, include_interproc=False)


def test_fake_app_interprocedural():
    _check_fake_app(analyze_file_interprocedural, include_interproc=True)


# --- engine behaviors ----------------------------------------------------------

def test_format_on_literal_propagates():
    assert len(_intra('import os\nx=input()\nos.system("ls {}".format(x))\n')) == 1


def test_join_on_literal_propagates():
    assert len(_intra('import os\nt=input()\nos.system(",".join([t]))\n')) == 1


def test_chained_method_calls_propagate():
    assert len(_intra('import os\nx=input()\nos.system(x.strip().lower())\n')) == 1


def test_keyword_args_reach_sinks():
    f = _intra('import subprocess\nx=input()\nsubprocess.run(args=x, shell=True)\n')
    assert len(f) == 1 and f[0].severity == "HIGH"


def test_subprocess_list_keyword_is_safe():
    assert _intra('import subprocess\nx=input()\nsubprocess.run(args=["ls", x])\n') == []


def test_yaml_safe_loader_not_flagged():
    assert _intra('import yaml\nx=input()\nyaml.load(x, Loader=yaml.SafeLoader)\n') == []
    assert len(_intra('import yaml\nx=input()\nyaml.load(x, Loader=yaml.FullLoader)\n')) == 1
    assert len(_intra('import yaml\nx=input()\nyaml.load(x)\n')) == 1


def test_branches_merge_as_union():
    code = ('import os\nx="a"\nif cond():\n    x=input()\nelse:\n    x="b"\n'
            'os.system(x)\n')
    assert len(_intra(code)) == 1, "taint from one branch must survive the merge"
    code = ('import os\nx=input()\nif cond():\n    x="a"\nelse:\n    x="b"\n'
            'os.system(x)\n')
    assert _intra(code) == [], "taint cleared on every path is gone"


def test_try_except_merge():
    code = ('import os\nx="a"\ntry:\n    x=input()\nexcept Exception:\n    x="b"\n'
            'os.system(x)\n')
    assert len(_intra(code)) == 1


def test_container_store_taints_base():
    assert len(_intra('import os\nd={}\nd["k"]=input()\nos.system(d["k"])\n')) == 1


def test_attribute_store_is_precise():
    code = ('import os\nclass C:\n    def m(self):\n        self.a=input()\n'
            '        open(self.a)\n        open(self.b)\n')
    assert _lines(_intra(code)) == [5]


def test_tuple_unpack():
    assert len(_intra('import os\na, b = input().split(":")\nos.system(b)\n')) == 1


def test_sanitizer_wins_over_propagator():
    assert _intra('import os, shlex\nx=input()\nos.system(shlex.join(["ls", x]))\n') == []


def test_receiver_propagators():
    assert len(_intra('import os\nd=request.get_json()\nos.system(d.get("k"))\n')) == 1
    assert _intra('import os\ncache={}\nk=input()\nos.system(cache.get(k))\n') == []


def test_suppression_comment():
    assert _intra('import os\nx=input()\nos.system(x)  # taintpy: ignore\n') == []
    assert _intra('import os\nx=input()\nos.system(x)  # noqa: taintpy\n') == []


def test_ternary_and_boolop():
    assert len(_intra('import os\nx=input() or "d"\nos.system(x)\n')) == 1
    assert len(_intra('import os\nx=input() if c else "d"\nos.system(x)\n')) == 1


def test_comprehension():
    code = 'import os\nxs=[s.strip() for s in input().split()]\nos.system(xs[0])\n'
    assert len(_intra(code)) == 1


# --- interprocedural behaviors ------------------------------------------------

def test_summary_keeps_highest_severity():
    code = 'import os\ndef h(p):\n    open(p)\n    os.system(p)\nh(input())\n'
    f = analyze_module_interprocedural(code)
    assert len(f) == 1 and f[0].severity == "HIGH" and "os.system" in f[0].sink


def test_summary_sources_off_while_seeding():
    # A function that returns input() must not be summarized as "param -> return".
    code = 'import os\ndef h(p):\n    return input()\nos.system(h("const"))\n'
    f = analyze_module_interprocedural(code)
    assert len(f) == 1 and f[0].tainted_arg == "h('const')"


def test_keyword_args_map_to_params():
    code = ('import os\ndef h(a, cmd):\n    os.system(cmd)\n'
            'h(cmd=input(), a=1)\nh(1, "safe")\n')
    assert _lines(analyze_module_interprocedural(code)) == [4]


def test_methods_resolve_via_self():
    code = (
        'import os\nclass C:\n    def sink(self, p):\n        os.system(p)\n'
        '    def entry(self):\n        self.sink(input())\n'
    )
    f = analyze_module_interprocedural(code)
    assert _lines(f) == [6] and f[0].sink == "C.sink -> os.system"


def test_method_called_on_instance():
    code = ('import os\ndef h(p):\n    return p\n'
            'class A:\n    def h(self, p):\n        os.system(p)\n'
            'A().h(input())\n')
    assert _lines(analyze_module_interprocedural(code)) == [7]


def test_cross_file():
    paths = [os.path.join(HERE, "multifile", n) for n in ("helpers.py", "main.py")]
    f = analyze_files_interprocedural(paths)
    by_file = {}
    for x in f:
        by_file.setdefault(os.path.basename(x.filename), []).append(x.lineno)
    assert sorted(by_file.get("main.py", [])) == [8, 12, 17], by_file
    assert "helpers.py" not in by_file


# --- CLI ------------------------------------------------------------------------

def test_cli_json_and_exit_code():
    rc, out = _cli(["--format", "json", "--interproc", os.path.join(HERE, "multifile")])
    assert rc == 1
    data = json.loads(out)
    assert data["count"] == 3 and len(data["findings"]) == 3
    assert {"file", "line", "severity", "category", "sink"} <= set(data["findings"][0])

    rc, out = _cli([os.path.join(HERE, "safe_example.py")])
    assert rc == 0 and "0 finding(s)" in out


def test_cli_min_severity():
    _, out = _cli(["--format", "json", "--min-severity", "HIGH", FAKE_APP])
    data = json.loads(out)
    assert data["count"] > 0
    assert all(f["severity"] == "HIGH" for f in data["findings"])


def test_rules_file():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "rules.json")
        with open(p, "w") as f:
            json.dump({"sources": ["bottle.request.query.get"],
                       "sinks": {"db.raw": ["sql-injection", "high"]}}, f)
        rules.load_rules(p)
    try:
        f = _intra('q=bottle.request.query.get("q")\ndb.raw(q)\n')
        assert len(f) == 1
        assert f[0].category == "sql-injection" and f[0].severity == "HIGH"
    finally:
        rules.SOURCE_CALL_SUFFIXES.discard("bottle.request.query.get")
        rules.SINKS.pop("db.raw", None)


if __name__ == "__main__":
    tests = [(n, fn) for n, fn in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {name}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)
