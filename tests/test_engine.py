"""Intraprocedural engine: propagation, sinks, sources, paths."""

import sys

import pytest
from taint_helpers import intra, lines

from taintpy.analyzer import analyze_source


# --- propagation ------------------------------------------------------------

def test_format_on_literal_propagates():
    assert len(intra('import os\nx=input()\nos.system("ls {}".format(x))\n')) == 1


def test_join_on_literal_propagates():
    assert len(intra('import os\nt=input()\nos.system(",".join([t]))\n')) == 1


def test_chained_method_calls_propagate():
    assert len(intra('import os\nx=input()\nos.system(x.strip().lower())\n')) == 1


def test_percent_format_and_fstring():
    assert len(intra('import os\nx=input()\nos.system("ls %s" % x)\n')) == 1
    assert len(intra('import os\nx=input()\nos.system(f"ls {x}")\n')) == 1


def test_newer_str_methods_propagate():
    assert len(intra('import os\nx=input()\nos.system(x.removeprefix("a"))\n')) == 1


def test_tuple_unpack():
    assert len(intra('import os\na, b = input().split(":")\nos.system(b)\n')) == 1


def test_ternary_and_boolop():
    assert len(intra('import os\nx=input() or "d"\nos.system(x)\n')) == 1
    assert len(intra('import os\nx=input() if c else "d"\nos.system(x)\n')) == 1


def test_comprehension():
    code = 'import os\nxs=[s.strip() for s in input().split()]\nos.system(xs[0])\n'
    assert len(intra(code)) == 1


def test_sink_inside_comprehension_sees_loop_variable():
    code = 'import os\nnames=input().split()\n[os.system(n) for n in names]\n'
    assert lines(intra(code)) == [3]


def test_walrus():
    assert len(intra('import os\nif (x := input()):\n    os.system(x)\n')) == 1


def test_container_store_taints_base():
    assert len(intra('import os\nd={}\nd["k"]=input()\nos.system(d["k"])\n')) == 1


def test_attribute_store_is_precise():
    code = ('class C:\n    def m(self):\n        self.a=input()\n'
            '        open(self.a)\n        open(self.b)\n')
    assert lines(intra(code)) == [4]


def test_receiver_propagators():
    assert len(intra('import os\nd=request.get_json()\nos.system(d.get("k"))\n')) == 1
    assert intra('import os\ncache={}\nk=input()\nos.system(cache.get(k))\n') == []


def test_sanitizer_wins_over_propagator():
    assert intra('import os, shlex\nx=input()\nos.system(shlex.join(["ls", x]))\n') == []


def test_unknown_call_sanitizes_by_default():
    assert intra('import os\nx=input()\nos.system(mystery(x))\n') == []


def test_unknown_call_propagate_policy():
    f = analyze_source('import os\nx=input()\nos.system(mystery(x))\n',
                       unknown_calls="propagate")
    assert len(f) == 1 and f[0].confidence == "medium"


# --- control flow -------------------------------------------------------------

def test_branches_merge_as_union():
    code = 'import os\nx="a"\nif cond():\n    x=input()\nelse:\n    x="b"\nos.system(x)\n'
    assert len(intra(code)) == 1, "taint from one branch must survive the merge"
    code = 'import os\nx=input()\nif cond():\n    x="a"\nelse:\n    x="b"\nos.system(x)\n'
    assert intra(code) == [], "taint cleared on every path is gone"


def test_try_except_merge():
    code = 'import os\nx="a"\ntry:\n    x=input()\nexcept Exception:\n    x="b"\nos.system(x)\n'
    assert len(intra(code)) == 1


def test_loop_carried_taint():
    # On the first pass ``cmd`` is clean when it reaches the sink. Taint only
    # arrives on the second iteration, so this needs the loop fixpoint.
    code = ('import os\ncmd="ls"\nnxt="ls"\nfor _ in range(3):\n'
            '    os.system(cmd)\n    cmd = nxt\n    nxt = input()\n')
    assert lines(intra(code)) == [5]


@pytest.mark.skipif(sys.version_info < (3, 10), reason="match needs Python 3.10")
def test_match_statement():
    code = ('import os\nmatch input().split():\n    case [verb, arg]:\n'
            '        os.system(arg)\n')
    assert lines(intra(code)) == [4]


# --- sinks --------------------------------------------------------------------

def test_keyword_args_reach_sinks():
    f = intra('import subprocess\nx=input()\nsubprocess.run(args=x, shell=True)\n')
    assert len(f) == 1 and f[0].severity == "HIGH"


def test_subprocess_list_is_safe_unless_program_or_shell_is_tainted():
    assert intra('import subprocess\nx=input()\nsubprocess.run(["ls", x])\n') == []
    assert intra('import subprocess\nx=input()\nsubprocess.run(args=["ls", x])\n') == []
    f = intra('import subprocess\nx=input()\nsubprocess.run([x, "-l"])\n')
    assert len(f) == 1
    f = intra('import subprocess\nx=input()\nsubprocess.run(["sh", "-c", x])\n')
    assert len(f) == 1 and f[0].severity == "HIGH"


def test_yaml_loaders():
    assert intra('import yaml\nx=input()\nyaml.load(x, Loader=yaml.SafeLoader)\n') == []
    assert len(intra('import yaml\nx=input()\nyaml.load(x, Loader=yaml.FullLoader)\n')) == 1
    assert len(intra('import yaml\nx=input()\nyaml.load(x)\n')) == 1


def test_sql_concat_flagged_parameterized_not():
    code = ('import sqlite3\nname=input()\ncur=sqlite3.connect("db").cursor()\n'
            'cur.execute("SELECT * FROM t WHERE n=\'" + name + "\'")\n'
            'cur.execute("SELECT * FROM t WHERE n=?", (name,))\n')
    f = intra(code)
    assert lines(f) == [4] and f[0].category == "sql-injection"


def test_ssrf():
    f = intra('import requests\nu=input()\nrequests.get(u, timeout=5)\n')
    assert len(f) == 1 and f[0].category == "ssrf"
    assert intra('import requests\np=input()\nrequests.get("https://x", params={"q": p})\n') == []


def test_template_injection():
    f = intra('from flask import render_template_string, request\n'
              'render_template_string(request.args["t"])\n')
    assert len(f) == 1 and f[0].category == "template-injection"


def test_exact_sinks_do_not_match_methods():
    assert intra('import webbrowser\nwebbrowser.open(input())\n') == []
    assert len(intra('open(input())\n')) == 1


def test_receiver_sink_on_tainted_path():
    f = intra('from pathlib import Path\nPath(input()).read_text()\n')
    assert len(f) == 1 and f[0].category == "path-traversal"


def test_conditional_deserialization_sinks():
    assert intra('import numpy as np\nnp.load(input())\n') == []
    assert len(intra('import numpy as np\nnp.load(input(), allow_pickle=True)\n')) == 1
    assert len(intra('import torch\ntorch.load(input())\n')) == 1
    assert intra('import torch\ntorch.load(input(), weights_only=True)\n') == []


def test_import_aliases_are_canonicalized():
    assert len(intra('import os as o\no.system(input())\n')) == 1
    assert len(intra('from os import system\nsystem(input())\n')) == 1
    assert len(intra('import subprocess as sp\nsp.call(input(), shell=True)\n')) == 1


def test_suppression_comment():
    assert intra('import os\nx=input()\nos.system(x)  # taintpy: ignore\n') == []
    assert intra('import os\nx=input()\nos.system(x)  # noqa: taintpy\n') == []


# --- sources ------------------------------------------------------------------

def test_flask_route_parameters_are_sources():
    code = ('import os\nfrom flask import Flask\napp=Flask(__name__)\n'
            '@app.route("/run/<cmd>")\ndef run(cmd):\n    os.system(cmd)\n')
    assert lines(intra(code)) == [6]


def test_fastapi_params_are_sources_but_depends_is_not():
    code = ('import os\nfrom fastapi import FastAPI, Depends\napp=FastAPI()\n'
            '@app.get("/x")\ndef x(q: str, db=Depends(get_db)):\n'
            '    os.system(q)\n    os.system(db)\n')
    assert lines(intra(code)) == [6]


def test_mock_patch_is_not_a_route():
    code = ('import os\nfrom unittest import mock\n'
            '@mock.patch("os.system")\ndef test_x(m):\n    os.system(m)\n')
    assert intra(code) == []


def test_django_class_based_view_request():
    code = ('import os\nclass V:\n    def get(self, request):\n'
            '        os.system(self.request.GET["q"])\n')
    assert lines(intra(code)) == [4]


# --- findings carry the path ----------------------------------------------------

def test_finding_records_source_and_path():
    code = 'import os\nraw = input()\ntmp = raw\ncmd = "echo " + tmp\nos.system(cmd)\n'
    (f,) = intra(code)
    assert (f.source_line, f.lineno) == (2, 5)
    assert [(s.line, s.kind) for s in f.path] == [
        (2, "source"), (2, "assign"), (3, "assign"), (4, "assign"), (5, "sink")]
    d = f.to_dict()
    assert d["source_line"] == 2 and d["line"] == 5 and len(d["path"]) == 5


def test_two_sources_to_one_sink_are_two_findings():
    code = 'import os, sys\nif c:\n    x = input()\nelse:\n    x = sys.argv[1]\nos.system(x)\n'
    assert len(intra(code)) == 1, "one path per variable is kept"
    code = 'import os, sys\nos.system(input() + sys.argv[1])\n'
    assert len(intra(code)) == 1
    code = 'import os, sys\ndef f(a):\n    os.system(a)\nf(input())\nf(sys.argv[1])\n'
    assert intra(code) == [], "intraprocedural mode does not follow calls"
