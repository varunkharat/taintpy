"""Interprocedural engine: summaries, resolution, attributes, globals, modules."""

import os

from taint_helpers import HERE, inter, inter_files, lines

from taintpy.analyzer import analyze_file
from taintpy.interprocedural import (
    analyze_file_interprocedural,
    analyze_files_interprocedural,
    analyze_program,
)


def test_interproc_example_blind_without_engine():
    assert analyze_file(os.path.join(HERE, "interproc_example.py")) == []


def test_interproc_example():
    f = analyze_file_interprocedural(os.path.join(HERE, "interproc_example.py"))
    # Both findings are at the sink inside run_it, from two different sources.
    assert lines(f) == [13, 13]
    assert sorted(x.source_line for x in f) == [9, 28]


def test_source_inside_callee_is_the_reported_source():
    code = 'import os\ndef get():\n    return input()\ndef main():\n    v = get()\n    os.system(v)\n'
    (f,) = inter(code)
    assert (f.source_line, f.lineno) == (3, 6)
    kinds = [s.kind for s in f.path]
    assert kinds[0] == "source" and kinds[-1] == "sink" and "return" in kinds


def test_finding_is_reported_at_the_sink_inside_the_callee():
    code = 'import os\ndef h(p):\n    os.system(p)\nh(input())\n'
    (f,) = inter(code)
    assert (f.lineno, f.source_line, f.sink) == (3, 4, "os.system")
    assert "reached through h()" in f.note


def test_param_reaching_two_sinks_gives_two_findings():
    code = 'import os\ndef h(p):\n    open(p)\n    os.system(p)\nh(input())\n'
    f = inter(code)
    assert sorted((x.lineno, x.severity) for x in f) == [(3, "MEDIUM"), (4, "HIGH")]


def test_summary_sources_off_while_seeding():
    # A function that returns input() is "returns a source", not "param -> return".
    code = 'import os\ndef h(p):\n    return input()\nos.system(h("const"))\n'
    (f,) = inter(code)
    assert f.tainted_arg == "h('const')" and f.source_line == 3


def test_keyword_args_map_to_params():
    code = 'import os\ndef h(a, cmd):\n    os.system(cmd)\nh(cmd=input(), a=1)\nh(1, "safe")\n'
    (f,) = inter(code)
    assert f.source_line == 4


def test_star_args_and_kwargs():
    code = ('import os\ndef a(*args):\n    os.system(args[0])\n'
            'def b(**kw):\n    os.system(kw["c"])\n'
            'def c(x, y):\n    os.system(y)\n'
            'a(input())\nb(c=input())\nc(*input().split())\n')
    assert sorted((x.lineno, x.source_line) for x in inter(code)) == [(3, 8), (5, 9), (7, 10)]


def test_methods_resolve_via_self():
    code = ('import os\nclass C:\n    def sink(self, p):\n        os.system(p)\n'
            '    def entry(self):\n        self.sink(input())\n')
    (f,) = inter(code)
    assert (f.lineno, f.source_line, f.confidence) == (4, 6, "high")


def test_constructor_typed_local_resolves_the_right_class():
    # Two classes define run(); only A.run has a sink. b is a B, so no finding.
    code = ('import os\nclass A:\n    def run(self, x):\n        os.system(x)\n'
            'class B:\n    def run(self, x):\n        print(x)\n'
            'b = B()\nb.run(input())\na = A()\na.run(input())\n')
    (f,) = inter(code)
    assert (f.lineno, f.source_line, f.confidence) == (4, 11, "high")


def test_ambiguous_method_name_is_reported_with_low_confidence():
    code = ('import os\nclass A:\n    def run(self, x):\n        os.system(x)\n'
            'class B:\n    def run(self, x):\n        print(x)\n'
            'def go(obj):\n    obj.run(input())\n')
    (f,) = inter(code)
    assert f.confidence == "low"
    assert any("ambiguous" in s.detail for s in f.path)


def test_unique_method_name_is_medium_confidence():
    code = 'import os\nclass A:\n    def run(self, x):\n        os.system(x)\ndef go(obj):\n    obj.run(input())\n'
    (f,) = inter(code)
    assert f.confidence == "medium"


def test_builtin_method_names_are_not_guessed():
    # A user class with a get() method must not hijack dict.get.
    code = ('import os\nclass Repo:\n    def get(self, key):\n        return key\n'
            'def go(cache):\n    os.system(cache.get(input()))\n')
    assert inter(code) == []


def test_user_function_shadowing_a_rule_name_uses_the_summary():
    code = 'def execute(q):\n    print(q)\nexecute(input())\n'
    assert inter(code) == []


def test_class_called_as_attribute_skips_self():
    code = ('import os\nclass C:\n    def m(self, x):\n        os.system(x)\n'
            'C.m(C(), input())\nC.m(input(), "safe")\n')
    (f,) = inter(code)
    assert f.source_line == 5


def test_super_call():
    code = ('import os\nclass Base:\n    def run(self, x):\n        os.system(x)\n'
            'class Child(Base):\n    def run(self, x):\n        super().run(x)\n'
            '    def go(self):\n        self.run(input())\n')
    assert lines(inter(code)) == [4]


def test_instance_attribute_across_methods():
    code = ('import os\nclass S:\n    def __init__(self):\n        self.cmd = input()\n'
            '    def go(self):\n        os.system(self.cmd)\n')
    (f,) = inter(code)
    assert (f.lineno, f.source_line) == (6, 4)


def test_instance_attribute_from_constructor_argument():
    code = ('import os\nclass S:\n    def __init__(self, cmd):\n        self.cmd = cmd\n'
            '    def go(self):\n        os.system(self.cmd)\n'
            's = S(input())\ns.go()\nt = S("ls")\n')
    (f,) = inter(code)
    assert (f.lineno, f.source_line) == (6, 7)


def test_attribute_read_on_typed_local_and_inherited_attribute():
    code = ('import os\nclass Base:\n    def __init__(self, p):\n        self.p = p\n'
            'class Child(Base):\n    def use(self):\n        open(self.p)\n'
            'c = Child(input())\nos.system(c.p)\n')
    assert sorted((x.lineno, x.source_line) for x in inter(code)) == [(7, 8), (9, 8)]


def test_module_global():
    code = 'import os\nCMD = input()\ndef f():\n    os.system(CMD)\n'
    (f,) = inter(code)
    assert (f.lineno, f.source_line) == (4, 2)


def test_global_written_inside_function():
    code = ('import os\nCMD = "ls"\ndef load():\n    global CMD\n    CMD = input()\n'
            'def run():\n    os.system(CMD)\n')
    (f,) = inter(code)
    assert (f.lineno, f.source_line) == (7, 5)


def test_local_shadows_global():
    code = 'import os\nCMD = input()\ndef f():\n    CMD = "ls"\n    os.system(CMD)\n'
    assert inter(code) == []


def test_recursion_terminates():
    code = ('import os\ndef f(x, n):\n    if n:\n        return f(x, n - 1)\n    return x\n'
            'os.system(f(input(), 3))\n')
    ctx = analyze_program([("<t>", code)])
    assert ctx.converged and len(ctx.findings) == 1


# --- multiple modules ----------------------------------------------------------

def test_cross_file_fixture():
    paths = [os.path.join(HERE, "multifile", n) for n in ("helpers.py", "main.py")]
    f = analyze_files_interprocedural(paths)
    got = sorted((os.path.basename(x.filename), x.lineno,
                  os.path.basename(x.source_file), x.source_line) for x in f)
    assert got == [("helpers.py", 7, "main.py", 8),
                   ("helpers.py", 7, "main.py", 12),
                   ("helpers.py", 18, "main.py", 17)]


def test_import_alias_and_from_import(tmp_path):
    f = inter_files(tmp_path, {
        "util.py": "import os\ndef sh(c):\n    os.system(c)\n",
        "a.py": "import util as u\nu.sh(input())\n",
        "b.py": "from util import sh as run\nrun(input())\n",
    })
    assert sorted(os.path.basename(x.source_file) for x in f) == ["a.py", "b.py"]
    assert all(x.confidence == "high" for x in f)


def test_package_relative_import_and_reexport(tmp_path):
    f = inter_files(tmp_path, {
        "pkg/__init__.py": "from .core import run\n",
        "pkg/core.py": "import os\ndef run(c):\n    os.system(c)\n",
        "pkg/sub/__init__.py": "",
        "pkg/sub/user.py": "from .. import run\nfrom ..core import run as r2\nrun(input())\nr2(input())\n",
        "app.py": "import pkg\npkg.run(input())\n",
    })
    assert sorted((os.path.basename(x.source_file), x.source_line) for x in f) == [
        ("app.py", 2), ("user.py", 3), ("user.py", 4)]


def test_same_function_name_in_two_modules_is_not_confused(tmp_path):
    f = inter_files(tmp_path, {
        "danger.py": "import os\ndef run(c):\n    os.system(c)\n",
        "safe.py": "def run(c):\n    print(c)\n",
        "main.py": "from safe import run\nrun(input())\n",
    })
    assert f == []


def test_imported_global(tmp_path):
    f = inter_files(tmp_path, {
        "config.py": "import os\nCMD = os.environ['CMD']\n",
        "main.py": "import os\nfrom config import CMD\ndef go():\n    os.system(CMD)\n",
    })
    (x,) = f
    assert os.path.basename(x.source_file) == "config.py" and x.lineno == 4


def test_external_library_call_is_not_matched_to_user_method():
    code = ('import os, requests\nclass Client:\n    def get(self, u):\n        os.system(u)\n'
            'requests.get(input())\n')
    assert [x.category for x in inter(code)] == ["ssrf"]
