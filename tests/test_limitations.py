"""Known limitations, written as tests that are expected to fail.

Each test states what a perfect analyzer would do. ``strict=True`` means
that if a change makes one of these pass, the suite fails until the test is
moved out of this file and the README's limitations list is updated in the
same commit.
"""

import pytest
from taint_helpers import inter

xfail = pytest.mark.xfail(strict=True)


@xfail
def test_path_sensitivity():
    # A guard that rejects bad input is invisible: there is no path condition.
    code = ('import os\ndef f():\n    x = input()\n    if x.isalnum():\n'
            '        os.system("ls " + x)\n')
    assert inter(code) == []


@xfail
def test_closures():
    # Nested functions do not see the enclosing function's variables.
    code = ('import os\ndef outer():\n    x = input()\n    def inner():\n'
            '        os.system(x)\n    inner()\n')
    assert len(inter(code)) == 1


@xfail
def test_dispatch_to_subclass_override():
    # self.run() inside Base resolves to Base.run, never to a subclass override.
    code = ('import os\nclass Base:\n    def go(self):\n        self.run(input())\n'
            '    def run(self, x):\n        pass\nclass Child(Base):\n'
            '    def run(self, x):\n        os.system(x)\n')
    assert len(inter(code)) == 1


@xfail
def test_instance_attributes_are_flow_insensitive():
    # The attribute is overwritten with a constant before the read, but class
    # attribute taint ignores order, so this is still reported.
    code = ('import os\nclass S:\n    def __init__(self):\n        self.c = input()\n'
            '        self.c = "ls"\n    def go(self):\n        os.system(self.c)\n')
    assert inter(code) == []


@xfail
def test_containers_are_coarse():
    # One tainted key taints the whole dict.
    code = 'import os\nd = {"safe": "ls"}\nd["user"] = input()\nos.system(d["safe"])\n'
    assert inter(code) == []


@xfail
def test_variable_argument_list_is_not_inspected():
    # An exec-form list held in a variable is treated like a shell string.
    code = 'import subprocess\ncmd = ["ls", input()]\nsubprocess.run(cmd)\n'
    assert inter(code) == []


@xfail
def test_unknown_library_calls_drop_taint():
    # textwrap.shorten is not in the propagator list, so taint stops here
    # under the default policy.
    code = 'import os, textwrap\nos.system(textwrap.shorten(input(), 20))\n'
    assert len(inter(code)) == 1


@xfail
def test_lambdas_are_not_analyzed():
    code = 'import os\nrun = lambda c: os.system(c)\nrun(input())\n'
    assert len(inter(code)) == 1


@xfail
def test_sanitizers_are_not_context_aware():
    # html.escape does not stop command injection, but every sanitizer
    # cleans data for every sink.
    code = 'import os, html\nos.system(html.escape(input()))\n'
    assert len(inter(code)) == 1
