"""The README's sample output must be what the tool really prints."""

import contextlib
import io
import os

from taint_helpers import HERE

from taintpy.cli import main

ROOT = os.path.dirname(HERE)


def test_readme_quick_start_output_is_real():
    buf = io.StringIO()
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        with contextlib.redirect_stdout(buf):
            main(["examples/02_cross_function.py"])
    finally:
        os.chdir(cwd)
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    assert buf.getvalue().strip() in readme


def test_every_example_has_exactly_one_finding():
    examples = os.path.join(ROOT, "examples")
    for name in sorted(os.listdir(examples)):
        if name.endswith(".py"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["--format", "json", os.path.join(examples, name)])
            assert rc == 1 and '"count": 1' in buf.getvalue(), name
