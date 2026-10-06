"""The in-browser build in docs/ must match the current source, and the
shared service module must behave the same way the server does."""

import json
import os
import subprocess
import sys

from taint_helpers import HERE

from taintpy import rules
from taintpy.service import analyze_json

ROOT = os.path.dirname(HERE)


def _tree(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                out[os.path.relpath(path, root).replace(os.sep, "/")] = f.read()
    return out


def test_docs_site_is_up_to_date(tmp_path):
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_site.py"),
                    str(tmp_path)], check=True, capture_output=True)
    built, committed = _tree(str(tmp_path)), _tree(os.path.join(ROOT, "docs"))
    assert built.keys() == committed.keys()
    stale = sorted(k for k in built if built[k] != committed[k])
    assert not stale, f"docs/ is stale, run python tools/build_site.py: {stale}"
    assert 'const BACKEND = "pyodide";' in built["index.html"]


def test_analyze_json_round_trip():
    out = json.loads(analyze_json(json.dumps({"code": "import os\nos.system(input())\n"})))
    assert out["status"] == 200 and out["body"]["count"] == 1
    f = out["body"]["findings"][0]
    assert f["explanation"] and f["fix"]


def test_analyze_json_errors():
    out = json.loads(analyze_json(json.dumps({"code": "def (:\n"})))
    assert out["status"] == 400 and out["body"]["detail"]["line"] == 1
    out = json.loads(analyze_json(json.dumps({"code": "x=1", "engine": "magic"})))
    assert out["status"] == 422


def test_every_category_has_help():
    categories = {c for c, _ in rules.SINKS.values()} | {c for c, _ in rules.RECEIVER_SINKS.values()}
    assert categories <= set(rules.CATEGORY_HELP)
