"""Command-line interface: output formats, filters, exit codes, rule files."""

import contextlib
import io
import json
import os

from taint_helpers import HERE

from taintpy import rules
from taintpy.analyzer import analyze_source
from taintpy.cli import main

FAKE_APP = os.path.join(HERE, "fake_app")
MULTIFILE = os.path.join(HERE, "multifile")


def _cli(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_json_report_and_exit_code():
    rc, out = _cli(["--format", "json", MULTIFILE])
    assert rc == 1
    data = json.loads(out)
    assert data["tool"] == "taintpy" and data["engine"] == "interproc"
    assert data["count"] == 3 and data["files_scanned"] == 2
    assert data["fixpoint"]["converged"] is True
    f = data["findings"][0]
    assert {"file", "line", "severity", "confidence", "category", "sink",
            "source_file", "source_line", "path"} <= set(f)
    assert f["path"][0]["kind"] == "source" and f["path"][-1]["kind"] == "sink"

    rc, out = _cli([os.path.join(HERE, "safe_example.py")])
    assert rc == 0 and "0 finding(s)" in out


def test_engine_flag():
    _, out = _cli(["--format", "json", "--engine", "intra", MULTIFILE])
    assert json.loads(out)["count"] == 0
    _, out = _cli(["--format", "json", "--interproc", MULTIFILE])
    assert json.loads(out)["count"] == 3


def test_min_severity_and_confidence():
    _, out = _cli(["--format", "json", "--min-severity", "HIGH", FAKE_APP])
    data = json.loads(out)
    assert data["count"] > 0 and all(f["severity"] == "HIGH" for f in data["findings"])
    _, out = _cli(["--format", "json", "--min-confidence", "high", FAKE_APP])
    assert all(f["confidence"] == "high" for f in json.loads(out)["findings"])


def test_skipped_files_are_reported(tmp_path):
    (tmp_path / "py2.py").write_text('print "hello"\n', encoding="utf-8")
    (tmp_path / "ok.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    rc, out = _cli(["--format", "json", str(tmp_path)])
    data = json.loads(out)
    assert rc == 1 and data["files_scanned"] == 1
    assert len(data["skipped"]) == 1 and "syntax error" in data["skipped"][0]["reason"]
    _, text = _cli([str(tmp_path)])
    assert "1 path(s) skipped" in text


def test_sarif_output(tmp_path):
    out_file = tmp_path / "r.sarif"
    rc = main(["--format", "sarif", "-o", str(out_file), MULTIFILE])
    assert rc == 1
    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "taintpy"
    assert len(run["results"]) == 3
    r = run["results"][0]
    assert r["ruleId"] in {"command-injection", "path-traversal"}
    assert r["codeFlows"][0]["threadFlows"][0]["locations"]


def test_rules_file_and_restore(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({
        "sources": ["bottle.request.query.get"],
        "sinks": {"db.raw": ["sql-injection", "high"],
                  "db.q": {"category": "sql-injection", "severity": "medium",
                           "args": [0]}},
    }), encoding="utf-8")
    code_file = tmp_path / "app.py"
    code_file.write_text('q=bottle.request.query.get("q")\ndb.raw(q)\ndb.q("x", q)\ndb.q(q)\n',
                         encoding="utf-8")
    _, out = _cli(["--format", "json", "--rules", str(p), str(code_file)])
    found = sorted((f["line"], f["severity"]) for f in json.loads(out)["findings"])
    assert found == [(2, "HIGH"), (4, "MEDIUM")]
    # The CLI restores the built-in rules afterwards.
    assert "db.raw" not in rules.SINKS
    assert analyze_source('q=bottle.request.query.get("q")\ndb.raw(q)\n') == []
