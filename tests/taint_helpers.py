"""Shared helpers for the test files."""

import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from taintpy.analyzer import analyze_source  # noqa: E402
from taintpy.interprocedural import analyze_program  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def intra(code):
    return analyze_source(textwrap.dedent(code))


def inter(code, **kw):
    return analyze_program([("<test>", textwrap.dedent(code))], **kw).findings


def inter_files(tmp_path, files, **kw):
    """Write ``{relative path: code}`` under tmp_path and analyze them together."""
    sources = []
    for rel, code in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")
        sources.append((str(path), path.read_text(encoding="utf-8")))
    return analyze_program(sources, **kw).findings


def lines(findings):
    return sorted(f.lineno for f in findings)
