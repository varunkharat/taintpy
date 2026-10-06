"""SARIF 2.1.0 output.

SARIF is the JSON format GitHub code scanning reads, and the one Semgrep and
CodeQL can both emit, so producing it lets taintpy results sit next to theirs
in the same viewer or the same comparison script. Each finding becomes a
result with a ``codeFlow`` holding the full taint path.
"""

import os

from . import __version__

LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def _uri(path):
    return path.replace(os.sep, "/")


def _location(file, line, message=None):
    loc = {"physicalLocation": {"artifactLocation": {"uri": _uri(file)},
                                "region": {"startLine": max(int(line), 1)}}}
    if message:
        loc["message"] = {"text": message}
    return loc


def to_sarif(result):
    categories = sorted({f.category for f in result.findings})
    rules = [{"id": c, "name": c, "shortDescription": {"text": c.replace("-", " ")}}
             for c in categories]
    results = []
    for f in result.findings:
        flow = [{"location": _location(s.file, s.line, f"{s.kind}: {s.detail}")}
                for s in f.path]
        results.append({
            "ruleId": f.category,
            "level": LEVELS.get(f.severity, "warning"),
            "message": {"text": f"Tainted data from line {f.source_line} reaches "
                                f"{f.sink}(): {f.tainted_arg}"},
            "locations": [_location(f.filename, f.lineno)],
            "relatedLocations": [dict(_location(f.source_file, f.source_line, "source"), id=0)],
            "codeFlows": [{"threadFlows": [{"locations": flow}]}] if flow else [],
            "properties": {"severity": f.severity, "confidence": f.confidence,
                           "sink": f.sink, "note": f.note},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "taintpy", "version": __version__,
                                "rules": rules}},
            "properties": {"engine": result.engine,
                           "unknown_calls": result.unknown_calls,
                           "skipped": result.skipped},
            "results": results,
        }],
    }
