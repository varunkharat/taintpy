"""Command-line interface.

    taintpy [--engine interproc|intra] [--format text|json|sarif] [--rules FILE]
            [--unknown-calls sanitize|propagate] [--min-severity LEVEL]
            [--min-confidence LEVEL] [-o FILE] <file-or-directory> ...
"""

import argparse
import ast
import json
import os
import sys
import warnings

from . import __version__, rules
from .analyzer import CONFIDENCE_ORDER, SEVERITY_ORDER, analyze_source
from .interprocedural import analyze_program
from .sarif import to_sarif

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "env", "node_modules",
             ".tox", ".nox", ".mypy_cache", ".pytest_cache", "build", "dist",
             "site-packages"}


def iter_python_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                                 and not d.endswith(".egg-info"))
                for name in sorted(files):
                    if name.endswith(".py"):
                        yield os.path.join(root, name)
        elif path.endswith(".py") and os.path.isfile(path):
            yield path
        else:
            yield path        # reported as skipped by load_sources


def load_sources(paths):
    """Read and syntax-check every file.

    Returns (sources, skipped). A file that cannot be analyzed is never
    dropped silently: it goes in ``skipped`` with the reason, and that list
    is part of the JSON and SARIF output. Python 2 files are the common case
    in older projects, and a scan that quietly ignored them would look
    cleaner than it is.
    """
    sources, skipped = [], []
    for path in iter_python_files(paths):
        if not (path.endswith(".py") and os.path.isfile(path)):
            skipped.append({"file": path, "reason": "not a python file"})
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()
            with warnings.catch_warnings():
                # Invalid escape sequences in old code warn on parse.
                warnings.simplefilter("ignore", SyntaxWarning)
                ast.parse(code, filename=path)
        except (OSError, UnicodeDecodeError) as e:
            skipped.append({"file": path, "reason": f"unreadable: {e}"})
            continue
        except (SyntaxError, ValueError) as e:
            skipped.append({"file": path, "reason": f"syntax error: {e}"})
            continue
        sources.append((path, code))
    return sources, skipped


class ScanResult:
    def __init__(self, findings, skipped, files_scanned, engine, unknown_calls,
                 rounds=None, converged=None):
        self.findings = findings
        self.skipped = skipped
        self.files_scanned = files_scanned
        self.engine = engine
        self.unknown_calls = unknown_calls
        self.rounds = rounds
        self.converged = converged


def scan(paths, engine="interproc", unknown_calls="sanitize",
         min_severity="LOW", min_confidence="low"):
    sources, skipped = load_sources(paths)
    rounds = converged = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        if engine == "interproc":
            ctx = analyze_program(sources, unknown_calls)
            findings, rounds, converged = ctx.findings, ctx.rounds, ctx.converged
        else:
            findings = []
            for path, code in sources:
                findings.extend(analyze_source(code, filename=path,
                                               unknown_calls=unknown_calls))

    sev_cap = SEVERITY_ORDER[min_severity.upper()]
    conf_cap = CONFIDENCE_ORDER[min_confidence.lower()]
    findings = [f for f in findings
                if SEVERITY_ORDER.get(f.severity, 9) <= sev_cap
                and CONFIDENCE_ORDER[f.confidence] <= conf_cap]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.filename,
                                 f.lineno, f.source_file, f.source_line))
    return ScanResult(findings, skipped, len(sources), engine, unknown_calls,
                      rounds, converged)


def run(paths, interproc=False, min_severity="LOW"):
    """Older entry point, kept so existing scripts keep working."""
    return scan(paths, "interproc" if interproc else "intra",
                min_severity=min_severity).findings


def to_json(result, rules_files=()):
    return {
        "tool": "taintpy",
        "version": __version__,
        "engine": result.engine,
        "options": {"unknown_calls": result.unknown_calls},
        "rules_files": list(rules_files),
        "files_scanned": result.files_scanned,
        "fixpoint": {"rounds": result.rounds, "converged": result.converged},
        "skipped": result.skipped,
        "count": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
    }


def to_text(result):
    out = []
    for finding in result.findings:
        out.append(str(finding))
        out.append("")
    out.append(f"--- {len(result.findings)} finding(s) in {result.files_scanned} "
               f"file(s), engine={result.engine} ---")
    if result.skipped:
        out.append(f"--- {len(result.skipped)} path(s) skipped ---")
        for s in result.skipped:
            out.append(f"    {s['file']}: {s['reason']}")
    return "\n".join(out)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="taintpy",
        description="Taint-tracking static analyzer for Python injection bugs.",
    )
    parser.add_argument("paths", nargs="+", help="Python files or directories")
    parser.add_argument("--engine", choices=("interproc", "intra"), default="interproc",
                        help="interproc follows taint across functions and files "
                             "(default); intra stays inside one function")
    parser.add_argument("--interproc", action="store_const", const="interproc",
                        dest="engine", help="same as --engine interproc")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text",
                        help="output format (default: text)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write the report to FILE instead of stdout")
    parser.add_argument("--rules", metavar="FILE", action="append", default=[],
                        help="JSON file with extra sources/sinks (repeatable)")
    parser.add_argument("--unknown-calls", choices=("sanitize", "propagate"),
                        default="sanitize",
                        help="what a call taintpy knows nothing about does to taint "
                             "(default: sanitize)")
    parser.add_argument("--min-severity", choices=("HIGH", "MEDIUM", "LOW"),
                        default="LOW", help="hide findings below this severity")
    parser.add_argument("--min-confidence", choices=("high", "medium", "low"),
                        default="low", help="hide findings below this confidence")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    saved = rules.snapshot()
    try:
        for rules_file in args.rules:
            rules.load_rules(rules_file)
        result = scan(args.paths, args.engine, args.unknown_calls,
                      args.min_severity, args.min_confidence)
    finally:
        rules.restore(saved)

    if args.format == "json":
        report = json.dumps(to_json(result, args.rules), indent=2)
    elif args.format == "sarif":
        report = json.dumps(to_sarif(result), indent=2)
    else:
        report = to_text(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:  # taintpy: ignore (the operator picks this path)
            f.write(report + "\n")
    else:
        print(report)

    if result.converged is False:
        print("warning: interprocedural fixpoint hit its round limit; "
              "results may be incomplete", file=sys.stderr)

    # Non-zero when anything was found, so it drops into CI.
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
