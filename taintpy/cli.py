"""cli.py — command-line interface.

Usage:
    python -m taintpy [--interproc] [--format text|json] [--rules FILE]
                      <file-or-directory> [file-or-directory ...]
"""

import argparse
import ast
import json
import os
import sys

from . import __version__, rules
from .analyzer import analyze_source
from .interprocedural import analyze_sources_interprocedural

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "env", "node_modules",
             ".tox", ".mypy_cache", ".pytest_cache", "build", "dist"}

SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def iter_python_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    if name.endswith(".py"):
                        yield os.path.join(root, name)
        elif path.endswith(".py"):
            yield path
        else:
            print(f"skipping non-python path: {path}", file=sys.stderr)


def load_sources(paths):
    """Read and syntax-check every file; skip the ones that don't parse."""
    sources = []
    for path in iter_python_files(paths):
        try:
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()
            ast.parse(code, filename=path)
        except (OSError, UnicodeDecodeError) as e:
            print(f"skip (unreadable): {path}: {e}", file=sys.stderr)
            continue
        except SyntaxError as e:
            print(f"skip (syntax error): {path}: {e}", file=sys.stderr)
            continue
        sources.append((path, code))
    return sources


def run(paths, interproc=False, min_severity="LOW"):
    sources = load_sources(paths)
    if interproc:
        findings = analyze_sources_interprocedural(sources)
    else:
        findings = []
        for path, code in sources:
            findings.extend(analyze_source(code, filename=path))

    threshold = SEVERITY_RANK.get(min_severity.upper(), 2)
    findings = [f for f in findings
                if SEVERITY_RANK.get(f.severity, 9) <= threshold]
    # Highest severity first, then by location.
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9),
                                 f.filename, f.lineno))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="taintpy",
        description="Taint-tracking static analyzer for injection bugs.",
    )
    parser.add_argument("paths", nargs="+", help="Python files or directories")
    parser.add_argument("--interproc", action="store_true",
                        help="follow taint across function boundaries")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="output format (default: text)")
    parser.add_argument("--rules", metavar="FILE", action="append", default=[],
                        help="JSON file with extra sources/sinks (repeatable)")
    parser.add_argument("--min-severity", choices=("HIGH", "MEDIUM", "LOW"),
                        default="LOW", help="hide findings below this level")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    for rules_file in args.rules:
        rules.load_rules(rules_file)   # taintpy: ignore (user-chosen file)

    findings = run(args.paths, interproc=args.interproc,
                   min_severity=args.min_severity)

    if args.format == "json":
        print(json.dumps({"findings": [f.to_dict() for f in findings],
                          "count": len(findings)}, indent=2))
    else:
        for finding in findings:
            print(finding)
            print()
        print(f"--- {len(findings)} finding(s) ---")

    # Exit non-zero if anything was found (handy for CI).
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
