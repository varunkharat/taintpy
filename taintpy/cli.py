"""cli.py — command-line interface.

Usage:
    python -m taintpy <file-or-directory> [file-or-directory ...]
"""

import argparse
import os
import sys

from .analyzer import analyze_file
from .interprocedural import analyze_file_interprocedural


def iter_python_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in files:
                    if name.endswith(".py"):
                        yield os.path.join(root, name)
        elif path.endswith(".py"):
            yield path
        else:
            print(f"skipping non-python path: {path}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="taintpy",
        description="Taint-tracking static analyzer for injection bugs.",
    )
    parser.add_argument("paths", nargs="+", help="Python files or directories")
    parser.add_argument("--interproc", action="store_true",
                        help="follow taint across function boundaries")
    args = parser.parse_args(argv)

    scan = analyze_file_interprocedural if args.interproc else analyze_file

    all_findings = []
    for path in iter_python_files(args.paths):
        try:
            all_findings.extend(scan(path))
        except SyntaxError as e:
            print(f"skip (syntax error): {path}: {e}", file=sys.stderr)

    # Highest severity first, then by location.
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda f: (order.get(f.severity, 9), f.filename, f.lineno))

    for finding in all_findings:
        print(finding)
        print()

    print(f"--- {len(all_findings)} finding(s) ---")
    # Exit non-zero if anything was found (handy for CI later).
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
