"""Score static analyzers against a labeled ground-truth file.

    python bench/run_bench.py GROUNDTRUTH.json [--tools taintpy,bandit,semgrep]
                              [--sarif NAME=FILE ...] [--match-category] [--out DIR]

See bench/README.md for the ground-truth format and the scoring rules.
Standard library only. Bandit and Semgrep are run as subprocesses when they
are on PATH; CodeQL, or any other tool, can be scored from a SARIF file you
produce yourself.
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
from collections import namedtuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# A tool result reduced to what scoring needs.
Detection = namedtuple("Detection", "file line cwe rule")

# taintpy category -> CWE, so --match-category can compare across tools.
CATEGORY_CWE = {
    "command-injection": {78, 77},
    "code-injection": {94, 95},
    "deserialization": {502},
    "sql-injection": {89},
    "path-traversal": {22, 23, 36, 73},
    "ssrf": {918},
    "template-injection": {1336, 94},
    "xss": {79},
    "xxe": {611},
    "ldap-injection": {90},
    "open-redirect": {601},
}


# --- ground truth ------------------------------------------------------------

def load_groundtruth(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    base = os.path.dirname(os.path.abspath(path))
    projects = {}
    for p in data["projects"]:
        p = dict(p)
        p["root"] = os.path.normpath(os.path.join(base, p["root"]))
        for case in p["cases"]:
            case.setdefault("vulnerable", True)
            if "lines" not in case and "function" not in case:
                raise ValueError(f"case {case.get('id')} needs 'lines' or 'function'")
        projects[p["name"]] = p
    return data.get("name", os.path.basename(path)), projects


def resolve_function_lines(root, case):
    """Turn a {"function": "Cls.method"} label into a line range by parsing
    the file. Lets labels survive small edits that shift line numbers."""
    import ast
    with open(os.path.join(root, case["file"]), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    wanted = case["function"].split(".")

    def search(body, names):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and node.name == names[0]:
                if len(names) == 1:
                    return node.lineno, node.end_lineno
                return search(node.body, names[1:])
        return None

    found = search(tree.body, wanted)
    if found is None:
        raise ValueError(f"case {case.get('id')}: function {case['function']} not found")
    return found


# --- running tools -----------------------------------------------------------

def _norm(path, root):
    path = os.path.normpath(path if os.path.isabs(path) else os.path.join(root, path))
    return os.path.relpath(path, root).replace(os.sep, "/")


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "unknown"


def run_taintpy(root, variant):
    engine, unknown = variant
    cmd = [sys.executable, "-m", "taintpy", "--format", "json",
           "--engine", engine, "--unknown-calls", unknown, "."]
    out = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=ROOT))
    data = json.loads(out.stdout)
    dets = []
    for f in data["findings"]:
        cwe = sorted(CATEGORY_CWE.get(f["category"], ()))
        dets.append(Detection(_norm(f["file"], root), f["line"], cwe, f["category"]))
    return dets, cmd, {"files_scanned": data["files_scanned"], "skipped": len(data["skipped"])}


def run_bandit(root):
    cmd = ["bandit", "-f", "json", "-q", "-r", "."]
    out = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    data = json.loads(out.stdout or "{}")
    dets = []
    for r in data.get("results", []):
        cwe = r.get("issue_cwe", {}).get("id")
        dets.append(Detection(_norm(r["filename"], root), r["line_number"],
                              [cwe] if cwe else [], r["test_id"]))
    scanned = data.get("metrics", {}).get("_totals", {})
    files = len([k for k in data.get("metrics", {}) if k != "_totals"])
    return dets, cmd, {"files_scanned": files, "errors": len(data.get("errors", [])),
                       "loc": scanned.get("loc")}


def run_semgrep(root, config):
    """Semgrep skips paths matching its default ignore list, which includes
    any ``tests/`` directory, and only scans files tracked by git. Either one
    can silently drop a benchmark project. So the project is copied to a
    temporary directory outside any repository, with an explicit empty
    .semgrepignore, and the number of files Semgrep reports as scanned is
    kept in the results."""
    import tempfile
    cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet",
           "--metrics", "off", "--no-git-ignore", "."]
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "project")
        shutil.copytree(root, work)
        open(os.path.join(work, ".semgrepignore"), "w").close()
        out = subprocess.run(cmd, cwd=work, capture_output=True, text=True)
    data = json.loads(out.stdout)
    dets = []
    for r in data.get("results", []):
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        dets.append(Detection(r["path"].replace("\\", "/"), r["start"]["line"],
                              sorted({n for n in map(_cwe_number, cwes) if n}), r["check_id"]))
    return dets, cmd, {"files_scanned": len(data.get("paths", {}).get("scanned", []))}


def parse_sarif(sarif, root):
    dets = []
    for run in sarif.get("runs", []):
        rule_cwes = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            tags = rule.get("properties", {}).get("tags", []) + \
                [rule.get("properties", {}).get("cwe", "")]
            rule_cwes[rule.get("id")] = sorted({_cwe_number(t) for t in tags if _cwe_number(t)})
        for res in run.get("results", []):
            for loc in res.get("locations", [])[:1]:
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                if uri.startswith("file://"):
                    uri = uri[len("file://"):]
                line = phys.get("region", {}).get("startLine", 0)
                dets.append(Detection(_norm(uri, root), line,
                                      rule_cwes.get(res.get("ruleId"), []), res.get("ruleId")))
    return dets


def _cwe_number(tag):
    tag = str(tag).upper()
    if "CWE-" not in tag:
        return None
    digits = ""
    for ch in tag.split("CWE-", 1)[1]:
        if not ch.isdigit():
            break
        digits += ch
    return int(digits) if digits else None


def count_python_files(root):
    return sum(1 for _, _, files in os.walk(root) for f in files if f.endswith(".py"))


# --- scoring -----------------------------------------------------------------

def case_matches(case, det, match_category):
    if det.file != case["file"].replace("\\", "/"):
        return False
    start, end = case["_range"]
    if not start <= det.line <= end:
        return False
    if match_category and case.get("cwe"):
        return int(case["cwe"]) in det.cwe
    return True


def score(projects, detections_by_project, match_category):
    """Per-case outcomes plus totals.

    TP: a vulnerable case with at least one detection inside it.
    FN: a vulnerable case with none.
    FP: a safe case (``"vulnerable": false``) with a detection inside it.
    TN: a safe case with none.
    Detections outside every labeled region are counted as ``unlabeled``.
    They are not called false positives because nobody checked them.
    """
    cases_out = []
    totals = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "unlabeled": 0}
    for name, project in projects.items():
        dets = detections_by_project.get(name, [])
        used = set()
        for case in project["cases"]:
            hits = [i for i, d in enumerate(dets) if case_matches(case, d, match_category)]
            used.update(hits)
            if case["vulnerable"]:
                outcome = "TP" if hits else "FN"
            else:
                outcome = "FP" if hits else "TN"
            totals[outcome] += 1
            cases_out.append({"project": name, "id": case.get("id"), "outcome": outcome,
                              "detections": [dets[i]._asdict() for i in hits]})
        labeled_files = {c["file"].replace("\\", "/") for c in project["cases"]}
        totals["unlabeled"] += sum(1 for i, d in enumerate(dets)
                                   if i not in used and d.file in labeled_files)
    vuln = totals["TP"] + totals["FN"]
    safe = totals["FP"] + totals["TN"]
    totals["recall"] = round(totals["TP"] / vuln, 4) if vuln else None
    totals["false_positive_rate"] = round(totals["FP"] / safe, 4) if safe else None
    return totals, cases_out


# --- main --------------------------------------------------------------------

TAINTPY_VARIANTS = {
    "taintpy": ("interproc", "sanitize"),
    "taintpy-intra": ("intra", "sanitize"),
    "taintpy-propagate": ("interproc", "propagate"),
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("groundtruth")
    ap.add_argument("--tools", default="taintpy,taintpy-intra,taintpy-propagate,bandit,semgrep",
                    help="comma-separated: " + ", ".join(list(TAINTPY_VARIANTS) + ["bandit", "semgrep"]))
    ap.add_argument("--semgrep-config", default="p/python")
    ap.add_argument("--sarif", action="append", default=[], metavar="NAME=FILE",
                    help="score a SARIF file produced elsewhere, e.g. codeql=out.sarif "
                         "(single-project ground truth only)")
    ap.add_argument("--match-category", action="store_true",
                    help="also require the detection's CWE to equal the case's CWE")
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    args = ap.parse_args(argv)

    dataset, projects = load_groundtruth(args.groundtruth)
    for p in projects.values():
        for case in p["cases"]:
            case["_range"] = tuple(case["lines"]) if "lines" in case \
                else resolve_function_lines(p["root"], case)

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    report = {"dataset": dataset, "groundtruth": os.path.abspath(args.groundtruth),
              "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "python": platform.python_version(), "platform": platform.platform(),
              "match_category": args.match_category, "tools": {}}

    for tool in tools:
        if tool in TAINTPY_VARIANTS:
            version = tool_version([sys.executable, "-m", "taintpy", "--version"])
            runner = lambda root, t=tool: run_taintpy(root, TAINTPY_VARIANTS[t])  # noqa: E731
        elif tool == "bandit":
            if not shutil.which("bandit"):
                print("bandit not on PATH, skipping", file=sys.stderr)
                continue
            version, runner = tool_version(["bandit", "--version"]), run_bandit
        elif tool == "semgrep":
            if not shutil.which("semgrep"):
                print("semgrep not on PATH, skipping", file=sys.stderr)
                continue
            version = tool_version(["semgrep", "--version"])
            runner = lambda root: run_semgrep(root, args.semgrep_config)  # noqa: E731
        else:
            ap.error(f"unknown tool {tool}")
        dets, commands, coverage = {}, None, {}
        for name, p in projects.items():
            dets[name], commands, coverage[name] = runner(p["root"])
            expected = count_python_files(p["root"])
            got = coverage[name].get("files_scanned")
            if got is not None and got < expected:
                print(f"warning: {tool} scanned {got} of {expected} .py files in {name}",
                      file=sys.stderr)
        totals, cases = score(projects, dets, args.match_category)
        report["tools"][tool] = {"version": version, "command": commands,
                                 "coverage": coverage, "totals": totals, "cases": cases}

    for spec in args.sarif:
        name, _, path = spec.partition("=")
        if len(projects) != 1:
            ap.error("--sarif needs a ground truth with exactly one project")
        (pname, p), = projects.items()
        with open(path, encoding="utf-8") as f:
            dets = {pname: parse_sarif(json.load(f), p["root"])}
        totals, cases = score(projects, dets, args.match_category)
        report["tools"][name] = {"version": "from SARIF", "command": f"SARIF file {path}",
                                 "totals": totals, "cases": cases}

    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, os.path.splitext(os.path.basename(args.groundtruth))[0])
    with open(stem + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    table = render_table(report)
    with open(stem + ".md", "w", encoding="utf-8") as f:
        f.write(table)
    print(table)
    return 0


def render_table(report):
    rows = [f"Dataset: {report['dataset']}  ",
            f"Run: {report['date']}, Python {report['python']}, {report['platform']}  ",
            f"Category must match: {report['match_category']}",
            "",
            "| tool | version | files scanned | TP | FN | FP | TN | unlabeled | recall | FP rate |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for name, t in report["tools"].items():
        s = t["totals"]
        fmt = lambda v: "n/a" if v is None else f"{v:.3f}"  # noqa: E731
        scanned = sum((c.get("files_scanned") or 0) for c in t.get("coverage", {}).values())             if t.get("coverage") else "n/a"
        rows.append(f"| {name} | {t['version']} | {scanned} | {s['TP']} | {s['FN']} | {s['FP']} | {s['TN']} "
                    f"| {s['unlabeled']} | {fmt(s['recall'])} | {fmt(s['false_positive_rate'])} |")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
