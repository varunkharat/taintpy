# Benchmark harness

`run_bench.py` runs several static analyzers on labeled code and scores them
against the labels. It exists so that any accuracy number quoted for taintpy
comes from a run anyone can repeat with one command.

No accuracy results are published in this repository yet. The only dataset
included, `datasets/smoke.json`, labels `tests/fake_app/`, which was written
by the author of taintpy to exercise taintpy. Its job is to show that the
harness works end to end. Numbers from it measure nothing about real code and
should not be quoted.

## Running it

```bash
pip install -e .                       # taintpy itself
pip install bandit semgrep             # optional; skipped when not on PATH
python bench/run_bench.py bench/datasets/smoke.json
```

Tools are chosen with `--tools`. The default runs all of them:

| name | what runs |
| --- | --- |
| `taintpy` | interprocedural engine, unknown calls sanitize (the CLI default) |
| `taintpy-intra` | intraprocedural engine |
| `taintpy-propagate` | interprocedural engine, unknown calls propagate |
| `bandit` | `bandit -f json -r .` |
| `semgrep` | `semgrep scan --config p/python` (change with `--semgrep-config`) |

CodeQL, or anything else that writes SARIF, is scored from a file you
produce yourself:

```bash
codeql database create db --language=python --source-root PROJECT
codeql database analyze db codeql/python-queries --format=sarif-latest --output=codeql.sarif
python bench/run_bench.py my_dataset.json --tools taintpy --sarif codeql=codeql.sarif
```

Results go to `bench/results/<dataset>.json` (every case, every detection,
tool versions, exact commands, files each tool scanned) and a Markdown table
next to it.

## Ground-truth format

```json
{
  "name": "my dataset",
  "projects": [
    {
      "name": "projectA",
      "root": "path/to/projectA",
      "cases": [
        {"id": "CVE-2023-0001", "file": "pkg/views.py", "lines": [120, 134], "cwe": 78},
        {"id": "decoy-1", "file": "pkg/util.py", "function": "Runner.safe_call",
         "vulnerable": false}
      ]
    }
  ]
}
```

- `root` is relative to the ground-truth file. Each tool scans that
  directory.
- `file` is relative to `root`.
- A case gives either `lines` (inclusive) or `function`. A function label,
  `"Cls.method"` or `"func"`, is turned into that function's line range by
  parsing the file, so it survives edits elsewhere in the file.
- `cwe` is optional. It is only used with `--match-category`.
- `vulnerable` defaults to true. Set it to false for a labeled safe region,
  which is how false positives are measured.

To use a published dataset, write a short script that converts its labels
into this format. Keep that script in the repository next to the converted
file, so the conversion is reviewable too.

## How scoring works

A detection counts for a case when it is in the same file and its line falls
inside the case's range.

| outcome | meaning |
| --- | --- |
| TP | a vulnerable case with at least one detection inside it |
| FN | a vulnerable case with none |
| FP | a safe case with at least one detection inside it |
| TN | a safe case with none |
| unlabeled | a detection in a labeled file but outside every labeled region |

Recall is TP / (TP + FN). The false positive rate is FP / (FP + TN).
Unlabeled detections are reported but not called false positives, because
nobody has checked them. On real projects many will be noise and some may be
real bugs nobody labeled.

Decisions worth knowing when you report results:

- **Location, not category, by default.** Tools name categories differently.
  Bandit's subprocess checks report CWE-78 whether or not input is involved, and taintpy has its own
  category names. Requiring categories to match mostly measures naming. Pass
  `--match-category` to require the detection's CWE to equal the case's CWE,
  and report both numbers if they differ.
- **Range size matters.** A whole-function range is easier to hit than a
  one-line range. Use the same labeling rule for every case and say which
  one you used.
- **Where taintpy reports.** taintpy reports at the sink, and its path
  includes the source. If a dataset labels the line where input enters
  rather than where it is used, ranges need to cover both, or the source
  location in the JSON report needs to be scored instead.
- **Coverage is checked.** The report records how many files each tool
  scanned, and the harness warns when a tool scanned fewer `.py` files than
  the project contains. This exists because Semgrep, by default, skips any
  path under `tests/` and any file git does not track. The harness copies
  each project to a temporary directory with an empty `.semgrepignore` so
  that does not happen silently. taintpy reports files it could not parse,
  usually Python 2 code, in its own JSON.
