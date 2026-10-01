# taintpy

A small **taint-tracking static analyzer** for Python that finds injection
vulnerabilities — command injection, code injection, and path traversal — by
tracing whether attacker-controllable data can reach a dangerous operation.

Unlike a simple linter that just flags "you called `os.system`", taintpy tracks
**data flow**: it only reports a sink when *tainted* data actually reaches it.
That's what keeps false positives low and makes findings worth acting on.

> Built as a security-research learning project. Use it only on code you own or
> are authorized to analyze.

## Install

No runtime dependencies. Python 3.9+.

```bash
git clone <your-repo-url>
cd taintpy
pip install -e .          # gives you the `taintpy` command
# or just run it in place:
python -m taintpy --help
```

## Usage

```bash
# scan a file (intraprocedural: within-function flows only)
taintpy path/to/file.py

# scan a whole project
taintpy path/to/project/

# follow taint ACROSS functions, methods and files (finds real-world bugs)
taintpy --interproc path/to/project/

# machine-readable output, only HIGH findings, extra rules for your framework
taintpy --interproc --format json --min-severity HIGH --rules my_rules.json src/
```

Example output:

```
[HIGH] command-injection at app.py:42
    sink: os.system(...)  <-- tainted input: 'ping ' + host
```

Exit code is non-zero when findings exist, so it drops into CI easily.
Suppress a known-safe line with a trailing `# taintpy: ignore` comment.

### Custom rules

`--rules FILE` merges a JSON file into the built-in rule set. Every key is
optional:

```json
{
  "sources":        ["bottle.request.query.get"],
  "source_objects": ["bottle.request.params"],
  "sinks":          {"db.raw_query": ["sql-injection", "HIGH"]},
  "propagators":    ["my_template.render"],
  "sanitizers":     ["my_escape"]
}
```

Names match by dotted-name *suffix*, so `request.args.get` also matches
`flask.request.args.get`.

## How it works

Four stages, one per concept:

1. **Parse** — `ast.parse` turns source into an Abstract Syntax Tree.
2. **Sources & sinks** (`rules.py`) — a data-driven list of where untrusted
   input enters (`input()`, `request.args.get(...)`, `sys.argv`,
   `parse_args()`, ...) and which operations are dangerous (`os.system`,
   `eval`, `open`, `subprocess.*`, `pickle.loads`, ...).
3. **Taint tracking** (`analyzer.py`) — walking statements in order, we keep a
   set of tainted names. Assignment from tainted data taints the target;
   taint propagates through string building (`+`, f-strings, `.format`,
   `.join`, `.strip().lower()`, `os.path.join`), tuple unpacking, container
   stores, comprehensions and ternaries; assignment from clean data clears it.
   At an `if`/`try`/loop the branches are analyzed separately and the results
   **unioned**, so taint from any path survives.
4. **Report** — when a sink receives a tainted argument (positional or
   keyword), we emit a finding with file, line, severity, and the tainted
   expression.

It encodes real security semantics, not just patterns — e.g. `subprocess.run`
with an argument **list** and no `shell=True` is the safe form and is *not*
flagged, `shell=True` with tainted input is escalated to HIGH, and
`yaml.load(..., Loader=SafeLoader)` is left alone.

Unknown function calls are assumed to **sanitize** (their result is clean).
That keeps false positives down at the cost of missing taint that flows through
helpers the tool doesn't know — which is exactly what `--interproc` fixes for
helpers defined in the code being scanned.

### Interprocedural mode (`--interproc`)

Real bugs usually span functions: input arrives in one function and reaches a
sink in another. To follow that, `interprocedural.py` computes a **summary** of
each function — *does it return tainted data?* *which parameters flow to the
return?* and *which parameters reach a sink inside it?* — by seeding one
parameter as tainted and watching the engine. It repeats until the summaries
stabilize (a fixpoint), then does a final pass where every call site knows what
the callee does. That's how it catches a `source -> helper -> helper -> sink`
chain across three functions.

Summaries are keyed by qualified name (`helper`, `Cls.method`) and shared
across **every file in the scan**, so `helpers.run(x)`, `self.method(x)` and
`obj.method(x)` all resolve, including across modules. Keyword arguments are
mapped to parameters by name.

**Tool hit != vulnerability.** A finding is a *data flow*, not proof of a bug.
Whether it's exploitable depends on whether that input is really
attacker-controlled — human triage the tool can't do for you.

## Validation

```bash
python tests/test_analyzer.py     # no dependencies
pytest                            # if installed
```

The suite covers:

- `tests/vulnerable_example.py` — 7 planted bugs, all must be caught.
- `tests/safe_example.py` — safe patterns, none may be flagged.
- `tests/interproc_example.py` — 2 cross-function bugs only `--interproc` sees.
- `tests/fake_app/` — a fake Flask file-share app and admin CLI with 21 planted
  bugs (`# BUG` / `# INTERPROC`) and 11 decoys (`# SAFE`). The test reads
  those markers and checks for exact agreement: no misses, no extras.
- `tests/multifile/` — taint entering in one module and hitting a sink in
  another, through a method call.
- Unit tests for each propagation rule, branch merging, suppression comments,
  JSON output and rule files.

## Known limitations

- **Calls are resolved by name, not by type.** `obj.method(x)` matches every
  function named `method` in the scan; same-named definitions share one
  summary (their effects are unioned). This favors recall over precision.
- **`*args` / `**kwargs` are not modeled** in summaries.
- **Flow-insensitive within a path.** Taint is a set of names; there is no
  path condition, so `if is_safe(x): sink(x)` is still reported.
- **Container stores are coarse.** `d[k] = tainted` taints all of `d`;
  `obj.attr = tainted` is tracked per attribute.
- **Sanitizers are an allowlist.** Unknown calls are assumed to clean data.
  A custom validator that merely checks and returns its input will hide the
  flow; add it to `propagators` in a rules file to follow it.
- **No dynamic dispatch, decorators, globals, or closures.** Taint does not
  flow through module globals or captured variables.

## Responsible use

This tool exists to help find and fix bugs. Only analyze code you own or have
explicit permission to test, and follow coordinated disclosure if you find a
real vulnerability in someone else's project.
