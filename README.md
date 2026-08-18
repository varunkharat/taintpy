# taintpy

A minimal **taint-tracking static analyzer** for Python that finds injection
vulnerabilities — command injection, code injection, and path traversal — by
tracing whether attacker-controllable data can reach a dangerous operation.

Unlike a simple linter that just flags "you called `os.system`", taintpy tracks
**data flow**: it only reports a sink when *tainted* data actually reaches it.
That's what keeps false positives low and makes findings worth acting on.

> Built as a security-research learning project. Use it only on code you own or
> are authorized to analyze.

## Install

No dependencies beyond Python 3.9+. Just clone and run.

```bash
git clone <your-repo-url>
cd taintpy
```

## Usage

```bash
# scan a file (intraprocedural: within-function flows only)
python -m taintpy path/to/file.py

# scan a whole project
python -m taintpy path/to/project/

# follow taint ACROSS function boundaries (finds real-world bugs)
python -m taintpy --interproc path/to/project/
```

Example output:

```
[HIGH] command-injection at app.py:42
    sink: os.system(...)  <-- tainted input: 'ping ' + host
```

Exit code is non-zero when findings exist, so it drops into CI easily.

## How it works

Four stages, one per concept:

1. **Parse** — `ast.parse` turns source into an Abstract Syntax Tree.
2. **Sources & sinks** (`rules.py`) — a data-driven list of where untrusted
   input enters (`input()`, `request.args.get(...)`, `sys.argv`, ...) and which
   operations are dangerous (`os.system`, `eval`, `open`, `subprocess.*`, ...).
3. **Taint tracking** (`analyzer.py`) — walking statements in order, we keep a
   set of tainted variables. Assignment from tainted data taints the target;
   taint propagates through string building (`+`, f-strings, `.format`,
   `os.path.join`); assignment from clean data clears it.
4. **Report** — when a sink receives a tainted argument, we emit a finding with
   file, line, severity, and the tainted expression.

It encodes real security semantics, not just patterns — e.g. `subprocess.run`
with an argument **list** and no `shell=True` is the safe form and is *not*
flagged, while `shell=True` with tainted input is escalated to HIGH.

### Interprocedural mode (`--interproc`)

Real bugs usually span functions: input arrives in one function and reaches a
sink in another. To follow that, `interprocedural.py` computes a **summary** of
each function — *does it return tainted data?* and *do any of its parameters
reach a sink inside it?* — by seeding one parameter as tainted and watching the
engine. It repeats until the summaries stabilize (a fixpoint), then does a final
pass where every call site knows what the callee does. That's how it catches a
`source -> helper -> helper -> sink` chain across three functions.

**Tool hit != vulnerability.** A finding is a *data flow*, not proof of a bug.
Whether it's exploitable depends on whether that input is really
attacker-controlled — human triage the tool can't do for you.

## Validation

```bash
python tests/test_analyzer.py
```

`tests/vulnerable_example.py` contains 7 planted bugs (all must be caught);
`tests/safe_example.py` contains safe patterns (none may be flagged).

## Known limitations (a.k.a. the v2 roadmap)

Being explicit about these is part of doing this honestly:

- **Cross-function tracking is name-based** — the `--interproc` engine matches
  callees by simple function name, so same-named functions collide and calls
  through `self.method(...)` or attributes aren't resolved yet.
- **No `*args`/`**kwargs` or keyword-arg mapping** — only positional parameters
  are modeled in summaries.
- **Branches aren't merged precisely** — taint added inside an `if` persists
  after it. This favors recall over precision.
- **No alias/container tracking** — taint through dict/list elements or object
  attributes is only partially modeled.
- **Sanitizer awareness is coarse** — unknown function calls are assumed to
  sanitize. A real sanitizer allowlist would improve precision.

## Responsible use

This tool exists to help find and fix bugs. Only analyze code you own or have
explicit permission to test, and follow coordinated disclosure if you find a
real vulnerability in someone else's project.
