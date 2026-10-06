# Design decisions

This document explains why taintpy is built the way it is. For each choice
it gives the alternative and what the alternative would have cost. The code
is the reference for what happens. This is the reference for why.

## 1. Report flows, not patterns

A finding requires a path from a source to a sink. The alternative, flagging
every call to a dangerous function, is what Bandit does. It never misses a
call, but it cannot tell `os.system("ls")` from `os.system(user_input)`, and
it says nothing about where the input came from. The study this tool was
built for asks whether vulnerabilities move into places pattern scanners
cannot follow, so the tool has to follow data, not match calls.

## 2. Walk the syntax tree in statement order

The engine walks each function's statements top to bottom and keeps a map of
tainted names. The standard alternative is to build a control-flow graph,
convert to SSA form (every variable assigned once), and run a dataflow
solver over it. That is more precise around loops, `break`, `continue` and
early returns, and it is what CodeQL and Pysa do.

The tree walk was chosen because each rule is a few lines that map directly
to a kind of Python statement, which makes it possible to explain every
finding by reading the code. What it costs:

- `if`/`else` branches are run separately and their results are unioned.
  Taint from either branch survives. This is a *may* analysis: it reports
  what could happen on some path.
- A loop body is re-run until the set of tainted names stops changing, so
  taint carried from one iteration to the next is caught. A CFG solver gets
  this for free. Here it is a small loop in `Analyzer._loop`, capped at 10
  rounds, and it terminates sooner in practice because each round can only
  add names.
- `break`, `continue` and `return` inside a branch are not modeled. Code
  after an early `return` is analyzed as if it might run. That can only add
  findings, never hide one.

## 3. Unknown calls clean taint by default

When tainted data goes into a call with no rule and no summary, taintpy has
to decide whether the result is tainted. Assuming it is (propagate) catches
flows through libraries taintpy does not know. It also taints the result of
almost every call, such as `len(x)`, `hash(x)` and `db.lookup(x)`, which
floods real projects with findings nobody will read. Assuming it is clean
(sanitize) misses flows through unknown libraries but keeps every finding
tied to something taintpy actually understands.

The default is sanitize, with a large propagator list for the string, path,
container and parsing functions that real code uses. `--unknown-calls
propagate` exists because the right setting depends on the question being
asked. For a study, running both and reporting both is more honest than
picking one. Flows that rely on the propagate assumption are marked medium
confidence.

## 4. A trace per tainted name

The state maps each tainted name to a trace: the steps from the source to
the current value. Before this, the state was a set of names, which could say
*that* a sink was reached but not *how*. The trace costs one tuple per
assignment and lets every finding show its source line and every hop.

When two branches both taint the same name, the merge keeps the shorter
trace. Both are real paths, and the shorter one is easier to check by hand.
The cost is that a finding shows one path, not all of them. Keeping every
path grows exponentially with the number of branches.

## 5. Function summaries instead of inlining

To follow taint into a callee there are two main options.

- **Inlining**: at each call, re-analyze the callee with the caller's actual
  arguments. This is precise, since each call site gets its own answer. Its
  cost multiplies with call depth, and recursion needs a special case to
  avoid looping forever.
- **Summaries**: analyze each function once per parameter and record what
  it does. Call sites look up the summary. This costs one analysis per
  parameter per round, regardless of how many call sites there are.

taintpy uses summaries. A summary records whether the function returns a
source, which parameters flow to the return, which reach a sink, and which
get stored on `self` or in a global. To compute "parameter *p* reaches a
sink", the engine seeds only *p* as tainted and turns built-in sources off.
Any taint that appears can then only have come from *p*. Without turning
sources off, a function that calls `input()` and also takes a parameter
would wrongly be summarized as "parameter reaches sink".

Summaries depend on other summaries, so the whole program is re-analyzed
until no summary changes. This is a fixpoint. It terminates because facts
are only added, never removed, and there are finitely many possible facts.
The findings from the final round, the one where nothing changed, are the
result. A safety cap of 25 rounds exists, and the report says if it was hit.

The cost is context-insensitivity: one summary serves every caller. If
`f(x, mode)` only reaches a sink when `mode == "shell"`, the summary still
says the parameter reaches the sink.

Each summary also stores the trace inside the callee. A finding that crosses
a call shows the caller's steps, the call, and the callee's steps, so the
source line is where the data really came from, even when the source is
inside a function that was called.

## 6. Findings are reported at the sink

An earlier version reported a cross-function finding at the call site. It is
now reported at the sink, with the call site in the path and the note. The
sink is where Bandit and Semgrep report, so a comparison by location lines
up, and it is the line a fix usually changes.

A finding is identified by its source and its sink. Two different inputs
reaching the same `os.system` are two findings. That keeps both paths
visible. Anyone counting vulnerable lines rather than flows should count
distinct sink locations.

## 7. Resolving calls, and saying how sure we are

`program.py` resolves a call in this order:

1. a function or class visible by name: nested definitions, module
   definitions, imports, `from x import *`;
2. `self.m()` and `cls.m()` through the current class and its bases;
3. `super().m()` through the bases;
4. `x.m()` where `x` was assigned from a constructor of a known class in the
   same function;
5. `module.f()` and `Class.m()` through the import graph.

If none of these work and the receiver is not an import, taintpy falls back
to every method in the program with that name. An earlier version did only
this fallback, which produced confident false positives when two classes
shared a method name. The other option, staying silent when the name is
ambiguous, hides real flows and does not tell anyone it did so. The current
rule follows all candidates but marks the finding medium confidence (one
candidate) or low (several), and names the candidates in the path. Nothing
is hidden and nothing is overstated. `--min-confidence` filters on it.

Methods with the names of common builtin methods (`get`, `split`, `read`,
`items` and the rest of the propagator lists) are never matched by name.
In real code `x.get(k)` is almost always a dict, and matching it to a user
`get` method made findings that were nearly always wrong.

When a call resolves with high confidence to code in the scanned program,
the built-in rules for that name are skipped. A user function called
`execute` is analyzed from its body, not treated as an SQL sink.

## 8. Instance attributes and globals are shared and flow-insensitive

Taint on `self.attr` cannot stay inside one function: it is written in
`__init__` and read in another method. taintpy keeps one table for the whole
program keyed by (class, attribute). A write of tainted data from any method
adds an entry. A read on that class or a subclass checks the table. Module
globals work the same way, keyed by (module, name).

Tracking attribute taint per object and in order would need to know which
object each variable points to at each point in the program, which is alias
analysis. That is a large step up in complexity. The table is simple and
catches the common pattern. It can report an attribute read that happens
before the write, or after the attribute was overwritten with a constant.
`tests/test_limitations.py` records that.

## 9. Module names come from `__init__.py` files

A file's module name is found by walking up the directories that contain an
`__init__.py`, the way Python names a module when its top package directory
is on `sys.path`. This does not depend on which directory the scan started
from. Projects without `__init__.py` files, and scripts that import siblings
by short name, are handled by matching an import against the end of a module
name and preferring the module in the importer's own directory.

## 10. Rules match by dotted suffix

Rules are written as dotted names (`request.args.get`) and match any call
whose name ends with that on a dot boundary. This catches `flask.request`,
an imported `request`, and `self.request` with one rule. Import aliases are
resolved first, so `import subprocess as sp; sp.call(...)` matches
`subprocess.call`. A few sinks (`open`, `eval`, `exec`) match only the whole
name, otherwise `webbrowser.open` would count as a file sink.

The cost is that a user variable named `request` matches the web request
rules. Resolving every name to the object it really refers to would need
type information that a static tree walk does not have.

Some sinks only care about one argument. `cursor.execute(sql, params)` is
only dangerous through `sql`, and that is why a parameterized query is not
flagged. `rules.SINK_ARGS` lists those positions.

## 11. Route parameters are sources

Flask URL variables and FastAPI query parameters arrive as function
parameters, not through a `request.*` call. A function is treated as a route
handler when it has a decorator like `@x.route(...)`, `@x.get(...)` or
`@x.post(...)` whose first argument is a string starting with `/`. The `/`
check is what separates `@app.get("/items")` from `@mock.patch("os.system")`.
FastAPI parameters with a `Depends(...)` default are injected objects, not
user data, and are skipped.

## 12. No dependencies

The analyzer uses only the standard library. A security tool that pulls in
packages adds supply-chain risk to every project that installs it, and the
standard `ast` module has everything a source-level analyzer needs. The web
interface is optional and installs its own dependencies through an extra.

## 13. The web interface is a thin layer

The page is one static HTML file with plain JavaScript, served by a small
FastAPI app that has one analysis endpoint. That endpoint calls the same
functions as the CLI and returns the same finding dictionaries as the JSON
report. Keeping it thin means there is one analyzer and one output format to
test and explain, and the page cannot disagree with the command line. There
is no frontend framework or build step, and nothing is loaded from a CDN, so
the page works offline and there is nothing to explain beyond the one file.
