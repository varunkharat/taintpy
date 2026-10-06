# taintpy

[![tests](https://github.com/varunkharat/taintpy/actions/workflows/test.yml/badge.svg)](https://github.com/varunkharat/taintpy/actions/workflows/test.yml)

**Try it in your browser, nothing to install:** <https://varunkharat.github.io/taintpy/>

A taint-tracking static analyzer for Python. It looks for injection bugs:
command injection, SQL injection, code injection, unsafe deserialization,
path traversal, server-side request forgery, template injection and a few
others.

## What taint tracking is

Most injection bugs have the same shape. Data the attacker controls enters
the program somewhere (a **source**: `input()`, `sys.argv`, a web request
parameter, a network response). It moves through variables, string
building and function calls. Eventually it reaches an operation that does
something dangerous with it (a **sink**: `os.system`, `cursor.execute`,
`open`, `pickle.loads`, `eval`). Along the way it may pass through a
**sanitizer** that makes it safe, such as `shlex.quote` or `int()`.

A taint tracker marks data from sources as *tainted*, follows that mark
through the program, and reports a sink only when tainted data actually
reaches it. That is different from a pattern scanner such as Bandit, which
flags `os.system(cmd)` wherever it appears, whether or not `cmd` can contain
attacker data. Following the data is what lets a taint tracker stay quiet on
`os.system("ls")` and still catch `os.system(cmd)` when `cmd` came from a
request three function calls earlier.

taintpy does this statically: it reads the source code and never runs it.

## Install

Python 3.9 or newer. The analyzer itself has no dependencies.

```bash
git clone https://github.com/varunkharat/taintpy.git
cd taintpy
pip install -e .            # installs the `taintpy` command
taintpy --help
```

Without installing, `python -m taintpy --help` works from the repo root.

## Quick start

`examples/02_cross_function.py` reads a name in one function, builds a
command in a second, and runs it in a third:

```python
def read_name():
    return input("name: ")

def build(name):
    return "id " + name.strip()

def run(cmd):
    os.system(cmd)

def main():
    run(build(read_name()))
```

```
$ taintpy examples/02_cross_function.py
[HIGH] command-injection at examples/02_cross_function.py:19  (confidence: high)
    sink: os.system(...)  <-- tainted input: cmd
    note: reached through run() called at examples/02_cross_function.py:23
    path:
          11  source    input()
          11  return    returned
          23  return    returned by read_name()
          23  call      passed to build() as name
          14  param     parameter name of build()
          15  return    returned
          23  return    returned by build()
          23  call      passed to run() as cmd
          18  param     parameter cmd of run()
          19  sink      os.system()

--- 1 finding(s) in 1 file(s), engine=interproc ---
```

The finding is reported at the sink, line 19. The path starts at the real
source, line 11, and lists every step in between. The `examples/` folder has
four more short programs, each showing one thing the analyzer follows.

## Usage

```bash
taintpy path/to/file.py                      # one file
taintpy path/to/project/                     # every .py file under a directory
taintpy --format json -o report.json src/    # machine-readable report
taintpy --format sarif -o report.sarif src/  # for GitHub code scanning and other SARIF viewers
```

| Option | Meaning |
| --- | --- |
| `--engine interproc` | Follow taint across functions, methods, classes and modules. The default. |
| `--engine intra` | Stay inside each function. Faster, finds less. `--interproc` is kept as an alias for the default. |
| `--format text\|json\|sarif` | Output format. |
| `-o FILE` | Write the report to a file. |
| `--rules FILE` | Load extra sources, sinks, propagators and sanitizers from JSON. Repeatable. |
| `--unknown-calls sanitize\|propagate` | What a call taintpy has no rule or summary for does to taint. See below. |
| `--min-severity HIGH\|MEDIUM\|LOW` | Hide findings below a severity. |
| `--min-confidence high\|medium\|low` | Hide findings below a confidence level. |

The exit code is 1 when there are findings and 0 when there are none, so the
command works as a CI gate. Put `# taintpy: ignore` on a sink line to
suppress a finding you have reviewed.

### What a finding contains

Each finding has the sink location, the category and severity, the tainted
expression at the sink, the source location, the full path, a confidence
level, and a plain-language explanation of the risk with a suggested fix. The JSON report also records the taintpy version, the
engine and options used, the rule files loaded, how many files were scanned,
and every file that was skipped and why. Files that fail to parse, which in
older projects usually means Python 2 code, are listed rather than silently
dropped.

**Confidence** says how sure taintpy is about the calls on the path:

- **high**: every call on the path was resolved through a definition,
  import, `self`, `super()`, or a local variable assigned from a
  constructor.
- **medium**: some call `obj.method()` could not be resolved that way, and
  exactly one method in the program has that name, so taintpy assumed it was
  that one. Also used for calls passed through by `--unknown-calls propagate`.
- **low**: as above, but several methods share the name. taintpy follows all
  of them and says so in the path.

### Unknown calls

When taint goes into a call that taintpy has no rule and no summary for,
say a function from a third-party library, it has to guess what comes out.
The default, `sanitize`, assumes the result is clean. That keeps false
positives down and loses real flows through libraries it does not know.
`propagate` assumes the result is tainted if any argument or the receiver
was. It finds more and reports more that is not real. Those findings are
marked medium confidence so they can be told apart.

### Custom rules

`--rules FILE` merges a JSON file into the built-in rules. Every key is
optional:

```json
{
  "sources":        ["bottle.request.query.get"],
  "source_objects": ["bottle.request.params"],
  "sinks": {
    "db.raw_query": ["sql-injection", "HIGH"],
    "db.query":     {"category": "sql-injection", "severity": "HIGH",
                     "args": [0], "keywords": ["sql"]}
  },
  "receiver_sinks":       {"mypath.dump": ["path-traversal", "LOW"]},
  "propagators":          ["my_template.render"],
  "receiver_propagators": ["fetch_one"],
  "sanitizers":           ["my_escape"]
}
```

Names match by dotted suffix on a dot boundary, so `request.args.get` also
matches `flask.request.args.get` and `self.request.args.get`. `args` and
`keywords` limit which arguments of a sink count, which is how a
parameterized SQL call avoids being flagged.

## Web interface

A web page lets you paste code, switch between the two engines, and see each
finding's path highlighted on the code: the source in amber, every step in
blue, the sink in red. Each finding also says in plain language what an
attacker could do and how to fix it.

There are two ways to run the same page.

**In the browser, with nothing installed.** The online version linked at the
top runs the analyzer itself inside the browser using
[Pyodide](https://pyodide.org), a build of Python for WebAssembly. The page
loads the same `.py` files the command line uses, and pasted code never
leaves your machine. The site is the `docs/` folder, built by
`python tools/build_site.py` and served by GitHub Pages. A test fails if
`docs/` falls out of date with the source.

**On your own machine, with a small server:**

```bash
pip install -e ".[web]"     # adds FastAPI and uvicorn; the analyzer itself still needs nothing
taintpy-web                 # serves http://127.0.0.1:8000
```

The server listens on this machine only unless you pass `--host`. Pasted
code is parsed, never run. The page calls one endpoint, `POST /api/analyze`,
which returns the same finding objects as the JSON report, so the
highlighting reads line numbers from the path data directly. Both versions
call the same function, `taintpy/service.py`.

## What it looks for

| Category | Example sinks |
| --- | --- |
| command-injection | `os.system`, `os.popen`, `os.exec*`, `subprocess.*` with `shell=True` or a tainted program name, `["sh", "-c", ...]` |
| code-injection | `eval`, `exec`, `compile`, `importlib.import_module` |
| deserialization | `pickle.loads`, `yaml.load` without a safe loader, `marshal`, `dill`, `jsonpickle`, `torch.load`, `numpy.load(allow_pickle=True)` |
| sql-injection | `cursor.execute` and friends (first argument only), Django `raw`/`extra`/`RawSQL`, `pandas.read_sql` |
| path-traversal | `open`, `os.remove`, `shutil.*`, `send_file`, `FileResponse`, `Path(...).read_text()` and similar |
| ssrf | `requests.*`, `httpx.*`, `urlopen` (URL argument only) |
| template-injection | `render_template_string`, `jinja2.Template`, `Environment.from_string` |
| xss | `Markup`, `mark_safe`, `HTMLResponse` |
| xxe | `lxml.etree.fromstring`, `parse`, `XML` |
| ldap-injection | `search_s` filter argument |
| open-redirect | `redirect`, `HttpResponseRedirect`, `RedirectResponse` |

Sources include `input()`, `sys.argv`, `os.environ`, `getpass`, stdin,
argparse results, socket reads, HTTP client responses, Flask, Django,
Starlette, FastAPI and aiohttp request accessors, and the parameters of
functions decorated as web routes (`@app.route("/...")`, `@router.get("/...")`).
The full lists are in `taintpy/rules.py`.

## How it works

1. **Parse.** Python's `ast` module turns each file into a syntax tree.
2. **Model the program.** `program.py` records every module, class and
   function and resolves what each name refers to, following imports.
3. **Track taint in one function.** `analyzer.py` walks the statements in
   order. It keeps a map from each tainted variable to its trace, the steps
   from the source. Taint passes through assignment, string building,
   containers, comprehensions and known library calls. An `if`, loop or `try`
   runs each branch separately and keeps taint from any of them.
4. **Summarize functions.** `interprocedural.py` describes each function by
   what it does with tainted input: does it return a source, which
   parameters reach its return value, which reach a sink, and which get
   stored on `self` or in a global. A call site uses the callee's summary
   instead of re-reading the callee. Summaries depend on each other, so the
   program is re-analyzed until they stop changing.
5. **Report.** A finding is a source and a sink connected by a path.

[DESIGN.md](DESIGN.md) explains each design decision, what the alternatives
were, and what they would have cost.

**A finding is a data flow, not a confirmed vulnerability.** Whether it is
exploitable depends on things taintpy cannot see: whether the source is
really attacker-controlled in deployment, and whether a check it does not
understand already makes the input safe. For example, running taintpy on its
own code reports that the `--rules` and `-o` paths from the command line
reach `open()`. That flow is real, but the person running the tool chooses
those paths, so it is not a vulnerability. Both lines carry a
`# taintpy: ignore` comment.

## Validation

```bash
pip install -e ".[dev,web]"    # web is only needed for tests/test_web.py, which skips otherwise
pytest
```

The test suite has:

- unit tests for each propagation rule, sink rule, source and output format;
- interprocedural tests for call resolution, imports across files and
  packages, instance attributes, globals, `*args`/`**kwargs` and recursion;
- marker-driven fixtures (`tests/fake_app/`, `tests/multifile/`) where every
  `# BUG` and `# INTERPROC` line must be reported and nothing else may be;
- `tests/test_limitations.py`, one test per known limitation below, each
  marked as an expected failure. If a change fixes a limitation, that test
  starts passing and the suite fails until the test and this README are
  updated together.

The fixtures were written by the author of the analyzer, so passing them
shows the tool does what it was built to do. It does not measure accuracy on
code nobody wrote for it. No accuracy figures are claimed here until a
measurement on an external benchmark can be rerun from this repository.

`bench/` holds the harness for that measurement. It runs taintpy, Bandit,
Semgrep, and any tool that writes SARIF (such as CodeQL) on labeled code, and
scores each one by recall and false positive rate. See
[bench/README.md](bench/README.md) for the label format and scoring rules.

## Known limitations

Every item below is checked by a test in `tests/test_limitations.py` or
follows from the design.

- **No path sensitivity.** A check such as `if x.isalnum():` before the sink
  is not understood, so the flow is still reported.
- **Sanitizers are not context-aware.** `html.escape` cleans data for every
  sink, including `os.system`, where it does nothing useful.
- **Unknown calls clean taint by default.** A library function not in the
  rules ends the trail. `--unknown-calls propagate` trades this for more
  false positives.
- **Limited type inference.** `obj.method()` is resolved only through
  `self`, `super()`, imports, or a local assigned from a constructor in the
  same function. Otherwise taintpy matches by method name and lowers the
  confidence. Methods with the names of common builtin methods (`get`,
  `split`, `read` and so on) are never matched by name.
- **No dispatch to subclass overrides.** `self.run()` inside a base class
  resolves to the base class's `run`, never a subclass's.
- **Instance attributes and module globals are flow-insensitive.** If any
  method writes tainted data to `self.cmd`, every read of `self.cmd` on that
  class is tainted, even a read before the write or after it is overwritten.
  An attribute written in a subclass is not seen by reads in the base class.
  Globals are tracked only by the interprocedural engine.
- **Closures and lambdas are not followed.** A nested function does not see
  its enclosing function's variables, and lambda bodies are not analyzed.
- **Decorators are ignored.** A call to a decorated function is analyzed as
  a call to the undecorated body.
- **Containers are coarse.** Storing tainted data under one key of a dict
  taints the whole dict. An argument list held in a variable and passed to
  `subprocess.run` is treated as tainted if any element is.
- **One path per variable.** When a variable could be tainted two ways,
  taintpy keeps the shorter trace, so a finding shows one path, not all of
  them.
- **One summary per function.** Summaries do not depend on the caller, so a
  function behaves the same at every call site.
- **Only scanned code is analyzed.** Calls into installed libraries are
  handled by rules only. Frameworks other than Flask, Django, Starlette,
  FastAPI and aiohttp need rules added for their sources.
- **Name-suffix rule matching.** A user variable named `request` will match
  the web request rules, and any method called `execute` counts as an SQL
  sink.
- **Python 3 only.** Files that do not parse as the running Python version's
  syntax are skipped and listed in the report.

## Built with

taintpy is written in Python. The analyzer uses only the Python standard
library, mainly the `ast` module, which parses Python source into a syntax
tree. Everything else is optional:

| Tool | Used for | Needed by |
| --- | --- | --- |
| [FastAPI](https://fastapi.tiangolo.com), [Uvicorn](https://www.uvicorn.org), [Pydantic](https://docs.pydantic.dev) | the local web server | `taintpy-web` only (`web` extra) |
| [Pyodide](https://pyodide.org) | running the analyzer in the browser | the online version only, loaded from the jsDelivr CDN |
| [pytest](https://pytest.org), [HTTPX](https://www.python-httpx.org) | running the tests | development only (`dev` extra) |
| [Bandit](https://github.com/PyCQA/bandit), [Semgrep](https://semgrep.dev), [CodeQL](https://codeql.github.com) | tools taintpy is compared against | `bench/` only, installed separately |
| [GitHub Actions](https://github.com/features/actions), [GitHub Pages](https://pages.github.com) | running tests on every push, hosting the online version | the repository |

The web page is hand-written HTML, CSS and JavaScript with no framework.

## Responsible use

Only analyze code you own or have permission to test. If you find a real
vulnerability in someone else's project, report it privately to the
maintainers and give them time to fix it before publishing anything.

## License

MIT. See [LICENSE](LICENSE).
