"""interprocedural.py — follow taint ACROSS function boundaries.

Instead of re-analyzing a function every time it's called, we compute a
one-time SUMMARY of each function that answers three questions:

  * returns_source : if I'm called, is my return value tainted (because of a
                     source inside me)?
  * param_to_return: which of my parameters, if tainted, flow to my return?
  * param_to_sink  : which of my parameters, if tainted, reach a dangerous sink
                     inside me? (this is the dangerous one)

We compute these by reusing the same engine: seed exactly one parameter as
tainted, run the body, and see whether a sink fired or the return came out
tainted. Because a function can call another function, we repeat the whole
process until the summaries stop changing (a "fixpoint").

Then we do one final pass over the code. Now, at every call site, we know what
the called function does — so we can flag a tainted argument flowing into a
sink two (or more) functions away.

Functions are keyed by qualified name: ``helper`` for module-level functions,
``Cls.method`` for methods. Call sites resolve ``helper(...)``,
``module.helper(...)``, ``self.method(...)`` and ``obj.method(...)``. All files
in one scan share a single summary table, so a helper imported from another
module is followed too. Same-named definitions share one summary (their
effects are unioned), which favors recall over precision.
"""

import ast

from .analyzer import Analyzer, SEVERITY_ORDER

MAX_ROUNDS = 20   # safety cap; real convergence is usually 2-3 rounds


class Summary:
    def __init__(self, name, params):
        self.name = name
        self.params = params                 # parameter names (no self/cls)
        self.returns_source = False          # bool
        self.param_to_return = set()         # {param_index, ...}
        self.param_to_sink = {}              # {param_index: (cat, sev, sink)}

    def snapshot(self):
        """Hashable view, used to detect when the fixpoint has stabilized."""
        return (
            self.returns_source,
            frozenset(self.param_to_return),
            frozenset(self.param_to_sink.items()),
        )

    def record_sink(self, idx, finding):
        """Keep the most severe sink a parameter can reach."""
        prev = self.param_to_sink.get(idx)
        if prev is None or (SEVERITY_ORDER.get(finding.severity, 9)
                            < SEVERITY_ORDER.get(prev[1], 9)):
            self.param_to_sink[idx] = (finding.category, finding.severity,
                                       finding.sink)


class FuncDef:
    """One function/method definition plus where it lives."""

    def __init__(self, node, filename, source_lines, class_name):
        self.node = node
        self.filename = filename
        self.source_lines = source_lines
        self.class_name = class_name

    @property
    def key(self):
        if self.class_name:
            return f"{self.class_name}.{self.node.name}"
        return self.node.name

    def params(self):
        """Ordered positional parameter names, minus self/cls on methods.

        ``*args``/``**kwargs`` are not modeled.
        """
        a = self.node.args
        names = [p.arg for p in (a.posonlyargs + a.args)]
        is_static = any(
            (isinstance(d, ast.Name) and d.id == "staticmethod")
            for d in self.node.decorator_list)
        if self.class_name and names and not is_static:
            names = names[1:]
        return names


def collect_functions(tree, filename, source_lines, into=None):
    """Map qualified name -> [FuncDef, ...] for every def in ``tree``."""
    funcs = {} if into is None else into

    class Collector(ast.NodeVisitor):
        def __init__(self):
            self.scope = []     # class name, or None inside a function

        def visit_ClassDef(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_FunctionDef(self, node):
            cls = self.scope[-1] if self.scope else None
            fd = FuncDef(node, filename, source_lines, cls)
            funcs.setdefault(fd.key, []).append(fd)
            self.scope.append(None)      # nested defs are plain functions
            self.generic_visit(node)
            self.scope.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

    Collector().visit(tree)
    return funcs


def _analyzer_for(fd, summaries, enable_sources):
    a = Analyzer(fd.filename, summaries=summaries, source_lines=fd.source_lines)
    a.enable_sources = enable_sources
    a.descend_into_defs = False   # analyze THIS function only
    a.class_name = fd.class_name
    return a


def compute_summaries(funcs):
    summaries = {key: Summary(key, defs[0].params())
                 for key, defs in funcs.items()}

    # Iterate to a fixpoint. Summaries only ever grow, so this terminates.
    for _ in range(MAX_ROUNDS):
        before = {n: s.snapshot() for n, s in summaries.items()}

        for key, defs in funcs.items():
            s = summaries[key]
            for fd in defs:
                # returns_source: sources ON, no params seeded.
                a = _analyzer_for(fd, summaries, enable_sources=True)
                a.process_body(fd.node.body, set())
                if a.return_tainted:
                    s.returns_source = True

                # param effects: sources OFF, seed one param at a time, so any
                # sink/return taint is attributable purely to that parameter.
                for i, pname in enumerate(s.params):
                    a = _analyzer_for(fd, summaries, enable_sources=False)
                    a.process_body(fd.node.body, {pname})
                    if a.return_tainted:
                        s.param_to_return.add(i)
                    for f in a.findings:
                        s.record_sink(i, f)

        after = {n: s.snapshot() for n, s in summaries.items()}
        if after == before:
            break

    return summaries


def analyze_sources_interprocedural(sources):
    """Analyze several modules together.

    ``sources`` is an iterable of ``(filename, code)`` pairs. Summaries are
    shared across all of them, so cross-module helper calls resolve.
    """
    modules = []
    funcs = {}
    for filename, code in sources:
        tree = ast.parse(code, filename=filename)
        lines = code.splitlines()
        modules.append((filename, tree, lines))
        collect_functions(tree, filename, lines, into=funcs)

    summaries = compute_summaries(funcs)

    # Final pass: module top-level + each function body ONCE, with summaries
    # active so call sites resolve. Params are untainted here; cross-function
    # findings come from call sites passing tainted args.
    findings = []
    for filename, tree, lines in modules:
        mod = Analyzer(filename, summaries=summaries, source_lines=lines)
        mod.descend_into_defs = False
        mod.process_body(tree.body, set())
        findings.extend(mod.findings)

    for defs in funcs.values():
        for fd in defs:
            a = _analyzer_for(fd, summaries, enable_sources=True)
            a.process_body(fd.node.body, set())
            findings.extend(a.findings)

    # De-duplicate (a call site can be reached from multiple passes).
    seen, unique = set(), []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            unique.append(f)
    return unique


def analyze_module_interprocedural(code, filename="<unknown>"):
    return analyze_sources_interprocedural([(filename, code)])


def analyze_file_interprocedural(path):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_module_interprocedural(f.read(), filename=path)


def analyze_files_interprocedural(paths):
    """Analyze many files as one program (shared summaries)."""
    sources = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            sources.append((path, f.read()))
    return analyze_sources_interprocedural(sources)
