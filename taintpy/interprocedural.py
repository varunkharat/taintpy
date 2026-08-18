"""interprocedural.py — follow taint ACROSS function boundaries.

The idea: instead of re-analyzing a function every time it's called, we compute
a one-time SUMMARY of each function that answers three questions:

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
"""

import ast
from .analyzer import Analyzer, dotted_name


class Summary:
    def __init__(self, name, params):
        self.name = name
        self.params = params                 # list of parameter names
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


def _positional_params(func_node):
    """Ordered positional parameter names (ignores *args/**kwargs for now)."""
    a = func_node.args
    return [p.arg for p in (a.posonlyargs + a.args)]


def collect_functions(tree):
    """Map simple function name -> its ast node (module fns + methods).

    Limitation: names must be unique-ish; same-named functions collide
    (last one wins). Good enough for an MVP; note it in the writeup.
    """
    funcs = {}

    class Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            funcs[node.name] = node
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    Collector().visit(tree)
    return funcs


def _run_body(func_node, seeded, summaries, filename, enable_sources):
    """Run the engine over one function body with `seeded` params tainted.

    Returns (num_findings, return_tainted).
    """
    a = Analyzer(filename, summaries=summaries)
    a.enable_sources = enable_sources
    a.descend_into_defs = False   # analyze THIS function only
    a.process_body(func_node.body, set(seeded))
    return len(a.findings), a.return_tainted


def compute_summaries(tree, filename):
    funcs = collect_functions(tree)
    summaries = {name: Summary(name, _positional_params(node))
                 for name, node in funcs.items()}

    # Iterate to a fixpoint. Summaries only ever grow, so this terminates.
    for _ in range(20):  # safety cap; real convergence is usually 2-3 rounds
        changed = False
        before = {n: s.snapshot() for n, s in summaries.items()}

        for name, node in funcs.items():
            s = summaries[name]

            # returns_source: sources ON, no params seeded.
            _, ret_tainted = _run_body(node, set(), summaries, filename,
                                       enable_sources=True)
            if ret_tainted:
                s.returns_source = True

            # param effects: sources OFF, seed one param at a time, so any
            # sink/return taint is attributable purely to that parameter.
            for i, pname in enumerate(s.params):
                a = Analyzer(filename, summaries=summaries)
                a.enable_sources = False
                a.descend_into_defs = False
                a.process_body(node.body, {pname})
                if a.return_tainted:
                    s.param_to_return.add(i)
                if a.findings:
                    f = max(a.findings, key=lambda x: x.severity)  # HIGH<MEDIUM alpha
                    s.param_to_sink[i] = (f.category, f.severity, f.sink)

        after = {n: s.snapshot() for n, s in summaries.items()}
        if after != before:
            changed = True
        if not changed:
            break

    return summaries, funcs


def analyze_module_interprocedural(code, filename="<unknown>"):
    tree = ast.parse(code, filename=filename)
    summaries, funcs = compute_summaries(tree, filename)

    # Final pass: analyze module top-level + each function body ONCE, with
    # summaries active so call sites resolve. Params are untainted here;
    # cross-function findings come from call sites passing tainted args.
    findings = []

    mod = Analyzer(filename, summaries=summaries)
    mod.descend_into_defs = False
    mod.process_body(tree.body, set())
    findings.extend(mod.findings)

    for node in funcs.values():
        a = Analyzer(filename, summaries=summaries)
        a.descend_into_defs = False
        a.process_body(node.body, set())
        findings.extend(a.findings)

    # De-duplicate (a call site can be reached from multiple passes).
    seen, unique = set(), []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            unique.append(f)
    return unique


def analyze_file_interprocedural(path):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_module_interprocedural(f.read(), filename=path)
