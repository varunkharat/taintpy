"""Follow taint across function, method, class and module boundaries.

Each function gets a SUMMARY that answers four questions:

  returns_source   if I am called, is my return value tainted by a source
                   inside me? (stored as the trace inside me)
  param_to_return  which parameters, if tainted, flow to my return value?
  param_to_sink    which parameters, if tainted, reach a sink inside me?
  param_to_store   which parameters, if tainted, get written to an instance
                   attribute or a module global?

A summary is computed with the same engine as everything else: seed exactly
one parameter as tainted, turn built-in sources off so any taint that shows
up can only have come from that parameter, and watch what happens. The trace
recorded inside the callee is kept in the summary, so a finding that crosses
a call shows the steps on both sides of it.

Summaries depend on other summaries, so the whole program is re-analyzed
until nothing changes (a fixpoint). Facts are only ever added, never
removed, so this terminates. The findings from the last round, the one where
nothing changed, are the result.

Two pieces of state are shared across the program rather than kept per
function, and both are flow-insensitive: taint on instance attributes, keyed
by (class, attribute), and taint on module globals, keyed by (module, name).
If any method anywhere writes tainted data to ``self.cmd``, every read of
``self.cmd`` on that class is tainted, regardless of order.

Why summaries instead of re-analyzing the callee at every call site
(inlining)? Inlining gives more precise, call-site-specific answers but its
cost grows with every level of call depth and it needs a special case for
recursion. Summaries cost one analysis per parameter per round and handle
recursion through the fixpoint. The price is context-insensitivity: one
summary serves every caller.
"""

import ast
from collections import namedtuple

from . import rules
from .analyzer import Analyzer, State, Step
from .program import ClassInfo, FuncInfo, GlobalRef, Program, import_aliases

MAX_ROUNDS = 25

# How a call site maps onto a callee. ``how`` is extra text for the trace,
# set when the target was chosen by method name alone.
Target = namedtuple("Target", "func summary binding confidence how")


class Summary:
    def __init__(self, func):
        self.func = func
        self.returns_source = None      # trace, or None
        self.param_to_return = {}       # param -> trace inside the callee
        self.param_to_sink = {}         # param -> {location key: Finding}
        self.param_to_store = {}        # param -> {store target: trace}

    def snapshot(self):
        """What the fixpoint compares. Traces are left out on purpose: two
        rounds can find different but equally valid paths, and that must not
        count as a change."""
        return (
            self.returns_source is not None,
            frozenset(self.param_to_return),
            frozenset((p, k) for p, sinks in self.param_to_sink.items() for k in sinks),
            frozenset((p, w) for p, stores in self.param_to_store.items() for w in stores),
        )


class Context:
    def __init__(self, program, unknown_calls="sanitize"):
        self.program = program
        self.unknown_calls = unknown_calls
        self.summaries = {f.key: Summary(f) for f in program.functions}
        self.classes = {c.key: c for c in program.classes}
        self.attrs = {}        # (class key, attr) -> trace
        self.globals = {}      # (module key, name) -> trace
        self.aliases = {m.key: import_aliases(m.tree) for m in program.modules}
        self.rounds = 0
        self.converged = False
        self.findings = []
        self._static = {}
        # Methods with these names are almost always called on builtin types
        # (``d.get``, ``s.split``, ``f.read``). Guessing a user method of the
        # same name for them adds noise and no recall, so the name-only
        # fallback skips them and the built-in rule applies.
        self._builtin_method_names = {
            name.rsplit(".", 1)[-1]
            for table in (rules.PROPAGATOR_SUFFIXES, rules.RECEIVER_PROPAGATOR_SUFFIXES,
                          rules.SANITIZER_SUFFIXES)
            for name in table}

    # --- called by the analyzer ------------------------------------------

    def resolve_call(self, call, analyzer, state):
        """Return (targets, user_code). ``user_code`` is True when the call
        definitely goes to code in the scanned program, in which case the
        built-in rules for that name do not apply."""
        func = call.func
        fi, mod = analyzer.func, analyzer.module
        prog = self.program

        if isinstance(func, ast.Attribute):
            base = func.value
            if isinstance(base, ast.Name):
                if base.id in ("self", "cls") and fi is not None and fi.class_info:
                    m = prog.lookup_method(fi.class_info, func.attr)
                    if m is not None:
                        return [self._target(m, call)], True
                    # Possibly defined in a subclass or a mixin we cannot see.
                    return self._fallback(call, func.attr), False
                classes = state.types.get(base.id)
                if classes:
                    found = [prog.lookup_method(self.classes[c], func.attr) for c in sorted(classes)]
                    return [self._target(m, call) for m in found if m is not None], True
            elif (isinstance(base, ast.Call) and isinstance(base.func, ast.Name)
                  and base.func.id == "super" and fi is not None and fi.class_info):
                for parent in prog.mro(fi.class_info)[1:]:
                    if func.attr in parent.methods:
                        return [self._target(parent.methods[func.attr], call)], True
                return [], False

        cache_key = (id(call), fi.key if fi else mod.key)
        cached = self._static.get(cache_key)
        if cached is None:
            cached = self._resolve_static(call, fi, mod)
            self._static[cache_key] = cached
        func_info, skip, user_code, fallback_name = cached
        if func_info is not None:
            return [self._target(func_info, call, skip)], True
        if fallback_name is not None:
            return self._fallback(call, fallback_name), False
        return [], user_code

    def _resolve_static(self, call, fi, mod):
        """Resolution that does not depend on local variable types, cached
        per call node. Returns (FuncInfo or None, args to skip, user_code,
        method name to fall back on)."""
        prog = self.program
        func = call.func
        ref = prog.resolve_expr(func, fi, mod)
        if isinstance(ref, FuncInfo):
            skip = 0
            if (ref.class_info is not None and not ref.is_static
                    and not ref.is_classmethod and isinstance(func, ast.Attribute)
                    and isinstance(prog.resolve_expr(func.value, fi, mod), ClassInfo)):
                skip = 1     # ``Cls.method(obj, x)``: the first argument is self
            return ref, skip, True, None
        if isinstance(ref, ClassInfo):
            init = prog.lookup_method(ref, "__init__")
            return init, 0, True, None
        if ref is not None:
            return None, 0, False, None
        if not isinstance(func, ast.Attribute):
            return None, 0, False, None
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and (
                root.id in mod.imports or prog.resolve_name(root.id, fi, mod) is not None):
            # Rooted in an import or a known def: an external library call
            # (``requests.get``) or a missing attribute. Not a guess-able method.
            return None, 0, False, None
        return None, 0, False, func.attr

    def _target(self, func_info, call, skip=0, confidence="high", how=""):
        return Target(func_info, self.summaries[func_info.key],
                      func_info.signature.bind(call, skip), confidence, how)

    def _fallback(self, call, name):
        if name.startswith("__") or name in self._builtin_method_names:
            return []
        candidates = self.program.methods_by_name.get(name, [])
        if not candidates:
            return []
        if len(candidates) == 1:
            confidence = "medium"
            how = " (matched by method name only)"
        else:
            confidence = "low"
            names = ", ".join(sorted(c.display for c in candidates))
            how = f" (ambiguous: matched by method name to {names})"
        return [self._target(c, call, 0, confidence, how) for c in candidates]

    def class_of_call(self, call, analyzer):
        ref = self.program.resolve_expr(call.func, analyzer.func, analyzer.module)
        return frozenset([ref.key]) if isinstance(ref, ClassInfo) else frozenset()

    def attr_trace(self, class_key, attr):
        cls = self.classes.get(class_key)
        if cls is None:
            return None
        for c in self.program.mro(cls):
            trace = self.attrs.get((c.key, attr))
            if trace is not None:
                return trace
        return None

    def global_trace(self, analyzer, name):
        fi, mod = analyzer.func, analyzer.module
        if fi is not None and name in fi.local_names:
            return None
        ref = self.program.resolve_name(name, fi, mod)
        if isinstance(ref, GlobalRef):
            return self.globals.get((ref.module.key, ref.name))
        if ref is None:
            return self.globals.get((mod.key, name))
        return None

    def store(self, where, trace):
        kind, owner, name = where
        table = self.attrs if kind == "attr" else self.globals
        table.setdefault((owner, name), trace)

    def line_text(self, filename, lineno):
        mod = self.program.by_file.get(filename)
        if mod is None or not 0 < lineno <= len(mod.lines):
            return ""
        return mod.lines[lineno - 1]

    # --- the fixpoint ----------------------------------------------------

    def _analyzer(self, mod, fi, enable_sources):
        return Analyzer(mod.filename, mod.lines, context=self, module=mod, func=fi,
                        enable_sources=enable_sources, unknown_calls=self.unknown_calls,
                        aliases=self.aliases[mod.key])

    def _snapshot(self):
        return ({k: s.snapshot() for k, s in self.summaries.items()},
                frozenset(self.attrs), frozenset(self.globals))

    def run(self):
        for self.rounds in range(1, MAX_ROUNDS + 1):
            before = self._snapshot()
            found = {}

            for mod in self.program.modules:
                a = self._analyzer(mod, None, True)
                state = State()
                a.process_body(mod.tree.body, state)
                for name, trace in state.taint.items():
                    if "." not in name:
                        self.store(("global", mod.key, name), trace)
                _collect(found, a.findings)

            for fi in self.program.functions:
                s = self.summaries[fi.key]
                a = self._analyzer(fi.module, fi, True)
                a.process_body(fi.node.body, a.entry_state(fi.node))
                _collect(found, a.findings)
                if a.return_trace is not None and s.returns_source is None:
                    s.returns_source = a.return_trace

                for p in fi.signature.all_params():
                    a = self._analyzer(fi.module, fi, False)
                    seed = (Step(fi.filename, fi.node.lineno, "param",
                                 f"parameter {p} of {fi.display}()"),)
                    a.process_body(fi.node.body, State({p: seed}))
                    if a.return_trace is not None:
                        s.param_to_return.setdefault(p, a.return_trace)
                    for f in a.findings:
                        s.param_to_sink.setdefault(p, {}).setdefault(f.location_key(), f)
                    for where, trace in a.stores:
                        s.param_to_store.setdefault(p, {}).setdefault(where, trace)

            self.findings = list(found.values())
            if self._snapshot() == before:
                self.converged = True
                break
        return self.findings


def _collect(found, findings):
    for f in findings:
        old = found.get(f.key())
        if old is None or len(f.path) < len(old.path):
            found[f.key()] = f


def analyze_program(sources, unknown_calls="sanitize"):
    """Analyze several modules as one program and return the Context, which
    carries the findings plus how many rounds the fixpoint took."""
    ctx = Context(Program(sources), unknown_calls)
    ctx.run()
    return ctx


def analyze_sources_interprocedural(sources, unknown_calls="sanitize"):
    return analyze_program(sources, unknown_calls).findings


def analyze_module_interprocedural(code, filename="<unknown>", unknown_calls="sanitize"):
    return analyze_sources_interprocedural([(filename, code)], unknown_calls)


def analyze_file_interprocedural(path, unknown_calls="sanitize"):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_module_interprocedural(f.read(), filename=path,
                                              unknown_calls=unknown_calls)


def analyze_files_interprocedural(paths, unknown_calls="sanitize"):
    sources = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            sources.append((path, f.read()))
    return analyze_sources_interprocedural(sources, unknown_calls)
