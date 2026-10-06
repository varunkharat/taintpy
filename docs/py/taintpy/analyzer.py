"""The taint engine: walk a function or module body and track which names
hold attacker-controlled data, and how they got it.

State is a mapping from a name (``x``, or an attribute path like
``self.cmd``) to a *trace*: the tuple of steps from a source to the current
value. A name that is not in the mapping is clean. Recording the trace
costs little over recording a bare name, and it is what lets a finding say
where the data came from instead of only where it ended up.

The same engine runs in two modes. On its own (``analyze_source``) it is
intraprocedural: calls to the program's own functions are treated like any
unknown call. With a ``context`` from interprocedural.py it asks the context
what a call resolves to and uses that function's summary.
"""

import ast
from collections import namedtuple

from . import rules
from .program import canonical_name, import_aliases
from .rules import name_matches

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}

# A sink line carrying one of these comments is not reported.
SUPPRESS_MARKERS = ("taintpy: ignore", "noqa: taintpy")

# Loops and recursion can grow a trace without bound. Past this length we keep
# the first and last steps, which are the ones a reader needs.
MAX_TRACE = 60
# A loop body is re-run until the set of tainted names stops changing, so
# taint that is carried from one iteration to the next is not missed.
# Each run can only add names, so this is a safety cap.
LOOP_ROUNDS = 10

UNKNOWN_CALL_POLICIES = ("sanitize", "propagate")


Step = namedtuple("Step", "file line kind detail confidence")
Step.__new__.__defaults__ = ("high",)


def extend(*parts):
    """Concatenate traces and steps, dropping immediate repeats."""
    out = []
    for part in parts:
        if not part:
            continue
        # Step is itself a namedtuple, so check for it before treating the
        # part as a trace.
        for item in ((part,) if isinstance(part, Step) else part):
            if not out or out[-1] != item:
                out.append(item)
    if len(out) > MAX_TRACE:
        half = MAX_TRACE // 2
        gap = Step(out[half].file, out[half].line, "elided",
                   f"{len(out) - MAX_TRACE} steps omitted")
        out = out[:half] + [gap] + out[-(MAX_TRACE - half - 1):]
    return tuple(out)


class Finding:
    def __init__(self, filename, lineno, sink, category, severity, tainted_arg,
                 path, note=""):
        self.filename = filename
        self.lineno = lineno
        self.sink = sink
        self.category = category
        self.severity = severity
        self.tainted_arg = tainted_arg
        self.path = tuple(path)
        self.note = note

    @property
    def source(self):
        return self.path[0] if self.path else None

    @property
    def source_file(self):
        return self.source.file if self.source else self.filename

    @property
    def source_line(self):
        return self.source.line if self.source else self.lineno

    @property
    def confidence(self):
        worst = "high"
        for step in self.path:
            if CONFIDENCE_ORDER.get(step.confidence, 0) > CONFIDENCE_ORDER[worst]:
                worst = step.confidence
        return worst

    def location_key(self):
        return (self.filename, self.lineno, self.sink, self.category)

    def key(self):
        # One finding per (source, sink) pair: two different inputs reaching
        # the same sink are reported separately.
        return self.location_key() + (self.source_file, self.source_line)

    def to_dict(self):
        explanation, fix = rules.CATEGORY_HELP.get(self.category, ("", ""))
        return {
            "file": self.filename,
            "line": self.lineno,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "sink": self.sink,
            "tainted_input": self.tainted_arg,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "path": [{"file": s.file, "line": s.line, "kind": s.kind,
                      "detail": s.detail, "confidence": s.confidence}
                     for s in self.path],
            "note": self.note,
            "explanation": explanation,
            "fix": fix,
        }

    def __str__(self):
        head = (f"[{self.severity}] {self.category} at {self.filename}:{self.lineno}"
                f"  (confidence: {self.confidence})")
        lines = [head,
                 f"    sink: {self.sink}(...)  <-- tainted input: {self.tainted_arg}"]
        if self.note:
            lines.append(f"    note: {self.note}")
        if self.path:
            lines.append("    path:")
            for s in self.path:
                where = s.line if s.file == self.filename else f"{s.file}:{s.line}"
                lines.append(f"      {str(where):>6}  {s.kind:<9} {s.detail}")
        return "\n".join(lines)


class State:
    """Taint and known constructor types for the names in one scope."""

    __slots__ = ("taint", "types")

    def __init__(self, taint=None, types=None):
        self.taint = dict(taint or {})
        # name -> frozenset of class keys, for ``s = Store(); s.wipe(x)``.
        self.types = dict(types or {})

    def copy(self):
        return State(self.taint, self.types)

    def absorb(self, other):
        """Union with another branch. On a conflict keep the shorter trace,
        since either one is a real path and the shorter one is easier to read."""
        for name, trace in other.taint.items():
            mine = self.taint.get(name)
            if mine is None or len(trace) < len(mine):
                self.taint[name] = trace
        for name, classes in other.types.items():
            self.types[name] = self.types.get(name, frozenset()) | classes

    def replace_with(self, other):
        self.taint = other.taint
        self.types = other.types

    def signature(self):
        return frozenset(self.taint), frozenset(self.types.items())


def dotted_name(node):
    """Reconstruct a dotted name from a Name/Attribute chain.

    ``os.path.join`` -> "os.path.join". When the chain is rooted in something
    that is not a plain name (a string literal, a call result, a subscript)
    only the attribute part is returned: ``"...".format`` -> "format",
    ``x.strip().lower`` -> "lower". Suffix rules still match that way.
    """
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif not parts:
        return None
    return ".".join(reversed(parts))


def root_name(node):
    """The variable at the base of an Attribute/Subscript chain, or None."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def short(node, limit=60):
    text = ast.unparse(node)
    return text if len(text) <= limit else text[:limit - 3] + "..."


class Analyzer:
    def __init__(self, filename="<unknown>", source_lines=None, *, context=None,
                 module=None, func=None, enable_sources=True,
                 unknown_calls="sanitize", aliases=None):
        self.filename = filename
        self.source_lines = source_lines or []
        self.context = context
        self.module = module
        self.func = func
        self.enable_sources = enable_sources
        if unknown_calls not in UNKNOWN_CALL_POLICIES:
            raise ValueError(f"unknown_calls must be one of {UNKNOWN_CALL_POLICIES}")
        self.unknown_calls = unknown_calls
        self.aliases = aliases or {}
        # Intraprocedural mode analyzes nested defs in place. The interprocedural
        # engine analyzes each function on its own and turns this off.
        self.descend_into_defs = context is None
        self._findings = {}
        self.return_trace = None
        # Writes to attributes or globals seen while sources are off. The
        # interprocedural engine turns these into "param flows to store" facts.
        self.stores = []

    @property
    def findings(self):
        return list(self._findings.values())

    def step(self, node, kind, detail, confidence="high"):
        return Step(self.filename, getattr(node, "lineno", 0), kind, detail, confidence)

    # --- name matching ---------------------------------------------------

    def _names(self, func_node):
        written = dotted_name(func_node)
        canon = canonical_name(written, self.aliases)
        return (canon, written) if canon != written else (written,)

    def _match(self, func_node, table, exact=()):
        for name in self._names(func_node):
            hit = name_matches(name, table, exact)
            if hit is not None:
                return hit
        return None

    # --- sources ---------------------------------------------------------

    def source_label(self, node):
        if not self.enable_sources:
            return None
        if isinstance(node, ast.Call):
            if self._match(node.func, rules.SOURCE_CALL_SUFFIXES):
                if self._resolves_to_user_code(node):
                    return None
                return f"{short(node.func)}()"
        elif isinstance(node, ast.Subscript):
            if self._match(node.value, rules.SOURCE_OBJECT_SUFFIXES):
                return short(node)
        elif isinstance(node, ast.Attribute):
            if self._match(node, rules.SOURCE_OBJECT_SUFFIXES):
                return short(node)
        return None

    def entry_state(self, func_node):
        """Initial state for a function body. Route-handler parameters are
        sources; everything else starts clean."""
        state = State()
        if not self.enable_sources or not is_route_handler(func_node):
            return state
        a = func_node.args
        defaults = dict(zip([p.arg for p in a.args][::-1], a.defaults[::-1]))
        defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d})
        for p in a.posonlyargs + a.args + a.kwonlyargs:
            if p.arg in rules.ROUTE_PARAM_SKIP:
                continue
            default = defaults.get(p.arg)
            if isinstance(default, ast.Call) and dotted_name(default.func) in ("Depends", "fastapi.Depends"):
                continue
            state.taint[p.arg] = (Step(self.filename, p.lineno, "source",
                                       f"route parameter {p.arg} of {func_node.name}()"),)
        return state

    # --- call resolution (interprocedural only) --------------------------

    def _targets(self, call, state):
        if self.context is None:
            return [], False
        return self.context.resolve_call(call, self, state)

    def _resolves_to_user_code(self, call):
        if self.context is None:
            return False
        return self.context.resolve_call(call, self, State())[1]

    # --- taint of an expression ------------------------------------------

    def taint_of(self, node, state):
        """The trace that makes ``node`` tainted, or None if it is clean."""
        if node is None:
            return None
        label = self.source_label(node)
        if label is not None:
            return (self.step(node, "source", label),)

        if isinstance(node, ast.Name):
            trace = state.taint.get(node.id)
            if trace is None and self.context is not None and self.enable_sources:
                trace = self.context.global_trace(self, node.id)
                if trace is not None:
                    trace = extend(trace, self.step(node, "global", f"read global {node.id}"))
            return trace
        if isinstance(node, ast.BinOp):
            return self._first(state, node.left, node.right)
        if isinstance(node, (ast.BoolOp, ast.JoinedStr)):
            return self._first(state, *node.values)
        if isinstance(node, ast.IfExp):
            return self._first(state, node.body, node.orelse)
        if isinstance(node, (ast.FormattedValue, ast.Await, ast.Starred)):
            return self.taint_of(node.value, state)
        if isinstance(node, ast.NamedExpr):
            trace = self.taint_of(node.value, state)
            self._assign(node.target, trace, state, node)
            return trace
        if isinstance(node, ast.Call):
            return self._call_taint(node, state)
        if isinstance(node, ast.Subscript):
            return self.taint_of(node.value, state)
        if isinstance(node, ast.Attribute):
            key = dotted_name(node)
            if key in state.taint:
                return state.taint[key]
            trace = self._stored_attr_taint(node, state)
            if trace is not None:
                return trace
            return self.taint_of(node.value, state)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._first(state, *node.elts)
        if isinstance(node, ast.Dict):
            return self._first(state, *[e for e in node.keys + node.values if e is not None])
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension_taint(node, [node.elt], state)
        if isinstance(node, ast.DictComp):
            return self._comprehension_taint(node, [node.key, node.value], state)
        return None

    def is_tainted(self, node, state):
        return self.taint_of(node, state) is not None

    def _first(self, state, *nodes):
        for n in nodes:
            trace = self.taint_of(n, state)
            if trace is not None:
                return trace
        return None

    def _comprehension_state(self, node, state):
        inner = state.copy()
        for gen in node.generators:
            trace = self.taint_of(gen.iter, inner)
            self._assign(gen.target, trace, inner, gen.iter)
        return inner

    def _comprehension_taint(self, node, results, state):
        inner = self._comprehension_state(node, state)
        return self._first(inner, *results)

    def _stored_attr_taint(self, node, state):
        """``self.x`` or ``obj.x`` tainted by a write somewhere else in the
        program. Only the interprocedural engine knows about those writes."""
        if self.context is None or not self.enable_sources:
            return None
        if not isinstance(node.value, ast.Name):
            return None
        classes = self._classes_of(node.value.id, state)
        for cls in classes:
            trace = self.context.attr_trace(cls, node.attr)
            if trace is not None:
                return extend(trace, self.step(node, "attribute", f"read {short(node)}"))
        return None

    def _classes_of(self, name, state):
        if name in ("self", "cls") and self.func is not None and self.func.class_info:
            return (self.func.class_info.key,)
        return tuple(sorted(state.types.get(name, ())))

    def _call_taint(self, node, state):
        targets, user_code = self._targets(node, state)
        if targets or user_code:
            for t in targets:
                label = t.func.display
                s = t.summary
                if self.enable_sources and s.returns_source is not None:
                    return extend(s.returns_source,
                                  self.step(node, "return", f"returned by {label}()", t.confidence))
                for pname, inner in s.param_to_return.items():
                    for arg in t.binding.get(pname, ()):
                        trace = self.taint_of(arg, state)
                        if trace is not None:
                            return extend(
                                trace,
                                self.step(node, "call", f"passed to {label}() as {pname}{t.how}", t.confidence),
                                inner,
                                self.step(node, "return", f"returned by {label}()", t.confidence))
            if user_code:
                return None

        if self._match(node.func, rules.SANITIZER_SUFFIXES):
            return None
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if self._match(node.func, rules.PROPAGATOR_SUFFIXES):
            return self._first(state, *([receiver] if receiver is not None else []),
                               *node.args, *[k.value for k in node.keywords])
        if self._match(node.func, rules.RECEIVER_PROPAGATOR_SUFFIXES):
            return self.taint_of(receiver, state) if receiver is not None else None
        if self.unknown_calls == "propagate":
            trace = self._first(state, *([receiver] if receiver is not None else []),
                                *node.args, *[k.value for k in node.keywords])
            if trace is not None:
                return extend(trace, self.step(
                    node, "call", f"assumed to pass through {short(node.func)}()", "medium"))
        return None

    # --- sinks -----------------------------------------------------------

    def check_sinks_in_expr(self, expr, state):
        if expr is not None:
            self._check_calls(expr, state)

    def _check_calls(self, node, state):
        # A hand-rolled walk instead of ast.walk, so comprehension variables are
        # bound while we look at the calls inside the comprehension.
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for gen in node.generators:
                self._check_calls(gen.iter, state)
            inner = self._comprehension_state(node, state)
            for gen in node.generators:
                for cond in gen.ifs:
                    self._check_calls(cond, inner)
            for part in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
                self._check_calls(part, inner)
            return
        if isinstance(node, ast.Call):
            self._check_call(node, state)
        for child in ast.iter_child_nodes(node):
            self._check_calls(child, state)

    def _check_call(self, call, state):
        targets, user_code = self._targets(call, state)
        if not user_code:
            match = self._sink_match(call.func)
            if match is not None:
                self._check_builtin_sink(call, match, state)
            if isinstance(call.func, ast.Attribute) and call.func.attr in rules.RECEIVER_SINKS:
                self._check_receiver_sink(call, state)
        for t in targets:
            self._apply_summary(call, t, state)

    def _sink_match(self, func_node):
        for name in self._names(func_node):
            hit = rules.match_sink(name)
            if hit is not None:
                return hit
        return None

    def _apply_summary(self, call, target, state):
        """A tainted argument flowing into a parameter that reaches a sink, or
        a store, inside the callee."""
        s = target.summary
        label = target.func.display
        for pname, sinks in s.param_to_sink.items():
            for arg in target.binding.get(pname, ()):
                trace = self.taint_of(arg, state)
                if trace is None:
                    continue
                enter = self.step(call, "call", f"passed to {label}() as {pname}{target.how}",
                                  target.confidence)
                if self._suppressed(self.filename, call.lineno):
                    break
                for inner in sinks.values():
                    self._add_finding(Finding(
                        inner.filename, inner.lineno, inner.sink, inner.category,
                        inner.severity, inner.tainted_arg,
                        extend(trace, enter, inner.path),
                        note=_join_notes(f"reached through {label}() called at "
                                         f"{self.filename}:{call.lineno}", inner.note)))
                break
        for pname, stores in s.param_to_store.items():
            for arg in target.binding.get(pname, ()):
                trace = self.taint_of(arg, state)
                if trace is None:
                    continue
                enter = self.step(call, "call", f"passed to {label}() as {pname}{target.how}",
                                  target.confidence)
                for where, inner in stores.items():
                    self._store(where, extend(trace, enter, inner))
                break

    def _check_builtin_sink(self, call, match, state):
        category, severity = rules.SINKS[match]

        if match.startswith("yaml.load") and self._yaml_loader_is_safe(call):
            return
        needed = rules.SINK_REQUIRES_TRUE.get(match)
        if needed and not _keyword_is_true(call, needed):
            return
        safe_flag = rules.SINK_SAFE_IF_TRUE.get(match)
        if safe_flag and _keyword_is_true(call, safe_flag):
            return

        note = ""
        shell_true = _keyword_is_true(call, "shell")
        candidates = None
        if match.startswith("subprocess") and not shell_true:
            cmd = call.args[0] if call.args else next(
                (kw.value for kw in call.keywords if kw.arg == "args"), None)
            if isinstance(cmd, (ast.List, ast.Tuple)):
                if _is_shell_list(cmd):
                    severity = "HIGH"
                    note = "argument list runs a shell with -c"
                    candidates = cmd.elts
                elif cmd.elts:
                    # An argument list without a shell is the safe form, unless
                    # the attacker picks the program itself.
                    candidates = [cmd.elts[0]]
                    note = "tainted program name in an argument list"
                else:
                    return

        if candidates is None:
            candidates = self._sink_arguments(call, match)
        tainted_arg = trace = None
        for arg in candidates:
            trace = self.taint_of(arg, state)
            if trace is not None:
                tainted_arg = short(arg)
                break
        if trace is None:
            return

        if shell_true:
            severity = "HIGH"
            note = "shell=True with tainted input is command injection"

        self._add_finding(Finding(
            self.filename, call.lineno, match, category, severity, tainted_arg,
            extend(trace, self.step(call, "sink", f"{match}()")), note))

    @staticmethod
    def _sink_arguments(call, match):
        spec = rules.SINK_ARGS.get(match)
        if spec is None:
            return list(call.args) + [kw.value for kw in call.keywords
                                      if kw.arg not in rules.SINK_CONFIG_KEYWORDS]
        positions, keywords = spec
        args = [call.args[i] for i in positions
                if i < len(call.args) and not isinstance(call.args[i], ast.Starred)]
        if any(isinstance(a, ast.Starred) for a in call.args):
            args.extend(a.value for a in call.args if isinstance(a, ast.Starred))
        args.extend(kw.value for kw in call.keywords
                    if kw.arg in keywords or kw.arg is None)
        return args

    def _check_receiver_sink(self, call, state):
        trace = self.taint_of(call.func.value, state)
        if trace is None:
            return
        name = call.func.attr
        category, severity = rules.RECEIVER_SINKS[name]
        self._add_finding(Finding(
            self.filename, call.lineno, name, category, severity,
            short(call.func.value),
            extend(trace, self.step(call, "sink", f".{name}() on a tainted path")),
            "receiver is tainted"))

    @staticmethod
    def _yaml_loader_is_safe(call):
        loader = next((kw.value for kw in call.keywords if kw.arg == "Loader"), None)
        if loader is None and len(call.args) >= 2:
            loader = call.args[1]
        if loader is None:
            return False
        name = dotted_name(loader)
        return name is not None and name.rsplit(".", 1)[-1] in rules.SAFE_YAML_LOADERS

    def _line(self, filename, lineno):
        if filename == self.filename:
            lines = self.source_lines
        elif self.context is not None:
            return self.context.line_text(filename, lineno)
        else:
            return ""
        return lines[lineno - 1] if 0 < lineno <= len(lines) else ""

    def _suppressed(self, filename, lineno):
        line = self._line(filename, lineno)
        return any(marker in line for marker in SUPPRESS_MARKERS)

    def _add_finding(self, finding):
        if self._suppressed(finding.filename, finding.lineno):
            return
        key = finding.key()
        old = self._findings.get(key)
        if old is None or len(finding.path) < len(old.path):
            self._findings[key] = finding

    # --- statements ------------------------------------------------------

    def process_body(self, statements, state):
        for stmt in statements:
            self.process_stmt(stmt, state)

    def _merge_branches(self, state, bodies, keep_original=False):
        """Run each body from a copy of ``state`` and union the results.

        A name is tainted afterwards if ANY path could taint it (recall over
        precision). ``keep_original`` is for constructs that may run zero
        times, so the state from before them survives too.
        """
        merged = state.copy() if keep_original else State()
        for body in bodies:
            branch = state.copy()
            self.process_body(body, branch)
            merged.absorb(branch)
        state.replace_with(merged)

    def _loop(self, state, body):
        for _ in range(LOOP_ROUNDS):
            before = state.signature()
            self._merge_branches(state, [body], keep_original=True)
            if state.signature() == before:
                break

    def _evaluate(self, expr, state):
        """Check an expression for sinks and also compute its taint, for the
        side effect: a walrus inside an ``if`` or ``while`` test binds a name."""
        self.check_sinks_in_expr(expr, state)
        self.taint_of(expr, state)

    def process_stmt(self, stmt, state):
        if isinstance(stmt, ast.Assign):
            self.check_sinks_in_expr(stmt.value, state)
            trace = self.taint_of(stmt.value, state)
            classes = self._constructed_classes(stmt.value)
            for target in stmt.targets:
                self._assign(target, trace, state, stmt)
                self._set_type(target, classes, state)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.check_sinks_in_expr(stmt.value, state)
                self._assign(stmt.target, self.taint_of(stmt.value, state), state, stmt)
                self._set_type(stmt.target, self._constructed_classes(stmt.value), state)
            return

        if isinstance(stmt, ast.AugAssign):
            self.check_sinks_in_expr(stmt.value, state)
            trace = self.taint_of(stmt.value, state)
            if trace is not None:
                self._assign(stmt.target, trace, state, stmt)
            return

        if isinstance(stmt, ast.Expr):
            self._evaluate(stmt.value, state)
            return

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self.check_sinks_in_expr(stmt.value, state)
                trace = self.taint_of(stmt.value, state)
                if trace is not None:
                    trace = extend(trace, self.step(stmt, "return", "returned"))
                    if self.return_trace is None or len(trace) < len(self.return_trace):
                        self.return_trace = trace
            return

        if isinstance(stmt, (ast.Assert, ast.Raise, ast.Delete)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.check_sinks_in_expr(child, state)
            return

        if isinstance(stmt, ast.If):
            self._evaluate(stmt.test, state)
            self._merge_branches(state, [stmt.body, stmt.orelse])
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.check_sinks_in_expr(stmt.iter, state)
            trace = self.taint_of(stmt.iter, state)
            if trace is not None:
                self._assign(stmt.target, trace, state, stmt)
            self._loop(state, stmt.body)
            self.process_body(stmt.orelse, state)
            return

        if isinstance(stmt, ast.While):
            self._evaluate(stmt.test, state)
            self._loop(state, stmt.body)
            self.process_body(stmt.orelse, state)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.check_sinks_in_expr(item.context_expr, state)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars,
                                 self.taint_of(item.context_expr, state), state, stmt)
            self.process_body(stmt.body, state)
            return

        if isinstance(stmt, ast.Try) or (
                hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
            after_body = state.copy()
            self.process_body(stmt.body, after_body)
            # A handler may run after any prefix of the body, so it starts from
            # everything that could be tainted by then.
            handler_start = state.copy()
            handler_start.absorb(after_body)
            merged = after_body.copy()
            for handler in stmt.handlers:
                branch = handler_start.copy()
                if handler.name:
                    branch.taint.pop(handler.name, None)
                self.process_body(handler.body, branch)
                merged.absorb(branch)
            state.replace_with(merged)
            self.process_body(stmt.orelse, state)
            self.process_body(stmt.finalbody, state)
            return

        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            self.check_sinks_in_expr(stmt.subject, state)
            trace = self.taint_of(stmt.subject, state)
            bodies = []
            for case in stmt.cases:
                if trace is not None:
                    for n in ast.walk(case.pattern):
                        if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
                            state.taint[n.name] = extend(trace, self.step(case.pattern, "assign", n.name))
                bodies.append(case.body)
            self._merge_branches(state, bodies, keep_original=True)
            return

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if self.descend_into_defs:
                saved = self.return_trace
                self.process_body(stmt.body, self.entry_state(stmt))
                self.return_trace = saved
            return

        if isinstance(stmt, ast.ClassDef):
            if self.descend_into_defs:
                self.process_body(stmt.body, State())
            return

    def _constructed_classes(self, value):
        if self.context is None or not isinstance(value, ast.Call):
            return frozenset()
        return self.context.class_of_call(value, self)

    @staticmethod
    def _set_type(target, classes, state):
        if isinstance(target, ast.Name):
            if classes:
                state.types[target.id] = classes
            else:
                state.types.pop(target.id, None)

    def _assign(self, target, trace, state, at):
        if isinstance(target, ast.Name):
            if trace is None:
                state.taint.pop(target.id, None)
                return
            state.taint[target.id] = extend(trace, self.step(at, "assign", target.id))
            if self.func is not None and target.id in self.func.global_decls:
                self._store(("global", self.func.module.key, target.id),
                            state.taint[target.id])
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, trace, state, at)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, trace, state, at)
        elif isinstance(target, ast.Attribute):
            key = dotted_name(target)
            if key is None:
                return
            if trace is None:
                state.taint.pop(key, None)
                return
            state.taint[key] = extend(trace, self.step(at, "assign", key))
            if isinstance(target.value, ast.Name):
                for cls in self._classes_of(target.value.id, state):
                    self._store(("attr", cls, target.attr), state.taint[key])
        elif isinstance(target, ast.Subscript):
            # ``d[k] = tainted`` taints the whole container. A clean store does
            # not clear it, because other slots may still hold tainted data.
            base = root_name(target)
            if trace is not None and base is not None:
                state.taint[base] = extend(trace, self.step(at, "assign", short(target)))

    def _store(self, where, trace):
        if self.context is None:
            return
        if self.enable_sources:
            self.context.store(where, trace)
        else:
            self.stores.append((where, trace))

    # --- entry point -----------------------------------------------------

    def analyze_module(self, tree):
        if not self.aliases:
            self.aliases = import_aliases(tree)
        self.process_body(tree.body, State())
        return self.findings


def is_route_handler(func_node):
    for d in func_node.decorator_list:
        if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                and d.func.attr in rules.ROUTE_DECORATORS):
            continue
        path = d.args[0] if d.args else next(
            (kw.value for kw in d.keywords if kw.arg in ("rule", "path")), None)
        if isinstance(path, ast.Constant) and isinstance(path.value, str) \
                and path.value.startswith("/"):
            return True
    return False


def _keyword_is_true(call, name):
    return any(kw.arg == name and isinstance(kw.value, ast.Constant)
               and kw.value.value is True for kw in call.keywords)


def _is_shell_list(node):
    consts = [e.value for e in node.elts
              if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    if not node.elts or not isinstance(node.elts[0], ast.Constant):
        return False
    program = str(node.elts[0].value).replace("\\", "/").rsplit("/", 1)[-1]
    return program in rules.SHELL_PROGRAMS and any(c in rules.SHELL_COMMAND_FLAGS for c in consts)


def _join_notes(*notes):
    return "; ".join(n for n in notes if n)


def analyze_source(code, filename="<unknown>", unknown_calls="sanitize"):
    """Intraprocedural analysis of one module's source text."""
    tree = ast.parse(code, filename=filename)
    analyzer = Analyzer(filename, code.splitlines(), unknown_calls=unknown_calls)
    return analyzer.analyze_module(tree)


def analyze_file(path, unknown_calls="sanitize"):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_source(f.read(), filename=path, unknown_calls=unknown_calls)
