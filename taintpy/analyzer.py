"""analyzer.py — the engine: parse code, track taint, flag sinks.

The engine walks statements in order and keeps a set of tainted variable
names. Expressions are classified as tainted or clean by ``expr_is_tainted``;
every call in a statement is checked against the sink rules by
``check_sinks_in_expr``.

Interprocedural support (see interprocedural.py) plugs in through *function
summaries*. When the engine sees a call to a user-defined function whose
summary says "I return tainted data", the call result is tainted; when a
tainted argument is passed into a parameter the summary says reaches a sink,
a finding is recorded at the call site. The same engine, with a couple of
flags flipped, is what *computes* those summaries.
"""

import ast

from . import rules
from .rules import name_matches

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# A sink line carrying one of these comments is not reported.
SUPPRESS_MARKERS = ("taintpy: ignore", "noqa: taintpy")


class Finding:
    def __init__(self, filename, lineno, sink, category, severity, tainted_arg,
                 note=""):
        self.filename = filename
        self.lineno = lineno
        self.sink = sink
        self.category = category
        self.severity = severity
        self.tainted_arg = tainted_arg
        self.note = note

    def key(self):
        return (self.filename, self.lineno, self.sink, self.category)

    def to_dict(self):
        return {
            "file": self.filename,
            "line": self.lineno,
            "severity": self.severity,
            "category": self.category,
            "sink": self.sink,
            "tainted_input": self.tainted_arg,
            "note": self.note,
        }

    def __str__(self):
        loc = f"{self.filename}:{self.lineno}"
        line = f"[{self.severity}] {self.category} at {loc}\n"
        line += f"    sink: {self.sink}(...)  <-- tainted input: {self.tainted_arg}"
        if self.note:
            line += f"\n    note: {self.note}"
        return line


def dotted_name(node):
    """Reconstruct a dotted name from a Name/Attribute chain.

    ``os.path.join`` -> "os.path.join". When the chain is rooted in something
    that is not a plain name (a string literal, a call result, a subscript)
    only the attribute part is returned: ``"...".format`` -> "format",
    ``x.strip().lower`` -> "lower". Suffix rules still match that way.
    An expression with no attribute chain at all returns None.
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


class Analyzer:
    def __init__(self, filename="<unknown>", summaries=None, source_lines=None):
        self.filename = filename
        self.findings = []
        # qualified name ("func" or "Class.method") -> Summary
        self.summaries = summaries or {}
        self._short_index = None
        self.source_lines = source_lines or []
        # Set while analyzing a method body so ``self.other()`` resolves.
        self.class_name = None
        # --- knobs used when COMPUTING summaries -------------------------
        # When False, built-in sources and "returns_source" don't fire, so the
        # only taint present is whatever parameter we deliberately seeded.
        self.enable_sources = True
        # When False, we don't recurse into nested def bodies (each function is
        # analyzed once, on its own).
        self.descend_into_defs = True
        # Set True by process_stmt when a `return` returns tainted data.
        self.return_tainted = False

    # --- SOURCE detection ------------------------------------------------

    def is_source(self, node):
        if not self.enable_sources:
            return False
        if isinstance(node, ast.Call):
            if name_matches(dotted_name(node.func), rules.SOURCE_CALL_SUFFIXES):
                return True
        if isinstance(node, ast.Subscript):
            if name_matches(dotted_name(node.value), rules.SOURCE_OBJECT_SUFFIXES):
                return True
        if isinstance(node, ast.Attribute):
            if name_matches(dotted_name(node), rules.SOURCE_OBJECT_SUFFIXES):
                return True
        return False

    # --- summary lookup --------------------------------------------------

    def _resolve_summaries(self, func):
        """Summaries a call's ``func`` expression may refer to."""
        if not self.summaries:
            return []
        if isinstance(func, ast.Name):
            s = self.summaries.get(func.id)
            return [s] if s is not None else []
        if not isinstance(func, ast.Attribute):
            return []
        base = func.value
        if (isinstance(base, ast.Name) and base.id in ("self", "cls")
                and self.class_name):
            s = self.summaries.get(f"{self.class_name}.{func.attr}")
            if s is not None:
                return [s]
        full = dotted_name(func)
        if "." in full and full in self.summaries:     # ``Cls.method(...)``
            return [self.summaries[full]]
        # Otherwise ``helpers.run(x)`` or ``obj.method(x)`` where we can't tell
        # the module/class. Any function with that short name is a candidate.
        if self._short_index is None:
            self._short_index = {}
            for key, summ in self.summaries.items():
                self._short_index.setdefault(key.rsplit(".", 1)[-1], []).append(summ)
        return self._short_index.get(func.attr, [])

    @staticmethod
    def _arg_for_param(call, summary, idx):
        """Expression passed for parameter ``idx`` of ``summary``, or None."""
        if idx < len(call.args):
            a = call.args[idx]
            return None if isinstance(a, ast.Starred) else a
        if idx < len(summary.params):
            pname = summary.params[idx]
            for kw in call.keywords:
                if kw.arg == pname:
                    return kw.value
        return None

    # --- TAINT of an expression -----------------------------------------

    def expr_is_tainted(self, node, tainted):
        if node is None:
            return False
        if self.is_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.BinOp):
            return (self.expr_is_tainted(node.left, tainted)
                    or self.expr_is_tainted(node.right, tainted))
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_tainted(v, tainted) for v in node.values)
        if isinstance(node, ast.IfExp):
            return (self.expr_is_tainted(node.body, tainted)
                    or self.expr_is_tainted(node.orelse, tainted))
        if isinstance(node, ast.JoinedStr):
            return any(self.expr_is_tainted(v, tainted) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, ast.NamedExpr):
            is_tainted = self.expr_is_tainted(node.value, tainted)
            self._assign_taint(node.target, is_tainted, tainted)
            return is_tainted

        if isinstance(node, ast.Call):
            return self._call_is_tainted(node, tainted)

        if isinstance(node, ast.Subscript):
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, ast.Attribute):
            if dotted_name(node) in tainted:          # obj.attr = tainted
                return True
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.expr_is_tainted(e, tainted) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.expr_is_tainted(e, tainted)
                       for e in node.keys + node.values if e is not None)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension_is_tainted(node, [node.elt], tainted)
        if isinstance(node, ast.DictComp):
            return self._comprehension_is_tainted(node, [node.key, node.value], tainted)
        return False

    def _comprehension_is_tainted(self, node, results, tainted):
        inner = set(tainted)
        for gen in node.generators:
            if self.expr_is_tainted(gen.iter, inner):
                self._assign_taint(gen.target, True, inner)
        return any(self.expr_is_tainted(r, inner) for r in results)

    def _call_is_tainted(self, node, tainted):
        fname = dotted_name(node.func)
        # (1) built-in source call
        if self.enable_sources and name_matches(fname, rules.SOURCE_CALL_SUFFIXES):
            return True
        # (2) call to a user function we have a summary for
        summaries = self._resolve_summaries(node.func)
        if summaries:
            for s in summaries:
                if self.enable_sources and s.returns_source:
                    return True
                for i in s.param_to_return:
                    a = self._arg_for_param(node, s, i)
                    if a is not None and self.expr_is_tainted(a, tainted):
                        return True
            return False
        # (3) explicit sanitizer -> clean
        if name_matches(fname, rules.SANITIZER_SUFFIXES):
            return False
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        # (4) known string plumbing that carries taint through
        if name_matches(fname, rules.PROPAGATOR_SUFFIXES):
            if receiver is not None and self.expr_is_tainted(receiver, tainted):
                return True
            return (any(self.expr_is_tainted(a, tainted) for a in node.args)
                    or any(self.expr_is_tainted(k.value, tainted)
                           for k in node.keywords))
        # (5) container/stream accessors: tainted only via their receiver
        if name_matches(fname, rules.RECEIVER_PROPAGATOR_SUFFIXES):
            return receiver is not None and self.expr_is_tainted(receiver, tainted)
        # (6) unknown call -> assume it sanitizes (keeps FPs down)
        return False

    # --- SINK checking ---------------------------------------------------

    def check_sinks_in_expr(self, expr, tainted):
        if expr is None:
            return
        for sub in ast.walk(expr):
            if not isinstance(sub, ast.Call):
                continue

            # (A) built-in / library sink
            match = name_matches(dotted_name(sub.func), set(rules.SINKS.keys()))
            if match is not None:
                self._maybe_flag_builtin_sink(sub, match, tainted)

            # (B) user-function sink: tainted arg reaches a sink *inside* it
            for s in self._resolve_summaries(sub.func):
                for idx, (cat, sev, sink_name) in sorted(s.param_to_sink.items()):
                    a = self._arg_for_param(sub, s, idx)
                    if a is None or not self.expr_is_tainted(a, tainted):
                        continue
                    self._add_finding(Finding(
                        self.filename, sub.lineno,
                        f"{s.name} -> {sink_name}", cat, sev, ast.unparse(a),
                        note=f"tainted arg reaches {sink_name}() inside "
                             f"{s.name}() (cross-function)",
                    ))
                    break

    def _maybe_flag_builtin_sink(self, call, match, tainted):
        category, severity = rules.SINKS[match]

        if match == "yaml.load" and self._yaml_loader_is_safe(call):
            return

        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in call.keywords
        )
        if match.startswith("subprocess") and not shell_true:
            cmd = call.args[0] if call.args else next(
                (kw.value for kw in call.keywords if kw.arg == "args"), None)
            if isinstance(cmd, (ast.List, ast.Tuple)):
                return      # argument list without a shell: the safe form

        candidates = list(call.args) + [
            kw.value for kw in call.keywords
            if kw.arg not in rules.SINK_CONFIG_KEYWORDS]
        tainted_arg = None
        for arg in candidates:
            if self.expr_is_tainted(arg, tainted):
                tainted_arg = ast.unparse(arg)
                break
        if tainted_arg is None:
            return

        note = ""
        if shell_true:
            severity = "HIGH"
            note = "shell=True with tainted input is command injection"

        self._add_finding(Finding(
            self.filename, call.lineno, match, category,
            severity, tainted_arg, note,
        ))

    @staticmethod
    def _yaml_loader_is_safe(call):
        for kw in call.keywords:
            if kw.arg == "Loader":
                name = dotted_name(kw.value)
                return name is not None and \
                    name.rsplit(".", 1)[-1] in rules.SAFE_YAML_LOADERS
        if len(call.args) >= 2:
            name = dotted_name(call.args[1])
            return name is not None and \
                name.rsplit(".", 1)[-1] in rules.SAFE_YAML_LOADERS
        return False

    def _add_finding(self, finding):
        if 0 < finding.lineno <= len(self.source_lines):
            line = self.source_lines[finding.lineno - 1]
            if any(marker in line for marker in SUPPRESS_MARKERS):
                return
        self.findings.append(finding)

    # --- statement processing -------------------------------------------

    def process_body(self, statements, tainted):
        for stmt in statements:
            self.process_stmt(stmt, tainted)

    def _merge_branches(self, tainted, bodies, keep_original=False):
        """Run each body from a copy of ``tainted`` and union the results.

        A variable is tainted afterwards if ANY path could taint it (recall
        over precision). ``keep_original`` is for constructs that may execute
        zero times (loops, try bodies) so the pre-state survives too.
        """
        merged = set(tainted) if keep_original else set()
        for body in bodies:
            branch = set(tainted)
            self.process_body(body, branch)
            merged |= branch
        tainted.clear()
        tainted.update(merged)

    def process_stmt(self, stmt, tainted):
        if isinstance(stmt, ast.Assign):
            self.check_sinks_in_expr(stmt.value, tainted)
            rhs_tainted = self.expr_is_tainted(stmt.value, tainted)
            for target in stmt.targets:
                self._assign_taint(target, rhs_tainted, tainted)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.check_sinks_in_expr(stmt.value, tainted)
                rhs_tainted = self.expr_is_tainted(stmt.value, tainted)
                self._assign_taint(stmt.target, rhs_tainted, tainted)
            return

        if isinstance(stmt, ast.AugAssign):
            self.check_sinks_in_expr(stmt.value, tainted)
            if self.expr_is_tainted(stmt.value, tainted):
                self._assign_taint(stmt.target, True, tainted)
            return

        if isinstance(stmt, ast.Expr):
            self.check_sinks_in_expr(stmt.value, tainted)
            return

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self.check_sinks_in_expr(stmt.value, tainted)
                if self.expr_is_tainted(stmt.value, tainted):
                    self.return_tainted = True
            return

        if isinstance(stmt, (ast.Assert, ast.Raise, ast.Delete)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.check_sinks_in_expr(child, tainted)
            return

        if isinstance(stmt, ast.If):
            self.check_sinks_in_expr(stmt.test, tainted)
            self._merge_branches(tainted, [stmt.body, stmt.orelse])
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.check_sinks_in_expr(stmt.iter, tainted)
            if self.expr_is_tainted(stmt.iter, tainted):
                self._assign_taint(stmt.target, True, tainted)
            self._merge_branches(tainted, [stmt.body], keep_original=True)
            self.process_body(stmt.orelse, tainted)
            return

        if isinstance(stmt, ast.While):
            self.check_sinks_in_expr(stmt.test, tainted)
            self._merge_branches(tainted, [stmt.body], keep_original=True)
            self.process_body(stmt.orelse, tainted)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.check_sinks_in_expr(item.context_expr, tainted)
                if item.optional_vars is not None:
                    self._assign_taint(
                        item.optional_vars,
                        self.expr_is_tainted(item.context_expr, tainted),
                        tainted)
            self.process_body(stmt.body, tainted)
            return

        if isinstance(stmt, ast.Try) or (
                hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
            after_body = set(tainted)
            self.process_body(stmt.body, after_body)
            # A handler may run after any prefix of the body: start it from
            # everything that could be tainted by then.
            handler_start = tainted | after_body
            merged = set(after_body)
            for handler in stmt.handlers:
                branch = set(handler_start)
                if handler.name:
                    branch.discard(handler.name)
                self.process_body(handler.body, branch)
                merged |= branch
            tainted.clear()
            tainted.update(merged)
            self.process_body(stmt.orelse, tainted)
            self.process_body(stmt.finalbody, tainted)
            return

        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            self.check_sinks_in_expr(stmt.subject, tainted)
            subject_tainted = self.expr_is_tainted(stmt.subject, tainted)
            bodies = []
            for case in stmt.cases:
                if subject_tainted:
                    for n in ast.walk(case.pattern):
                        if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
                            tainted.add(n.name)
                bodies.append(case.body)
            self._merge_branches(tainted, bodies, keep_original=True)
            return

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if self.descend_into_defs:
                self.process_body(stmt.body, set())
            return

        if isinstance(stmt, ast.ClassDef):
            if self.descend_into_defs:
                self.process_body(stmt.body, set())
            return

    def _assign_taint(self, target, is_tainted, tainted):
        if isinstance(target, ast.Name):
            if is_tainted:
                tainted.add(target.id)
            else:
                tainted.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_taint(elt, is_tainted, tainted)
        elif isinstance(target, ast.Starred):
            self._assign_taint(target.value, is_tainted, tainted)
        elif isinstance(target, ast.Attribute):
            # ``obj.attr = x`` tracks the exact attribute path.
            key = dotted_name(target)
            if key is None:
                return
            if is_tainted:
                tainted.add(key)
            else:
                tainted.discard(key)
        elif isinstance(target, ast.Subscript):
            # ``d[k] = tainted`` taints the whole container; a clean store does
            # not clear it because other slots may still hold tainted data.
            base = root_name(target)
            if is_tainted and base is not None:
                tainted.add(base)

    # --- entry point -----------------------------------------------------

    def analyze_module(self, tree):
        self.process_body(tree.body, set())
        return self.findings


def analyze_source(code, filename="<unknown>"):
    """Intraprocedural-only analysis of one module's source text."""
    tree = ast.parse(code, filename=filename)
    return Analyzer(filename, source_lines=code.splitlines()).analyze_module(tree)


def analyze_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_source(f.read(), filename=path)
