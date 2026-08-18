"""analyzer.py — the engine: parse code, track taint, flag sinks.

v0.2 adds *interprocedural* support via function summaries (see
interprocedural.py). The core intraprocedural logic is unchanged; we just teach
it two new tricks:

  * When it sees a call to a user-defined function whose SUMMARY says "I return
    tainted data," the call result is treated as tainted.
  * When a tainted argument is passed into a parameter position that the
    summary says "reaches a sink inside me," we record a finding at the call
    site — a bug that spans two functions.

Flags let the interprocedural driver reuse this same engine to *compute* those
summaries (by seeding a single parameter as tainted and watching what happens).
"""

import ast
from .rules import (
    SINKS,
    SOURCE_CALL_SUFFIXES,
    SOURCE_OBJECT_SUFFIXES,
    PROPAGATOR_SUFFIXES,
    name_matches,
)


class Finding:
    def __init__(self, filename, lineno, sink, category, severity, tainted_arg, note=""):
        self.filename = filename
        self.lineno = lineno
        self.sink = sink
        self.category = category
        self.severity = severity
        self.tainted_arg = tainted_arg
        self.note = note

    def key(self):
        return (self.filename, self.lineno, self.sink, self.category)

    def __str__(self):
        loc = f"{self.filename}:{self.lineno}"
        line = f"[{self.severity}] {self.category} at {loc}\n"
        line += f"    sink: {self.sink}(...)  <-- tainted input: {self.tainted_arg}"
        if self.note:
            line += f"\n    note: {self.note}"
        return line


def dotted_name(node):
    """Reconstruct a dotted name from a Name/Attribute chain, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class Analyzer:
    def __init__(self, filename="<unknown>", summaries=None):
        self.filename = filename
        self.findings = []
        # name -> Summary of every user-defined function we know about.
        self.summaries = summaries or {}
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
            if name_matches(dotted_name(node.func), SOURCE_CALL_SUFFIXES):
                return True
        if isinstance(node, ast.Subscript):
            if name_matches(dotted_name(node.value), SOURCE_OBJECT_SUFFIXES):
                return True
        if isinstance(node, ast.Attribute):
            if name_matches(dotted_name(node), SOURCE_OBJECT_SUFFIXES):
                return True
        return False

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
        if isinstance(node, ast.JoinedStr):
            return any(self.expr_is_tainted(v, tainted) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.expr_is_tainted(node.value, tainted)

        if isinstance(node, ast.Call):
            fname = dotted_name(node.func)
            # (1) built-in source call
            if name_matches(fname, SOURCE_CALL_SUFFIXES):
                return True
            # (2) call to a user function we have a summary for
            if isinstance(node.func, ast.Name) and node.func.id in self.summaries:
                s = self.summaries[node.func.id]
                if self.enable_sources and s.returns_source:
                    return True
                for i in s.param_to_return:
                    if i < len(node.args) and self.expr_is_tainted(node.args[i], tainted):
                        return True
                return False
            # (3) known string plumbing that carries taint through
            if name_matches(fname, PROPAGATOR_SUFFIXES):
                if isinstance(node.func, ast.Attribute) and \
                        self.expr_is_tainted(node.func.value, tainted):
                    return True
                return any(self.expr_is_tainted(a, tainted) for a in node.args)
            # (4) unknown call -> assume it sanitizes (keeps FPs down)
            return False

        if isinstance(node, ast.Subscript):
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, ast.Attribute):
            return self.expr_is_tainted(node.value, tainted)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.expr_is_tainted(e, tainted) for e in node.elts)
        return False

    # --- SINK checking ---------------------------------------------------

    def check_sinks_in_expr(self, expr, tainted):
        for sub in ast.walk(expr):
            if not isinstance(sub, ast.Call):
                continue

            # (A) built-in / library sink
            match = name_matches(dotted_name(sub.func), set(SINKS.keys()))
            if match is not None:
                self._maybe_flag_builtin_sink(sub, match, tainted)

            # (B) user-function sink: tainted arg reaches a sink *inside* it
            if isinstance(sub.func, ast.Name) and sub.func.id in self.summaries:
                s = self.summaries[sub.func.id]
                for idx, (cat, sev, sink_name) in s.param_to_sink.items():
                    if idx < len(sub.args) and \
                            self.expr_is_tainted(sub.args[idx], tainted):
                        self.findings.append(Finding(
                            self.filename, sub.lineno,
                            f"{sub.func.id} -> {sink_name}", cat, sev,
                            ast.unparse(sub.args[idx]),
                            note=f"tainted arg reaches {sink_name}() inside "
                                 f"{sub.func.id}() (cross-function)",
                        ))

    def _maybe_flag_builtin_sink(self, sub, match, tainted):
        category, severity = SINKS[match]
        tainted_arg = None
        for arg in sub.args:
            if self.expr_is_tainted(arg, tainted):
                tainted_arg = ast.unparse(arg)
                break
        if tainted_arg is None:
            return

        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in sub.keywords
        )
        if match.startswith("subprocess"):
            first_is_list = bool(sub.args) and isinstance(
                sub.args[0], (ast.List, ast.Tuple))
            if first_is_list and not shell_true:
                return

        note = ""
        if shell_true:
            severity = "HIGH"
            note = "shell=True with tainted input is command injection"

        self.findings.append(Finding(
            self.filename, sub.lineno, match, category,
            severity, tainted_arg, note,
        ))

    # --- statement processing -------------------------------------------

    def process_body(self, statements, tainted):
        for stmt in statements:
            self.process_stmt(stmt, tainted)

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

        if isinstance(stmt, ast.Return) and stmt.value is not None:
            self.check_sinks_in_expr(stmt.value, tainted)
            if self.expr_is_tainted(stmt.value, tainted):
                self.return_tainted = True
            return

        if isinstance(stmt, ast.If):
            self.check_sinks_in_expr(stmt.test, tainted)
            self.process_body(stmt.body, tainted)
            self.process_body(stmt.orelse, tainted)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.check_sinks_in_expr(stmt.iter, tainted)
            if self.expr_is_tainted(stmt.iter, tainted):
                self._assign_taint(stmt.target, True, tainted)
            self.process_body(stmt.body, tainted)
            self.process_body(stmt.orelse, tainted)
            return

        if isinstance(stmt, ast.While):
            self.check_sinks_in_expr(stmt.test, tainted)
            self.process_body(stmt.body, tainted)
            self.process_body(stmt.orelse, tainted)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.check_sinks_in_expr(item.context_expr, tainted)
            self.process_body(stmt.body, tainted)
            return

        if isinstance(stmt, ast.Try):
            self.process_body(stmt.body, tainted)
            for handler in stmt.handlers:
                self.process_body(handler.body, tainted)
            self.process_body(stmt.orelse, tainted)
            self.process_body(stmt.finalbody, tainted)
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

    # --- entry point -----------------------------------------------------

    def analyze_module(self, tree):
        self.process_body(tree.body, set())
        return self.findings


def analyze_source(code, filename="<unknown>"):
    """Intraprocedural-only convenience wrapper (used by the v1 tests)."""
    tree = ast.parse(code, filename=filename)
    return Analyzer(filename).analyze_module(tree)


def analyze_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return analyze_source(f.read(), filename=path)
