"""A model of the scanned code as one program: modules, classes, functions,
and what each name refers to.

The interprocedural engine uses this to answer "which function does this call
go to?" without running the code. Resolution is static and deliberately
simple:

  * plain names resolve through enclosing functions, module-level defs,
    imports (absolute, relative, aliased, re-exported from ``__init__``),
    and ``from x import *``;
  * ``self.m()`` resolves through the current class and its bases;
  * ``x.m()`` resolves when ``x`` was assigned from a constructor call of a
    class we know (the analyzer tracks that per variable);
  * anything else is unresolved, and the caller decides whether to fall
    back to matching by method name.

There is no type inference beyond the constructor rule, and no modeling of
dynamic dispatch to subclasses.
"""

import ast
import os
from collections import namedtuple

# A module-level variable, as opposed to a def or class: ``config.CMD``.
GlobalRef = namedtuple("GlobalRef", "module name")


class Signature:
    """Parameter names of a function, minus the implicit self/cls."""

    def __init__(self, node, drop_first):
        a = node.args
        positional = [p.arg for p in a.posonlyargs + a.args]
        if drop_first and positional:
            positional = positional[1:]
        self.positional = positional
        self.vararg = a.vararg.arg if a.vararg else None
        self.kwonly = [p.arg for p in a.kwonlyargs]
        self.kwarg = a.kwarg.arg if a.kwarg else None

    def all_params(self):
        names = list(self.positional)
        if self.vararg:
            names.append(self.vararg)
        names.extend(self.kwonly)
        if self.kwarg:
            names.append(self.kwarg)
        return names

    def bind(self, call, skip=0):
        """Map each parameter name to the argument expressions that may fill it.

        A list, not a single expression, because ``*xs`` at the call site may
        fill any remaining positional slot and ``**d`` any keyword slot. We do
        not know their lengths or keys, so they are bound to every slot they
        could reach.
        """
        bound = {}
        args = list(call.args)[skip:]
        pos_index = 0
        for arg in args:
            if isinstance(arg, ast.Starred):
                for name in self.positional[pos_index:]:
                    bound.setdefault(name, []).append(arg.value)
                if self.vararg:
                    bound.setdefault(self.vararg, []).append(arg.value)
                continue
            if pos_index < len(self.positional):
                bound.setdefault(self.positional[pos_index], []).append(arg)
            elif self.vararg:
                bound.setdefault(self.vararg, []).append(arg)
            pos_index += 1
        named = set(self.positional[pos_index:]) | set(self.kwonly)
        for kw in call.keywords:
            if kw.arg is None:
                for name in named:
                    bound.setdefault(name, []).append(kw.value)
                if self.kwarg:
                    bound.setdefault(self.kwarg, []).append(kw.value)
            elif kw.arg in named or kw.arg in self.positional:
                bound.setdefault(kw.arg, []).append(kw.value)
            elif self.kwarg:
                bound.setdefault(self.kwarg, []).append(kw.value)
        return bound


class FuncInfo:
    def __init__(self, node, module, class_info, parent):
        self.node = node
        self.name = node.name
        self.module = module
        self.class_info = class_info          # set for methods
        self.parent = parent                  # enclosing FuncInfo, if nested
        owner = class_info.key if class_info else (parent.key if parent else module.key)
        self.key = f"{owner}.{node.name}"
        decorators = {_decorator_name(d) for d in node.decorator_list}
        self.is_static = "staticmethod" in decorators
        self.is_classmethod = "classmethod" in decorators
        self.signature = Signature(node, drop_first=bool(class_info) and not self.is_static)
        self.nested = {}
        self.local_names, self.global_decls = _scope_names(node)

    @property
    def filename(self):
        return self.module.filename

    @property
    def display(self):
        """Name as a reader would write it inside its module: ``Store.wipe``."""
        return self.key[len(self.module.key) + 1:]


class ClassInfo:
    def __init__(self, node, module, parent):
        self.node = node
        self.name = node.name
        self.module = module
        self.parent = parent
        owner = parent.key if parent else module.key
        self.key = f"{owner}.{node.name}"
        self.methods = {}
        self.base_nodes = list(node.bases)

    @property
    def display(self):
        return self.key[len(self.module.key) + 1:]


class ModuleInfo:
    def __init__(self, filename, code, tree, name):
        self.filename = filename
        self.code = code
        self.lines = code.splitlines()
        self.tree = tree
        self.name = name
        self.key = name                       # made unique by Program if needed
        self.is_package = os.path.basename(filename) == "__init__.py"
        self.defs = {}
        self.imports = {}                     # alias -> ("module", name) | ("symbol", module, name)
        self.star_imports = []

    @property
    def directory(self):
        return os.path.dirname(os.path.abspath(self.filename))


def _decorator_name(node):
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _scope_names(func_node):
    """Names local to a function, and names it declares ``global``.

    Walks the body but stops at nested functions, classes, lambdas and
    comprehensions, since those open their own scope in Python 3.
    """
    local = set(Signature(func_node, drop_first=False).all_params())
    declared_global = set()
    stack = list(func_node.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local.add(node.name)
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp,
                             ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared_global.update(node.names)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            local.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local.add(node.name)
        stack.extend(ast.iter_child_nodes(node))
    return local - declared_global, declared_global


def module_name_for(filename):
    """Dotted module name, found by walking up through ``__init__.py`` dirs.

    This is how Python itself would name the file when its top package
    directory is on sys.path, and it does not depend on where the scan
    started.
    """
    if filename.startswith("<"):
        return filename
    path = os.path.abspath(filename)
    directory, base = os.path.split(path)
    stem = os.path.splitext(base)[0]
    parts = [] if base == "__init__.py" else [stem]
    while os.path.isfile(os.path.join(directory, "__init__.py")):
        parts.insert(0, os.path.basename(directory))
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return ".".join(parts) or stem


def import_aliases(tree):
    """alias -> fully dotted target, for every import in the module.

    Used to canonicalize names before rule matching, so ``import os as o``
    followed by ``o.system(x)`` still matches the ``os.system`` rule.
    Imports inside functions are included too. That is a simplification:
    a later function's local import can shadow a module-level name.
    """
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    root = a.name.split(".")[0]
                    aliases.setdefault(root, root)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            for a in node.names:
                if a.name == "*":
                    continue
                full = f"{base}.{a.name}" if node.module else f"{base}{a.name}"
                aliases[a.asname or a.name] = full
    return aliases


def canonical_name(dotted, aliases):
    if not dotted or not aliases:
        return dotted
    root, _, rest = dotted.partition(".")
    target = aliases.get(root)
    if target is None or target == root:
        return dotted
    return f"{target}.{rest}" if rest else target


class Program:
    def __init__(self, sources):
        """``sources`` is an iterable of ``(filename, code)`` pairs."""
        self.modules = []
        self.functions = []
        self.classes = []
        self.methods_by_name = {}
        self._by_name = {}
        for filename, code in sources:
            tree = ast.parse(code, filename=filename)
            mod = ModuleInfo(filename, code, tree, module_name_for(filename))
            self.modules.append(mod)
            self._by_name.setdefault(mod.name, []).append(mod)
        for name, mods in self._by_name.items():
            if len(mods) > 1:
                # Two scripts called main.py in different folders, for example.
                # Keys must be unique; import lookups still use the plain name.
                for i, mod in enumerate(mods):
                    mod.key = f"{name}@{i}"
        for mod in self.modules:
            self._collect(mod)
        self.by_file = {m.filename: m for m in self.modules}

    # --- building ----------------------------------------------------------

    def _collect(self, mod):
        program = self

        class Collector(ast.NodeVisitor):
            def __init__(self):
                self.cls = None
                self.func = None

            def _register(self, info):
                # A class nested in a class body is not reachable by a bare
                # name, so it is not registered anywhere.
                if self.cls is not None:
                    return
                if self.func is not None:
                    self.func.nested[info.name] = info
                else:
                    mod.defs[info.name] = info

            def visit_ClassDef(self, node):
                info = ClassInfo(node, mod, self.func)
                self._register(info)
                program.classes.append(info)
                saved = self.cls
                self.cls = info
                for stmt in node.body:
                    self.visit(stmt)
                self.cls = saved

            def visit_FunctionDef(self, node):
                info = FuncInfo(node, mod, self.cls, self.func)
                if self.cls is not None:
                    self.cls.methods[node.name] = info
                    program.methods_by_name.setdefault(node.name, []).append(info)
                else:
                    self._register(info)
                program.functions.append(info)
                saved_cls, saved_func = self.cls, self.func
                self.cls, self.func = None, info
                for stmt in node.body:
                    self.visit(stmt)
                self.cls, self.func = saved_cls, saved_func

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Import(self, node):
                for a in node.names:
                    if a.asname:
                        mod.imports[a.asname] = ("module", a.name)
                    else:
                        root = a.name.split(".")[0]
                        mod.imports.setdefault(root, ("module", root))

            def visit_ImportFrom(self, node):
                base = program._absolute(mod, node.module, node.level)
                for a in node.names:
                    if a.name == "*":
                        mod.star_imports.append(base)
                    else:
                        mod.imports[a.asname or a.name] = ("symbol", base, a.name)

        Collector().visit(mod.tree)

    @staticmethod
    def _absolute(mod, name, level):
        if not level:
            return name or ""
        parts = mod.name.split(".")
        if not mod.is_package:
            parts = parts[:-1]
        if level > 1:
            parts = parts[:len(parts) - (level - 1)]
        if name:
            parts.append(name)
        return ".".join(parts)

    # --- lookups -----------------------------------------------------------

    def find_module(self, name, importer=None):
        """The scanned module an import name refers to, or None if external.

        Falls back to suffix matching ("helpers" finds "app.helpers") because
        a project without ``__init__.py`` files, or a script that puts its own
        directory on sys.path, imports modules by their short name. When more
        than one module matches, prefer the one next to the importer, which is
        what sys.path[0] does for scripts.
        """
        if not name:
            return None
        candidates = self._by_name.get(name)
        if not candidates:
            candidates = [m for n, mods in self._by_name.items()
                          if n.endswith("." + name) for m in mods]
        if not candidates:
            return None
        if len(candidates) > 1 and importer is not None:
            near = [m for m in candidates if m.directory == importer.directory]
            if near:
                return near[0]
        return candidates[0]

    def resolve_name(self, name, func, module, depth=0):
        """What a bare name refers to: FuncInfo, ClassInfo, ModuleInfo,
        GlobalRef, or None when it is local, builtin, or external."""
        f = func
        while f is not None:
            if name in f.nested:
                return f.nested[name]
            f = f.parent
        if name in module.defs:
            return module.defs[name]
        imp = module.imports.get(name)
        if imp is not None:
            return self._resolve_import(imp, module, depth)
        for star in module.star_imports:
            target = self.find_module(star, module)
            if target is not None and target is not module and depth < 5:
                found = self.resolve_name(name, None, target, depth + 1)
                if found is not None:
                    return found
        return None

    def _resolve_import(self, imp, importer, depth):
        if depth > 5:          # guards against import cycles between __init__ files
            return None
        if imp[0] == "module":
            return self.find_module(imp[1], importer)
        _, modname, symbol = imp
        target = self.find_module(modname, importer)
        if target is None:
            return self.find_module(f"{modname}.{symbol}" if modname else symbol, importer)
        return self.member(target, symbol, depth + 1)

    def member(self, ref, attr, depth=0):
        if isinstance(ref, ModuleInfo):
            if attr in ref.defs:
                return ref.defs[attr]
            if attr in ref.imports:
                return self._resolve_import(ref.imports[attr], ref, depth + 1)
            sub = self.find_module(f"{ref.name}.{attr}", ref)
            if sub is not None:
                return sub
            return GlobalRef(ref, attr)
        if isinstance(ref, ClassInfo):
            return self.lookup_method(ref, attr)
        return None

    def resolve_expr(self, node, func, module):
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id, func, module)
        if isinstance(node, ast.Attribute):
            base = self.resolve_expr(node.value, func, module)
            if base is None:
                return None
            return self.member(base, node.attr)
        return None

    def bases(self, cls):
        out = []
        for b in cls.base_nodes:
            ref = self.resolve_expr(b, cls.parent, cls.module)
            if isinstance(ref, ClassInfo):
                out.append(ref)
        return out

    def mro(self, cls):
        """The class and its known bases, depth first. Not Python's C3 order,
        which only differs for diamond inheritance."""
        order, stack, seen = [], [cls], set()
        while stack:
            c = stack.pop(0)
            if c.key in seen:
                continue
            seen.add(c.key)
            order.append(c)
            stack[0:0] = self.bases(c)
        return order

    def lookup_method(self, cls, name):
        for c in self.mro(cls):
            if name in c.methods:
                return c.methods[name]
        return None
