"""Sources, sinks, propagators and sanitizers, kept as plain data.

Adding a rule should be a one-line edit here, or a JSON file passed with
``--rules`` (see ``load_rules``).

  SOURCE     an expression that produces attacker-controllable data.
  SINK       an operation that must not receive that data unchecked.
  PROPAGATOR a call whose result is tainted when its input is.
  SANITIZER  a call whose result is always clean.

Names are matched by dotted suffix on a dot boundary, so the rule
``request.args.get`` matches ``flask.request.args.get`` and
``self.request.args.get`` but not ``myrequest.args.get``.
"""

import json

# --- SOURCES ----------------------------------------------------------------

# Calls whose return value is tainted.
SOURCE_CALL_SUFFIXES = {
    "input",
    "os.getenv",
    "os.environ.get",
    "getpass.getpass",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
    "parse_args",            # argparse: everything on the Namespace is user input
    "parse_known_args",
    # sockets and network responses
    "recv",
    "recvfrom",
    "recv_into",
    "urlopen",
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "httpx.request",
    "getresponse",
    # Flask / Werkzeug
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.files.get",
    "request.get_json",
    "request.get_data",
    "request.args.getlist",
    "request.form.getlist",
    "request.values.getlist",
    # Starlette / FastAPI / aiohttp, where these are awaited methods
    "request.json",
    "request.body",
    "request.form",
    "request.text",
    "request.query_params.get",
    "request.path_params.get",
    # Django
    "request.GET.get",
    "request.POST.get",
    "request.GET.getlist",
    "request.POST.getlist",
    "request.COOKIES.get",
    "request.META.get",
}

# Objects whose attribute or subscript access yields tainted data,
# e.g. sys.argv[1], os.environ["X"], request.args["q"], request.form.
SOURCE_OBJECT_SUFFIXES = {
    "sys.argv",
    "os.environ",
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.query_string",
    "request.query_params",
    "request.path_params",
    "request.match_info",
    "request.query",
    "request.GET",
    "request.POST",
    "request.COOKIES",
    "request.FILES",
    "request.META",
    "request.body",
}

# Decorator method names that register a web route. A function decorated
# with one of these, called with a path string starting with "/", has its
# parameters treated as sources (Flask URL variables, FastAPI query/path
# params). The "/" check is what keeps ``@mock.patch("os.system")`` out.
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "head",
                    "options", "api_route", "websocket"}

# Route-handler parameters with these names are framework objects, not data.
ROUTE_PARAM_SKIP = {"self", "cls", "request", "req", "response", "background_tasks"}

# --- SINKS ------------------------------------------------------------------

# Dotted-name suffix -> (category, base severity).
SINKS = {
    # command execution
    "os.system":               ("command-injection", "HIGH"),
    "os.popen":                ("command-injection", "HIGH"),
    "os.execl":                ("command-injection", "HIGH"),
    "os.execle":               ("command-injection", "HIGH"),
    "os.execlp":               ("command-injection", "HIGH"),
    "os.execv":                ("command-injection", "HIGH"),
    "os.execve":               ("command-injection", "HIGH"),
    "os.execvp":               ("command-injection", "HIGH"),
    "os.execvpe":              ("command-injection", "HIGH"),
    "os.spawnl":               ("command-injection", "HIGH"),
    "os.spawnlp":              ("command-injection", "HIGH"),
    "os.spawnv":               ("command-injection", "HIGH"),
    "os.spawnvp":              ("command-injection", "HIGH"),
    "os.posix_spawn":          ("command-injection", "HIGH"),
    "os.posix_spawnp":         ("command-injection", "HIGH"),
    "pty.spawn":               ("command-injection", "HIGH"),
    "subprocess.run":          ("command-injection", "MEDIUM"),
    "subprocess.call":         ("command-injection", "MEDIUM"),
    "subprocess.check_call":   ("command-injection", "MEDIUM"),
    "subprocess.check_output": ("command-injection", "MEDIUM"),
    "subprocess.Popen":        ("command-injection", "MEDIUM"),
    "subprocess.getoutput":    ("command-injection", "HIGH"),
    "subprocess.getstatusoutput": ("command-injection", "HIGH"),
    "asyncio.create_subprocess_shell": ("command-injection", "HIGH"),
    "asyncio.create_subprocess_exec":  ("command-injection", "MEDIUM"),
    "exec_command":            ("command-injection", "HIGH"),     # paramiko
    # dynamic code execution and unsafe deserialization
    "eval":                    ("code-injection", "HIGH"),
    "exec":                    ("code-injection", "HIGH"),
    "compile":                 ("code-injection", "MEDIUM"),
    "__import__":              ("code-injection", "MEDIUM"),
    "importlib.import_module": ("code-injection", "MEDIUM"),
    "pickle.loads":            ("deserialization", "HIGH"),
    "pickle.load":             ("deserialization", "HIGH"),
    "pickle.Unpickler":        ("deserialization", "HIGH"),
    "cPickle.loads":           ("deserialization", "HIGH"),
    "dill.loads":              ("deserialization", "HIGH"),
    "dill.load":               ("deserialization", "HIGH"),
    "jsonpickle.decode":       ("deserialization", "HIGH"),
    "marshal.loads":           ("deserialization", "HIGH"),
    "marshal.load":            ("deserialization", "HIGH"),
    "shelve.open":             ("deserialization", "MEDIUM"),
    "yaml.load":               ("deserialization", "MEDIUM"),
    "yaml.load_all":           ("deserialization", "MEDIUM"),
    "yaml.unsafe_load":        ("deserialization", "HIGH"),
    "yaml.unsafe_load_all":    ("deserialization", "HIGH"),
    "torch.load":              ("deserialization", "MEDIUM"),
    "numpy.load":              ("deserialization", "MEDIUM"),
    "np.load":                 ("deserialization", "MEDIUM"),
    # SQL
    "execute":                 ("sql-injection", "HIGH"),
    "executemany":             ("sql-injection", "HIGH"),
    "executescript":           ("sql-injection", "HIGH"),
    "objects.raw":             ("sql-injection", "HIGH"),
    "RawSQL":                  ("sql-injection", "HIGH"),
    "extra":                   ("sql-injection", "MEDIUM"),
    "read_sql":                ("sql-injection", "HIGH"),
    "read_sql_query":          ("sql-injection", "HIGH"),
    # LDAP
    "search_s":                ("ldap-injection", "MEDIUM"),
    "search_ext_s":            ("ldap-injection", "MEDIUM"),
    # file access
    "open":                    ("path-traversal", "MEDIUM"),
    "io.open":                 ("path-traversal", "MEDIUM"),
    "codecs.open":             ("path-traversal", "MEDIUM"),
    "builtins.open":           ("path-traversal", "MEDIUM"),
    "os.open":                 ("path-traversal", "MEDIUM"),
    "os.remove":               ("path-traversal", "MEDIUM"),
    "os.unlink":               ("path-traversal", "MEDIUM"),
    "os.rename":               ("path-traversal", "MEDIUM"),
    "os.replace":              ("path-traversal", "MEDIUM"),
    "os.rmdir":                ("path-traversal", "MEDIUM"),
    "os.mkdir":                ("path-traversal", "LOW"),
    "os.makedirs":             ("path-traversal", "LOW"),
    "os.listdir":              ("path-traversal", "LOW"),
    "os.chmod":                ("path-traversal", "MEDIUM"),
    "shutil.copy":             ("path-traversal", "MEDIUM"),
    "shutil.copy2":            ("path-traversal", "MEDIUM"),
    "shutil.copyfile":         ("path-traversal", "MEDIUM"),
    "shutil.copytree":         ("path-traversal", "MEDIUM"),
    "shutil.move":             ("path-traversal", "MEDIUM"),
    "shutil.rmtree":           ("path-traversal", "HIGH"),
    "tarfile.open":            ("path-traversal", "MEDIUM"),
    "zipfile.ZipFile":         ("path-traversal", "MEDIUM"),
    "send_file":               ("path-traversal", "MEDIUM"),
    "send_from_directory":     ("path-traversal", "MEDIUM"),
    "FileResponse":            ("path-traversal", "MEDIUM"),
    "save":                    ("path-traversal", "MEDIUM"),     # werkzeug FileStorage.save
    # server-side request forgery
    "requests.get":            ("ssrf", "MEDIUM"),
    "requests.post":           ("ssrf", "MEDIUM"),
    "requests.put":            ("ssrf", "MEDIUM"),
    "requests.patch":          ("ssrf", "MEDIUM"),
    "requests.delete":         ("ssrf", "MEDIUM"),
    "requests.head":           ("ssrf", "MEDIUM"),
    "requests.request":        ("ssrf", "MEDIUM"),
    "httpx.get":               ("ssrf", "MEDIUM"),
    "httpx.post":              ("ssrf", "MEDIUM"),
    "httpx.request":           ("ssrf", "MEDIUM"),
    "urlopen":                 ("ssrf", "MEDIUM"),
    "urllib.request.Request":  ("ssrf", "MEDIUM"),
    # template injection and XSS
    "render_template_string":  ("template-injection", "HIGH"),
    "jinja2.Template":         ("template-injection", "HIGH"),
    "from_string":             ("template-injection", "HIGH"),
    "mako.template.Template":  ("template-injection", "HIGH"),
    "Markup":                  ("xss", "MEDIUM"),
    "mark_safe":               ("xss", "MEDIUM"),
    "HTMLResponse":            ("xss", "MEDIUM"),
    # XML parsers that resolve entities by default
    "lxml.etree.fromstring":   ("xxe", "MEDIUM"),
    "lxml.etree.parse":        ("xxe", "MEDIUM"),
    "lxml.etree.XML":          ("xxe", "MEDIUM"),
    "etree.fromstring":        ("xxe", "MEDIUM"),
    "etree.XML":               ("xxe", "MEDIUM"),
    # open redirect
    "redirect":                ("open-redirect", "LOW"),
    "flask.redirect":          ("open-redirect", "LOW"),
    "django.shortcuts.redirect": ("open-redirect", "LOW"),
    "HttpResponseRedirect":    ("open-redirect", "LOW"),
    "RedirectResponse":        ("open-redirect", "LOW"),
}

# Sinks that match only on the full dotted name, not as a suffix. Without
# this, the rule "open" would fire on ``webbrowser.open`` and ``zf.open``.
EXACT_SINKS = {"open", "eval", "exec", "compile", "__import__", "redirect"}

# Which arguments of a sink carry the dangerous payload, as
# (positional indexes, keyword names). Sinks not listed here check every
# argument except the config keywords below. The SQL entries are why a
# parameterized query, ``cur.execute("... ?", (name,))``, is not flagged.
SINK_ARGS = {
    "execute":        ((0,), ("sql", "query", "statement", "operation")),
    "executemany":    ((0,), ("sql", "query", "statement", "operation")),
    "executescript":  ((0,), ("sql_script",)),
    "objects.raw":    ((0,), ("raw_query",)),
    "RawSQL":         ((0,), ("sql",)),
    "extra":          ((), ("where", "select", "tables", "order_by")),
    "read_sql":       ((0,), ("sql",)),
    "read_sql_query": ((0,), ("sql",)),
    "search_s":       ((2,), ("filterstr",)),
    "search_ext_s":   ((2,), ("filterstr",)),
    "save":           ((0,), ("dst",)),
    "asyncio.create_subprocess_exec": ((0,), ("program",)),
    "requests.get":   ((0,), ("url",)),
    "requests.post":  ((0,), ("url",)),
    "requests.put":   ((0,), ("url",)),
    "requests.patch": ((0,), ("url",)),
    "requests.delete": ((0,), ("url",)),
    "requests.head":  ((0,), ("url",)),
    "requests.request": ((1,), ("url",)),
    "httpx.get":      ((0,), ("url",)),
    "httpx.post":     ((0,), ("url",)),
    "httpx.request":  ((1,), ("url",)),
    "urlopen":        ((0,), ("url",)),
    "urllib.request.Request": ((0,), ("url",)),
    "redirect":       ((0,), ("location", "to")),
    "flask.redirect": ((0,), ("location",)),
    "django.shortcuts.redirect": ((0,), ("to",)),
    "HttpResponseRedirect": ((0,), ("redirect_to",)),
    "RedirectResponse": ((0,), ("url",)),
    "send_from_directory": ((1,), ("path", "filename")),
}

# Keyword arguments on sinks that are configuration, not payload.
SINK_CONFIG_KEYWORDS = {"shell", "Loader", "mode", "encoding", "errors",
                        "timeout", "check", "text", "capture_output", "cwd",
                        "env", "stdout", "stderr", "stdin", "headers", "params",
                        "data", "json", "cookies", "auth", "verify"}

# Sinks that are only dangerous when a keyword is set to True ...
SINK_REQUIRES_TRUE = {"numpy.load": "allow_pickle", "np.load": "allow_pickle"}
# ... or are safe when a keyword is set to True.
SINK_SAFE_IF_TRUE = {"torch.load": "weights_only"}

# Sinks that fire when the RECEIVER is tainted, e.g. ``Path(user).read_text()``.
RECEIVER_SINKS = {
    "read_text":   ("path-traversal", "MEDIUM"),
    "read_bytes":  ("path-traversal", "MEDIUM"),
    "write_text":  ("path-traversal", "MEDIUM"),
    "write_bytes": ("path-traversal", "MEDIUM"),
    "unlink":      ("path-traversal", "MEDIUM"),
    "rmdir":       ("path-traversal", "MEDIUM"),
    "touch":       ("path-traversal", "LOW"),
    "extractall":  ("path-traversal", "MEDIUM"),
}

# ``yaml.load`` is only dangerous with the default / Full / Unsafe loader.
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}

# An argument list starting with one of these and containing a "-c" style
# flag goes through a shell even without shell=True.
SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe",
                  "powershell", "powershell.exe", "pwsh"}
SHELL_COMMAND_FLAGS = {"-c", "/c", "/C", "-Command", "-command"}

# Plain-language explanation and fix for each category, shown with findings
# so a reader who is not a security specialist knows why it matters.
CATEGORY_HELP = {
    "command-injection": (
        "Untrusted text becomes part of a shell command, so an attacker can run "
        "their own commands on the machine.",
        "Pass arguments as a list without shell=True, or quote them with shlex.quote."),
    "code-injection": (
        "Untrusted text is run as Python code, so an attacker can make the program "
        "do anything it is able to do.",
        "Never eval or exec user input. Parse it instead, e.g. ast.literal_eval or json.loads."),
    "deserialization": (
        "Untrusted bytes are loaded with a format that can run code while loading, "
        "such as pickle or unsafe YAML.",
        "Use a data-only format such as JSON, or yaml.safe_load."),
    "sql-injection": (
        "Untrusted text is built into an SQL query, so an attacker can read or change "
        "data they should not reach.",
        "Use a parameterized query: put ? or %s in the SQL and pass the values separately."),
    "path-traversal": (
        "Untrusted text is used as a file path, so an attacker can use ../ to reach "
        "files outside the intended folder.",
        "Reduce the name with os.path.basename or check the resolved path stays inside "
        "the allowed directory."),
    "ssrf": (
        "Untrusted text decides which URL the server requests, so an attacker can make "
        "it reach internal services.",
        "Only allow requests to a fixed list of hosts."),
    "template-injection": (
        "Untrusted text is compiled as a template, and template code can run on the server.",
        "Pass user data as template variables, never as the template itself."),
    "xss": (
        "Untrusted text is marked as safe HTML, so an attacker can run script in other "
        "users' browsers.",
        "Let the template engine escape the value instead of marking it safe."),
    "xxe": (
        "An XML parser that resolves external entities reads untrusted XML, which can "
        "leak local files.",
        "Use defusedxml, or turn off entity resolution in the parser."),
    "ldap-injection": (
        "Untrusted text is built into an LDAP filter, which can change what the search returns.",
        "Escape values with ldap.filter.escape_filter_chars."),
    "open-redirect": (
        "Untrusted text decides where the user is redirected, which helps phishing.",
        "Only redirect to relative paths or a fixed list of hosts."),
}


# --- PROPAGATORS ------------------------------------------------------------

# Calls that carry taint from their receiver OR any argument to their result.
# A call that matches nothing is assumed to sanitize (see the README), so this
# list is what keeps taint alive through ordinary string and path plumbing.
PROPAGATOR_SUFFIXES = {
    "os.path.join", "os.path.abspath", "os.path.normpath", "os.path.expanduser",
    "os.path.expandvars", "os.path.realpath", "os.path.dirname",
    "os.path.splitext", "os.path.relpath", "os.fspath",
    "pathlib.Path", "Path", "PurePath", "joinpath",
    "str.format", "format", "format_map", "join",
    "replace", "strip", "lstrip", "rstrip", "removeprefix", "removesuffix",
    "lower", "upper", "title", "capitalize", "casefold", "swapcase",
    "expandtabs", "translate",
    "encode", "decode",
    "split", "rsplit", "splitlines", "partition", "rpartition",
    "ljust", "rjust", "center", "zfill",
    "str", "bytes", "bytearray", "repr",
    "list", "tuple", "dict", "set", "frozenset", "sorted", "reversed",
    "enumerate", "zip", "map", "filter", "next", "iter", "min", "max",
    "copy.copy", "copy.deepcopy", "deepcopy",
    "json.loads", "json.dumps", "ast.literal_eval",
    "urllib.parse.unquote", "unquote", "unquote_plus",
    "urllib.parse.quote", "urllib.parse.quote_plus",
    "urllib.parse.urlparse", "urlparse", "urlsplit",
    "urllib.parse.urljoin", "urljoin", "parse_qs", "parse_qsl",
    "base64.b64decode", "b64decode", "urlsafe_b64decode", "bytes.fromhex",
    "codecs.decode", "zlib.decompress", "gzip.decompress",
    "shlex.split",
    "re.sub", "re.subn", "re.findall", "re.split", "re.match", "re.search",
    "re.fullmatch",
    "textwrap.dedent", "dedent",
    "sqlalchemy.text", "text",
}

# Calls whose result is tainted only when the RECEIVER is. ``d.get(k)`` is
# tainted when ``d`` is, not merely because ``k`` is.
RECEIVER_PROPAGATOR_SUFFIXES = {
    "get", "getlist", "items", "keys", "values", "pop", "popitem", "copy",
    "setdefault",
    "read", "readline", "readlines", "readall", "getvalue",
    "json", "iter_lines", "iter_content",
    "group", "groups", "groupdict",
}

# --- SANITIZERS -------------------------------------------------------------

# Calls that always yield clean data, even when the name would otherwise match
# a propagator (``shlex.join`` vs ``join``). Sanitizers are not context aware:
# ``html.escape`` cleans data for every sink, not just for HTML.
SANITIZER_SUFFIXES = {
    "shlex.quote", "shlex.join",
    "int", "float", "bool", "len", "abs", "round", "hash", "ord",
    "os.path.basename", "secure_filename", "safe_join",
    "html.escape", "markupsafe.escape", "escape", "bleach.clean",
    "re.escape",
    "uuid.UUID", "ipaddress.ip_address", "ipaddress.ip_network",
    "sql.Identifier", "sql.Literal",
}


def name_matches(dotted_name, table, exact=()):
    """Return the entry of ``table`` that ``dotted_name`` ends with, or None.

    Matching is on dot boundaries. Entries listed in ``exact`` only match the
    whole name. Longer entries win, so "subprocess.run" beats a bare "run".
    """
    if not dotted_name:
        return None
    if dotted_name in table:
        return dotted_name
    parts = dotted_name.split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in table and suffix not in exact:
            return suffix
    return None


def match_sink(dotted_name):
    return name_matches(dotted_name, SINKS, EXACT_SINKS)


def _as_sink_spec(spec):
    if isinstance(spec, dict):
        return spec["category"], spec["severity"].upper(), spec
    category, severity = spec[0], spec[1]
    return category, severity.upper(), {}


def load_rules(path):
    """Extend the built-in rules from a JSON file.

    Shape (every key optional)::

        {
          "sources":        ["my_framework.get_param"],
          "source_objects": ["my_framework.params"],
          "sinks":          {"my_db.raw_query": ["sql-injection", "HIGH"],
                             "my_db.q": {"category": "sql-injection",
                                         "severity": "HIGH",
                                         "args": [0], "keywords": ["sql"],
                                         "exact": false}},
          "receiver_sinks": {"my_path_type.dump": ["path-traversal", "LOW"]},
          "propagators":    ["my_fmt"],
          "receiver_propagators": ["fetch_one"],
          "sanitizers":     ["my_escape"]
        }
    """
    with open(path, "r", encoding="utf-8") as f:  # taintpy: ignore (the operator picks this path)
        data = json.load(f)
    SOURCE_CALL_SUFFIXES.update(data.get("sources", []))
    SOURCE_OBJECT_SUFFIXES.update(data.get("source_objects", []))
    for name, spec in data.get("sinks", {}).items():
        category, severity, extra = _as_sink_spec(spec)
        SINKS[name] = (category, severity)
        if "args" in extra or "keywords" in extra:
            SINK_ARGS[name] = (tuple(extra.get("args", ())),
                               tuple(extra.get("keywords", ())))
        if extra.get("exact"):
            EXACT_SINKS.add(name)
    for name, spec in data.get("receiver_sinks", {}).items():
        category, severity, _ = _as_sink_spec(spec)
        RECEIVER_SINKS[name] = (category, severity)
    PROPAGATOR_SUFFIXES.update(data.get("propagators", []))
    RECEIVER_PROPAGATOR_SUFFIXES.update(data.get("receiver_propagators", []))
    SANITIZER_SUFFIXES.update(data.get("sanitizers", []))
    return data


def snapshot():
    """Copy of every mutable rule table, for ``restore``.

    ``load_rules`` changes module-level state. Tests and the web server use
    snapshot/restore so one rules file does not leak into the next scan.
    """
    tables = {name: value for name, value in globals().items()
              if name.isupper() and isinstance(value, (set, dict))}
    return {name: value.copy() for name, value in tables.items()}


def restore(saved):
    for name, value in saved.items():
        table = globals()[name]
        table.clear()
        table.update(value)
