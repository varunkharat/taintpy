"""rules.py — the knowledge base of what's a SOURCE and what's a SINK.

Keeping these as plain data (not buried in code) is deliberate: adding a new
rule should be a one-line edit, and extra rules can be loaded from a JSON file
at runtime with ``--rules`` (see ``load_rules``).

Terminology:
  SOURCE     = an expression that produces attacker-controllable ("tainted") data.
  SINK       = a dangerous operation that must never receive tainted data unsanitized.
  PROPAGATOR = a call whose output is tainted if its input is (string plumbing).
  SANITIZER  = a call whose output is always considered clean.
"""

import json

# --- SOURCES -------------------------------------------------------------

# Function calls whose RETURN VALUE is tainted. We match by the *end* of the
# dotted name, so both "request.args.get" and "flask.request.args.get" match.
SOURCE_CALL_SUFFIXES = {
    "input",
    "os.getenv",
    "os.environ.get",
    "getpass.getpass",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
    "parse_args",            # argparse: everything on the Namespace is user input
    "recv",                  # sockets
    # Flask / web request accessors
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.get_json",
    "request.get_data",
    "request.args.getlist",
    "request.form.getlist",
    # Django
    "request.GET.get",
    "request.POST.get",
    "request.GET.getlist",
    "request.POST.getlist",
}

# Objects whose ATTRIBUTE or SUBSCRIPT access yields tainted data,
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
    "request.GET",
    "request.POST",
    "request.META",
    "request.body",
}

# --- SINKS ---------------------------------------------------------------

# Each sink maps a dotted-name SUFFIX to (category, base_severity).
# We match by suffix so "os.system" and (aliased) "system" both have a shot.
SINKS = {
    # Command execution -> command injection / RCE
    "os.system":               ("command-injection", "HIGH"),
    "os.popen":                ("command-injection", "HIGH"),
    "os.execv":                ("command-injection", "HIGH"),
    "os.execvp":               ("command-injection", "HIGH"),
    "os.spawnl":               ("command-injection", "HIGH"),
    "subprocess.run":          ("command-injection", "MEDIUM"),
    "subprocess.call":         ("command-injection", "MEDIUM"),
    "subprocess.check_call":   ("command-injection", "MEDIUM"),
    "subprocess.check_output": ("command-injection", "MEDIUM"),
    "subprocess.Popen":        ("command-injection", "MEDIUM"),
    "subprocess.getoutput":    ("command-injection", "HIGH"),
    "subprocess.getstatusoutput": ("command-injection", "HIGH"),
    # Dynamic code execution -> code injection / RCE
    "eval":                    ("code-injection", "HIGH"),
    "exec":                    ("code-injection", "HIGH"),
    "pickle.loads":            ("code-injection", "HIGH"),
    "pickle.load":             ("code-injection", "HIGH"),
    "marshal.loads":           ("code-injection", "HIGH"),
    "yaml.load":               ("code-injection", "MEDIUM"),
    "yaml.unsafe_load":        ("code-injection", "HIGH"),
    "importlib.import_module": ("code-injection", "MEDIUM"),
    # File access -> path traversal
    "open":                    ("path-traversal", "MEDIUM"),
    "os.remove":               ("path-traversal", "MEDIUM"),
    "os.unlink":               ("path-traversal", "MEDIUM"),
    "os.rename":               ("path-traversal", "MEDIUM"),
    "os.rmdir":                ("path-traversal", "MEDIUM"),
    "shutil.copy":             ("path-traversal", "MEDIUM"),
    "shutil.copyfile":         ("path-traversal", "MEDIUM"),
    "shutil.move":             ("path-traversal", "MEDIUM"),
    "shutil.rmtree":           ("path-traversal", "HIGH"),
    "send_file":               ("path-traversal", "MEDIUM"),
    "send_from_directory":     ("path-traversal", "MEDIUM"),
}

# Keyword arguments on sinks that are configuration, not data, and must not be
# treated as a tainted payload on their own.
SINK_CONFIG_KEYWORDS = {"shell", "Loader", "mode", "encoding", "errors",
                        "timeout", "check", "text", "capture_output"}

# ``yaml.load`` is only dangerous with the default / Full / Unsafe loader.
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}

# --- PROPAGATORS ---------------------------------------------------------

# Calls that carry taint from their receiver OR any argument to their result.
# Used so we don't lose the trail through common string plumbing. A plain
# unknown function call is treated as *possibly sanitizing* and does NOT
# propagate, which keeps false positives down.
PROPAGATOR_SUFFIXES = {
    "os.path.join",
    "os.path.abspath", "os.path.normpath", "os.path.expanduser",
    "pathlib.Path", "Path",
    "str.format",
    "format",      # "...".format(tainted)
    "join",        # sep.join([...tainted...])
    "replace", "strip", "lstrip", "rstrip",
    "lower", "upper", "title", "capitalize", "casefold",
    "encode", "decode",
    "split", "rsplit", "splitlines", "partition",
    "ljust", "rjust", "center", "zfill",
    "str", "bytes", "repr",
    "list", "tuple", "sorted", "reversed", "enumerate", "zip",
    "urllib.parse.unquote", "unquote", "unquote_plus",
    "base64.b64decode", "b64decode",
}

# Calls whose result is tainted only when the RECEIVER is (``d.get(k)`` is
# tainted when ``d`` is, not merely because ``k`` is).
RECEIVER_PROPAGATOR_SUFFIXES = {
    "get", "items", "keys", "values", "pop", "copy",
    "read", "readline", "readlines",
}

# --- SANITIZERS ----------------------------------------------------------

# Calls that always yield clean data, even when their name would otherwise
# match a propagator. Unknown calls are already assumed to sanitize; listing
# these explicitly documents the intent and protects against future
# propagator rules swallowing them (e.g. ``shlex.join`` vs ``join``).
SANITIZER_SUFFIXES = {
    "shlex.quote", "shlex.join",
    "int", "float", "bool", "len", "abs", "round",
    "os.path.basename", "secure_filename",
    "html.escape", "re.escape",
}


def name_matches(dotted_name, suffix_set):
    """Return the matching suffix if dotted_name equals or ends with
    '.'+suffix for any suffix in the set, else None."""
    if dotted_name is None:
        return None
    for suffix in suffix_set:
        if dotted_name == suffix or dotted_name.endswith("." + suffix):
            return suffix
    return None


def load_rules(path):
    """Extend the built-in rules from a JSON file.

    Shape (every key optional)::

        {
          "sources":        ["my_framework.get_param"],
          "source_objects": ["my_framework.params"],
          "sinks":          {"my_db.raw_query": ["sql-injection", "HIGH"]},
          "propagators":    ["my_fmt"],
          "sanitizers":     ["my_escape"]
        }
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    SOURCE_CALL_SUFFIXES.update(data.get("sources", []))
    SOURCE_OBJECT_SUFFIXES.update(data.get("source_objects", []))
    for name, spec in data.get("sinks", {}).items():
        category, severity = spec
        SINKS[name] = (category, severity.upper())
    PROPAGATOR_SUFFIXES.update(data.get("propagators", []))
    SANITIZER_SUFFIXES.update(data.get("sanitizers", []))
    return data
