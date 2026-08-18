"""rules.py — the knowledge base of what's a SOURCE and what's a SINK.

Keeping these as plain data (not buried in code) is deliberate: adding a new
rule should be a one-line edit, and later you can even load rules from a config
file. This is the part you'll grow the most as you find new bug patterns.

Terminology:
  SOURCE = an expression that produces attacker-controllable ("tainted") data.
  SINK   = a dangerous operation that must never receive tainted data unsanitized.
"""

# --- SOURCES -------------------------------------------------------------

# Function calls whose RETURN VALUE is tainted. We match by the *end* of the
# dotted name, so both "request.args.get" and "flask.request.args.get" match.
SOURCE_CALL_SUFFIXES = {
    "input",
    "os.getenv",
    "os.environ.get",
    "getpass.getpass",
    # Flask / web request accessors
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.get_json",
    "request.args.getlist",
    "request.form.getlist",
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
}

# --- SINKS ---------------------------------------------------------------

# Each sink maps a dotted-name SUFFIX to (category, base_severity).
# We match by suffix so "os.system" and (aliased) "system" both have a shot.
SINKS = {
    # Command execution -> command injection / RCE
    "os.system":               ("command-injection", "HIGH"),
    "os.popen":                ("command-injection", "HIGH"),
    "subprocess.run":          ("command-injection", "MEDIUM"),
    "subprocess.call":         ("command-injection", "MEDIUM"),
    "subprocess.check_call":   ("command-injection", "MEDIUM"),
    "subprocess.check_output": ("command-injection", "MEDIUM"),
    "subprocess.Popen":        ("command-injection", "MEDIUM"),
    # Dynamic code execution -> code injection / RCE
    "eval":                    ("code-injection", "HIGH"),
    "exec":                    ("code-injection", "HIGH"),
    "pickle.loads":            ("code-injection", "HIGH"),
    "pickle.load":             ("code-injection", "HIGH"),
    "yaml.load":               ("code-injection", "MEDIUM"),
    # File access -> path traversal
    "open":                    ("path-traversal", "MEDIUM"),
    "os.remove":               ("path-traversal", "MEDIUM"),
    "os.unlink":               ("path-traversal", "MEDIUM"),
    "shutil.copy":             ("path-traversal", "MEDIUM"),
    "shutil.rmtree":           ("path-traversal", "HIGH"),
    "send_file":               ("path-traversal", "MEDIUM"),
    "send_from_directory":     ("path-traversal", "MEDIUM"),
}

# Functions that PROPAGATE taint (tainted in -> tainted out). Used so we don't
# lose the trail through common string plumbing. A plain unknown function call
# is treated as *possibly sanitizing* and does NOT propagate, which keeps
# false positives down.
PROPAGATOR_SUFFIXES = {
    "os.path.join",
    "str.format",
    "format",      # "...".format(tainted)
    "join",        # sep.join([...tainted...])
    "replace", "strip", "lstrip", "rstrip",
    "lower", "upper", "encode", "decode",
}


def name_matches(dotted_name, suffix_set):
    """True if dotted_name equals or ends with '.'+suffix for any suffix."""
    if dotted_name is None:
        return None
    for suffix in suffix_set:
        if dotted_name == suffix or dotted_name.endswith("." + suffix):
            return suffix
    return None
