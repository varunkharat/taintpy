"""One analysis request in, one JSON-ready response out.

Shared by the FastAPI server (taintpy/web/app.py) and the in-browser build
in docs/, which runs this same file under Pyodide. Keeping it free of any
web framework is what lets both use it unchanged.
"""

import ast
import json
import warnings

from . import __version__
from .analyzer import analyze_source
from .interprocedural import analyze_program

FILENAME = "<input>"
# Large enough for any single file worth pasting, small enough that one
# request cannot tie up the server for long.
MAX_CODE_CHARS = 200_000
ENGINES = ("interproc", "intra")
UNKNOWN_CALLS = ("sanitize", "propagate")


class RequestError(ValueError):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def analyze(code, engine="interproc", unknown_calls="sanitize"):
    """Run one analysis. Raises RequestError for bad input or a syntax error."""
    if not isinstance(code, str) or len(code) > MAX_CODE_CHARS:
        raise RequestError(422, {"error": "code must be text under "
                                          f"{MAX_CODE_CHARS} characters"})
    if engine not in ENGINES or unknown_calls not in UNKNOWN_CALLS:
        raise RequestError(422, {"error": "unknown engine or unknown_calls option"})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            ast.parse(code, filename=FILENAME)
        except SyntaxError as e:
            raise RequestError(400, {"error": "syntax error", "message": e.msg,
                                     "line": e.lineno}) from e
        if engine == "interproc":
            findings = analyze_program([(FILENAME, code)], unknown_calls).findings
        else:
            findings = analyze_source(code, FILENAME, unknown_calls)
    findings.sort(key=lambda f: (f.lineno, f.source_line))
    return {"version": __version__, "engine": engine, "unknown_calls": unknown_calls,
            "count": len(findings), "findings": [f.to_dict() for f in findings]}


def analyze_json(payload):
    """JSON string in, JSON string out, with errors as {"status", "detail"}.
    This is the entry point the browser build calls."""
    try:
        req = json.loads(payload)
        body = analyze(req.get("code", ""), req.get("engine", "interproc"),
                       req.get("unknown_calls", "sanitize"))
        return json.dumps({"status": 200, "body": body})
    except RequestError as e:
        return json.dumps({"status": e.status, "body": {"detail": e.detail}})
