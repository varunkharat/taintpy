"""Web interface: paste code, pick an engine, see the taint paths inline.

Install with ``pip install -e ".[web]"`` and run ``taintpy-web``. The page
is static HTML served from ``static/``. All analysis happens in one JSON
endpoint that calls the same code the CLI does, and returns the same
finding dictionaries as the JSON report, so the page highlights lines from
structured data and never parses display text.
"""

import argparse
import ast
import os
import warnings

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse
    from pydantic import BaseModel, Field
except ImportError as e:
    raise SystemExit("The web interface needs its extra dependencies:\n"
                     '    pip install -e ".[web]"') from e

from .. import __version__
from ..analyzer import analyze_source
from ..interprocedural import analyze_program

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
FILENAME = "<input>"
# Large enough for any single file worth pasting, small enough that one
# request cannot tie up the server for long.
MAX_CODE_BYTES = 200_000


class AnalyzeRequest(BaseModel):
    code: str = Field(..., max_length=MAX_CODE_BYTES)
    engine: str = Field("interproc", pattern="^(interproc|intra)$")
    unknown_calls: str = Field("sanitize", pattern="^(sanitize|propagate)$")


def analyze(code, engine="interproc", unknown_calls="sanitize"):
    """Run one analysis and return the response body. Raises SyntaxError."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        ast.parse(code, filename=FILENAME)
        if engine == "interproc":
            findings = analyze_program([(FILENAME, code)], unknown_calls).findings
        else:
            findings = analyze_source(code, FILENAME, unknown_calls)
    findings.sort(key=lambda f: (f.lineno, f.source_line))
    return {"engine": engine, "unknown_calls": unknown_calls,
            "count": len(findings), "findings": [f.to_dict() for f in findings]}


def create_app():
    app = FastAPI(title="taintpy", version=__version__,
                  docs_url=None, redoc_url=None)

    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC, "index.html"))

    @app.get("/api/version")
    def version():
        return {"version": __version__}

    @app.post("/api/analyze")
    def analyze_endpoint(req: AnalyzeRequest):
        try:
            return analyze(req.code, req.engine, req.unknown_calls)
        except SyntaxError as e:
            raise HTTPException(status_code=400, detail={
                "error": "syntax error", "message": e.msg, "line": e.lineno})

    return app


app = create_app()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="taintpy-web",
                                     description="Run the taintpy web interface.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="address to bind (default: 127.0.0.1, this machine only)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    import uvicorn
    print(f"taintpy web interface on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
