"""Build the in-browser version of the web interface into docs/.

    python tools/build_site.py

GitHub Pages serves docs/ as a static site. The page is the same
taintpy/web/static/index.html the server uses, with its backend switched to
Pyodide (Python compiled to WebAssembly), and the analyzer's own .py files
copied next to it. Nothing is rewritten or bundled: the browser runs the
same source files as the command line. tests/test_site.py fails if docs/ is
out of date, so rerun this after changing the analyzer or the page.
"""

import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "taintpy", "web", "static", "index.html")
# Only the dependency-free core. cli.py and web/ are not needed in the browser.
MODULES = ["__init__.py", "analyzer.py", "interprocedural.py", "program.py",
           "rules.py", "sarif.py", "service.py"]


def render_page():
    with open(PAGE, encoding="utf-8") as f:
        html = f.read()
    files = [f"taintpy/{m}" for m in MODULES]
    for old, new in [('const BACKEND = "server";', 'const BACKEND = "pyodide";'),
                     ("const PY_FILES = [];", f"const PY_FILES = {json.dumps(files)};")]:
        if old not in html:
            raise SystemExit(f"index.html no longer contains {old!r}; update build_site.py")
        html = html.replace(old, new, 1)
    return html


def build(out_dir):
    # Empty the directory rather than deleting it: on Windows a directory
    # that a local preview server is serving from cannot be removed.
    if os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            path = os.path.join(out_dir, name)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
    os.makedirs(os.path.join(out_dir, "py", "taintpy"), exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write(render_page())
    for m in MODULES:
        with open(os.path.join(ROOT, "taintpy", m), encoding="utf-8") as src, \
                open(os.path.join(out_dir, "py", "taintpy", m), "w", encoding="utf-8",
                     newline="\n") as dst:
            dst.write(src.read())
    # Without this, GitHub Pages runs Jekyll, which silently drops files whose
    # names start with an underscore. That includes taintpy/__init__.py, and
    # the page would fail to import the package.
    open(os.path.join(out_dir, ".nojekyll"), "w").close()


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs"))
    print("built docs/")
