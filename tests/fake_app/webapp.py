"""Fake Flask "file share" app for exercising taintpy.

Every line marked ``# BUG`` is a planted vulnerability taintpy should catch.
Every line marked ``# SAFE`` is a decoy taintpy should leave alone.
Lines marked ``# INTERPROC`` are only findable with ``--interproc``.

This code is never meant to be run.
"""

import os
import pickle
import shutil
import subprocess

import yaml
from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_ROOT = "/srv/share/uploads"


# --------------------------------------------------------------------------
# Helpers (used by the interprocedural cases below)
# --------------------------------------------------------------------------

def current_user():
    # Returns tainted data: the cookie is attacker controlled.
    return request.cookies.get("user", "anonymous")


def build_path(name):
    # Parameter flows to return value through os.path.join.
    return os.path.join(UPLOAD_ROOT, name)


def run_shell(cmd):
    # The sink lives here, far from where the input arrives.
    return os.popen(cmd).read()


def normalize(name):
    # Parameter flows to return value via propagators (strip/lower).
    return name.strip().lower()


def hash_it(value):
    # Parameter does NOT reach the return value.
    return "sha256:" + "0" * 64


# --------------------------------------------------------------------------
# Routes: intraprocedural bugs
# --------------------------------------------------------------------------

@app.route("/download")
def download():
    name = request.args.get("name")
    path = os.path.join(UPLOAD_ROOT, name)
    return send_file(path)                                  # BUG path-traversal


@app.route("/view")
def view():
    name = request.args["name"]
    with open(UPLOAD_ROOT + "/" + name) as fh:              # BUG path-traversal
        return fh.read()


@app.route("/delete", methods=["POST"])
def delete():
    folder = request.form.get("folder")
    shutil.rmtree(f"{UPLOAD_ROOT}/{folder}")                # BUG path-traversal (HIGH)


@app.route("/convert", methods=["POST"])
def convert():
    fmt = request.form["format"]
    src = request.form["src"]
    cmd = "convert {} -format {} out.png".format(src, fmt)
    subprocess.run(cmd, shell=True)                         # BUG command-injection (HIGH)


@app.route("/ping")
def ping():
    host = request.values.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)  # BUG command-injection
    return out


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))                                  # BUG code-injection


@app.route("/restore", methods=["POST"])
def restore():
    blob = request.data
    session = pickle.loads(blob)                            # BUG code-injection
    return session["user"]


@app.route("/config", methods=["POST"])
def load_config():
    text = request.get_json()["yaml"]
    cfg = yaml.load(text)                                   # BUG code-injection (unsafe loader)
    return str(cfg)


@app.route("/tag")
def tag():
    tags = request.args.getlist("t")
    line = ",".join(tags)
    os.system("git tag " + line)                            # BUG command-injection via join


# --------------------------------------------------------------------------
# Routes: interprocedural bugs
# --------------------------------------------------------------------------

@app.route("/whoami")
def whoami():
    user = current_user()
    run_shell("id " + user)                                 # INTERPROC command-injection


@app.route("/thumb")
def thumb():
    p = build_path(request.args.get("name"))
    return send_file(p)                                     # INTERPROC path-traversal


@app.route("/rename")
def rename():
    clean = normalize(request.args.get("name"))
    os.remove(build_path(clean))                            # INTERPROC path-traversal (3 hops)


# --------------------------------------------------------------------------
# Routes: safe decoys (should NOT be flagged)
# --------------------------------------------------------------------------

@app.route("/version")
def version():
    return subprocess.check_output(["git", "describe"])     # SAFE constant list, no shell


@app.route("/ping-safe")
def ping_safe():
    host = request.args.get("host", "127.0.0.1")
    subprocess.run(["ping", "-c", "1", host])               # SAFE argument list, no shell
    return "ok"


@app.route("/fingerprint")
def fingerprint():
    digest = hash_it(request.args.get("name"))
    os.system("echo " + digest)                             # SAFE (interproc: taint dies in hash_it)
    return digest


@app.route("/reset")
def reset():
    name = request.args.get("name")
    name = "default.txt"                                    # taint overwritten
    with open(os.path.join(UPLOAD_ROOT, name)) as fh:       # SAFE
        return fh.read()


@app.route("/readme")
def readme():
    return send_file(os.path.join(UPLOAD_ROOT, "README.md"))  # SAFE constant path


@app.route("/log")
def log():
    msg = request.args.get("msg")
    app.logger.info("user said %s", msg)                    # SAFE: not a sink
    return "logged"
