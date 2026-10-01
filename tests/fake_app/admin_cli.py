"""Fake admin CLI for exercising taintpy.

Same conventions as webapp.py: ``# BUG`` should be flagged, ``# SAFE`` should
not, ``# INTERPROC`` needs ``--interproc``. Sources here are CLI-style:
sys.argv, os.environ, input(), getpass.

This code is never meant to be run.
"""

import getpass
import os
import shutil
import subprocess
import sys

BACKUP_DIR = "/var/backups/share"
ALLOWED_ENVS = {"dev", "staging", "prod"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def read_target():
    # Returns tainted data from argv.
    return sys.argv[2]


def backup_file(name):
    # Parameter reaches a sink inside this function.
    shutil.copy(name, BACKUP_DIR)


def announce(text):
    # Parameter reaches a sink inside this function.
    os.system("wall '" + text + "'")


def choose_env(raw):
    # Parameter does NOT reach return: allowlist lookup yields a constant.
    if raw in ALLOWED_ENVS:
        return "prod"
    return "dev"


# --------------------------------------------------------------------------
# Intraprocedural bugs
# --------------------------------------------------------------------------

def rotate_logs():
    days = sys.argv[1]
    os.system("find /var/log -mtime +" + days + " -delete")  # BUG command-injection


def deploy():
    env = os.environ["DEPLOY_ENV"]
    subprocess.call(f"./deploy.sh {env}", shell=True)         # BUG command-injection (HIGH)


def purge_cache():
    cache = os.getenv("CACHE_DIR", "/tmp/cache")
    shutil.rmtree(cache)                                      # BUG path-traversal (HIGH)


def load_plugin():
    code = input("plugin code: ")
    exec(code)                                                # BUG code-injection


def tail_log():
    which = input("log name: ")
    path = os.path.join("/var/log", which)
    with open(path, "rb") as fh:                              # BUG path-traversal
        return fh.read()[-4096:]


def sudo_check():
    pw = getpass.getpass("password: ")
    subprocess.Popen("echo " + pw + " | sudo -S true", shell=True)  # BUG command-injection


def cleanup_user():
    user = input("user: ").strip()
    os.unlink("/home/{}/.cache".format(user))                 # BUG path-traversal via .format


# --------------------------------------------------------------------------
# Interprocedural bugs
# --------------------------------------------------------------------------

def backup_from_argv():
    backup_file(read_target())                                # INTERPROC path-traversal


def broadcast():
    message = input("message: ")
    announce(message)                                         # INTERPROC command-injection


# --------------------------------------------------------------------------
# Safe decoys
# --------------------------------------------------------------------------

def list_dir_safe():
    target = sys.argv[1]
    subprocess.run(["ls", "-la", target])                     # SAFE argument list


def deploy_safe():
    env = choose_env(os.environ.get("DEPLOY_ENV", "dev"))
    subprocess.call(f"./deploy.sh {env}", shell=True)         # SAFE (interproc: allowlist returns const)


def restart_service():
    name = "nginx"
    os.system("systemctl restart " + name)                    # SAFE constant


def count_lines():
    path = input("file: ")
    n = len(path)                                             # unknown func: assumed sanitizing
    os.system("head -n " + str(n) + " /etc/motd")             # SAFE (int, not the raw path)


def show_help():
    topic = input("topic: ")
    print("No help for", topic)                               # SAFE: print is not a sink
