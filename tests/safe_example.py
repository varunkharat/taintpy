"""Safe examples. NONE of these should be flagged. Used to confirm the
analyzer's *precision* (low false positives).
"""

import os
import subprocess


def constant_command():
    os.system("ls -la")                      # constant, no taint


def constant_file():
    with open("config.txt") as f:            # constant path
        return f.read()


def list_args_no_shell():
    user = input("name: ")
    # argument list, no shell -> the classic SAFE way to pass user data
    subprocess.run(["id", user])             # note: still no shell=True


def overwritten_clean():
    data = input("x: ")
    data = "safe-default"                    # taint overwritten before use
    os.system("echo " + data)


def unrelated_variable():
    tainted = input("x: ")                   # noqa: taint exists but unused
    safe = "hello"
    os.system("echo " + safe)                # sink uses only clean data
