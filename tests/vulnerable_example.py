"""Deliberately vulnerable examples. Every function here has a real bug.
Used to confirm the analyzer's *recall* (it should flag all of these).
"""

import os
import subprocess


def cmd_injection_direct():
    host = input("host: ")
    os.system("ping -c 1 " + host)          # command injection


def cmd_injection_fstring():
    host = input("host: ")
    os.system(f"ping -c 1 {host}")           # command injection via f-string


def cmd_injection_subprocess_shell():
    user = input("name: ")
    subprocess.run("id " + user, shell=True)  # shell=True + taint -> HIGH


def path_traversal():
    filename = input("file: ")
    with open(filename) as f:                # path traversal
        return f.read()


def code_injection():
    expr = input("expr: ")
    return eval(expr)                        # code injection


def via_argv():
    import sys
    target = sys.argv[1]
    os.system("nmap " + target)              # source is sys.argv


def through_a_variable():
    raw = input("cmd: ")
    tmp = raw
    combined = "echo " + tmp
    os.system(combined)                      # taint flows raw->tmp->combined
