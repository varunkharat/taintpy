"""Entry module. Taint enters here, sinks live in helpers.py."""

import helpers
from helpers import run_shell, Store


def a():
    run_shell("ls " + input("dir: "))        # BUG (cross-file)


def b():
    helpers.run_shell(input("cmd: "))         # BUG (cross-file, module attr)


def c():
    s = Store("/srv")
    s.wipe(input("name: "))                   # BUG (method, 2 hops)


def d():
    s = Store("/srv")
    s.wipe(Store.label(input("x: ")))         # SAFE (staticmethod returns const)
