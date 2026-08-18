"""Cross-function (interprocedural) cases. The v1 intraprocedural engine finds
ZERO of the real bugs here; the v0.2 engine should find exactly 2.
"""

import os


def get_user_input():
    return input("name: ")            # this function RETURNS tainted data


def run_it(value):
    os.system("echo " + value)        # sink lives here, in another function


def passthrough(x):
    return x                          # param flows straight to return


def safe_wrapper(v):
    return "constant-safe-value"      # param does NOT reach the return


# BUG 1: source -> run_it's sink, across two functions
run_it(get_user_input())

# BUG 2: source -> passthrough -> run_it's sink, across three functions
run_it(passthrough(input("y: ")))

# SAFE: taint dies inside safe_wrapper, so run_it gets clean data
run_it(safe_wrapper(input("z: ")))
