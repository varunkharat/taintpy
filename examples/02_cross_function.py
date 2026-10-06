"""The input arrives in one function and the sink is two calls away.

A pattern scanner sees os.system(cmd) in run() with a parameter it knows
nothing about. Following the data shows that cmd can be user input.
"""

import os


def read_name():
    return input("name: ")


def build(name):
    return "id " + name.strip()


def run(cmd):
    os.system(cmd)


def main():
    run(build(read_name()))
