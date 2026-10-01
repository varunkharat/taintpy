"""Helpers imported by main.py. Cross-module interprocedural fixture."""

import os


def run_shell(cmd):
    os.system(cmd)                       # sink lives in this module


class Store:
    def __init__(self, root):
        self.root = root

    def resolve(self, name):
        return os.path.join(self.root, name)

    def wipe(self, name):
        os.remove(self.resolve(name))    # sink reached via self.resolve

    @staticmethod
    def label(x):
        return "const"
