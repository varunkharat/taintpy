"""taintpy: a taint-tracking static analyzer for Python injection bugs.

It reads Python source, finds where untrusted input enters (sources), and
reports when that data can reach a dangerous operation (sinks) without being
cleaned along the way.
"""

__version__ = "0.4.0"
