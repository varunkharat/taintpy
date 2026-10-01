"""taintpy — a minimal taint-tracking static analyzer for injection bugs.

A learning-grade security tool: it reads Python source, finds where untrusted
input enters (sources), and reports when that data can reach a dangerous
operation (sinks) without being cleaned along the way.
"""

__version__ = "0.3.0"
