"""Taint enters and reaches a sink in the same function."""

import os


def ping():
    host = input("host: ")
    os.system("ping -c 1 " + host)


def ping_safe():
    host = input("host: ")
    os.system("ping -c 1 example.com")
