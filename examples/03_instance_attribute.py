"""Taint stored on self in one method and used in another."""

import subprocess


class Backup:
    def __init__(self, target):
        self.target = target

    def start(self):
        subprocess.run(f"tar czf /tmp/b.tgz {self.target}", shell=True)


def main():
    job = Backup(input("directory: "))
    job.start()
