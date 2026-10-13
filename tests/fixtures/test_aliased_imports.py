# Aliased imports must not hide risky calls from the scanner.
import pickle as pk
import hashlib as hl
from os import system
from subprocess import run as sh

pk.loads(b"")
hl.md5(b"x")
system("ls")
sh("ls", shell=True)
