#!/usr/bin/env python3
# Arche Defender launcher. The code lives in arche/; see README.md. `./arche-defender.py --help` lists the options.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from arche.cli import main

if __name__ == '__main__':
    sys.exit(main())
