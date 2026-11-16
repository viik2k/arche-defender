# `python3 -m arche`, or `python3 path/to/arche/__main__.py` (what the systemd units and the menu entry run).
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from arche.cli import main

if __name__ == '__main__':
    sys.exit(main())
