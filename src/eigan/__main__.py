"""Permite ``python -m eigan`` (mesmo comportamento do comando ``eigan``)."""

import sys

from eigan.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
