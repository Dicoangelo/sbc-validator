"""Enable `python -m sbc_validator ...` as an alias for the console script.

Mirrors the `sbc-validator` entry point so the package is runnable directly,
without relying on the installed script being on PATH.
"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
