"""Entry point for ``python -m siptestwin`` and the PyInstaller executable.

An absolute import is used (not ``from .cli``) so the same module works both
when run as a package module (``python -m siptestwin``) and when PyInstaller
executes it as a top-level script with no package context.
"""

from siptestwin.cli import main

if __name__ == "__main__":
    main()
