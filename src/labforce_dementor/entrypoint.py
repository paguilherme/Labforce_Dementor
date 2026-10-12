from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__


def main(argv: Sequence[str] | None = None) -> None:
    """Start the CLI while keeping the lightweight version check dependency-free."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--version"]:
        program = "dementor" if argv is not None else (Path(sys.argv[0]).name or "dementor")
        if program == "__main__.py":
            program = "dementor"
        print(f"{program} {__version__}")
        return

    from .cli import main as cli_main

    cli_main(arguments)
