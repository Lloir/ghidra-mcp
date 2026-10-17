"""ghidra-mcp command-line entry point."""

from .config import load_settings
from .service import create_service


def main() -> None:
    create_service(load_settings()).run()
