"""PyInstaller entry point (absolute import so the frozen app can start)."""

from ptaf.cli import main

if __name__ == "__main__":
    main(prog_name="ptaf")
