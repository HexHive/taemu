#!/usr/bin/env python3
"""Compatibility entrypoint for the TA emulator fuzzing campaign CLI."""

from orchestrator.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
