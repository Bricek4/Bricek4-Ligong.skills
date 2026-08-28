#!/usr/bin/env python3
"""Run Ligong's unittest suite from any working directory."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = SKILL_ROOT / "tests"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run_tests.py")
    parser.add_argument("--pattern", default="test*.py")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    sys.path.insert(0, str(SKILL_ROOT))
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(TEST_ROOT),
        pattern=arguments.pattern,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
