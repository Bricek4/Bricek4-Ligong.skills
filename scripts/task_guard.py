#!/usr/bin/env python3
"""Public Ligong SSS and TaskGuard executable."""

from __future__ import annotations

from pathlib import Path
import sys


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT))


_CONTROL_COMMANDS = {"doctor", "fuse", "preflight"}


def _global_help() -> str:
    return """usage: task_guard.py COMMAND [options]

Ligong SSS control plane with TaskGuard v2 and fail-closed v3.

control commands:
  doctor      report runtime capabilities without side effects
  fuse        evaluate the one-way SSS risk fuse
  preflight   evaluate risk and TaskGuard admission
  export      export a protocol-specific read-only evidence bundle

TaskGuard commands:
  init        initialize guarded task state
  run         run the contract acceptance commands
  verify      verify acceptance and protected surfaces
  status      report the current guarded task state
  checkpoint  record a recoverable checkpoint
  dispose     dispose guarded task state

TaskGuard v3 control commands:
  validate    validate a strict external-action contract without state writes
  explain     explain adapter, authority, and release capability gaps
  doctor-v3   report v3 readiness (production remains disabled by default)
  provider-readiness  report exact missing provider/release evidence
  shadow      evaluate a provider plan without apply, rollback, or authority use
  plan        create a bound side-effect-free provider plan when registered
  apply       external mutation; fail-closed unless every release gate is proven
  reconcile   reconcile an interrupted external action
  rollback    execute a pre-authorized reversible rollback
  health      collect revision-bound provider health evidence
"""


def main(argv: list[str] | None = None) -> int:
    selected = sys.argv[1:] if argv is None else argv
    if selected and selected[0] in {"-h", "--help"}:
        print(_global_help(), end="")
        return 0
    if selected and selected[0] in _CONTROL_COMMANDS:
        from taskguard.control import main as control_main

        return control_main(selected)
    try:
        from taskguard.router import route_main

        return route_main(selected)
    except ValueError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
