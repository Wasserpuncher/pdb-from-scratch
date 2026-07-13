"""A tiny command-line debugger.

    pdbfs run ./prog main            set a breakpoint on main(), run, report hits

It launches the program stopped, resolves the requested function names to
addresses via the ELF symbol table, plants 0xCC breakpoints, and runs. Each
time a breakpoint fires it prints the function and the argument registers, then
continues. For a PIE it reads the load base from /proc/<pid>/maps and adds it to
each symbol's offset.
"""

from __future__ import annotations

import argparse
import os
import sys

from .elf import parse
from .tracer import Tracer


def _load_base(pid: int, path: str) -> int:
    """Where the kernel mapped the executable. For a PIE, symbol values are
    offsets from here; for a non-PIE the base is 0 and addresses are absolute."""
    real = os.path.realpath(path)
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if real in line and "r-xp" in line or (real in line and line.rstrip().endswith(real)):
                return int(line.split("-", 1)[0], 16)
    # Fall back to the first mapping of the file.
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if real in line:
                return int(line.split("-", 1)[0], 16)
    return 0


def cmd_run(args) -> int:
    path = os.path.abspath(args.program)
    elf = parse(path)

    targets = {}
    for name in args.function:
        sym = elf.func(name)
        if not sym:
            print(f"no function {name!r} in {path}", file=sys.stderr)
            return 2
        targets[name] = sym.value

    tracer = Tracer.launch([path, *args.args])
    base = _load_base(tracer.pid, path) if elf.is_pie else 0

    for name, value in targets.items():
        addr = base + value
        tracer.set_breakpoint(addr, name)
        print(f"breakpoint on {name} at {addr:#x}")

    print(f"\nrunning {path}\n")
    while True:
        hit = tracer.continue_past()
        if hit is None:
            break
        bp = tracer.breakpoints[hit]
        regs = tracer.get_regs()
        print(f"  hit {bp.label} (#{bp.hit_count})  "
              f"rdi={regs.rdi:#x} rsi={regs.rsi:#x} rdx={regs.rdx:#x}")

    print("\nprogram exited")
    for bp in tracer.breakpoints.values():
        print(f"  {bp.label}: {bp.hit_count} hit(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pdbfs", description="A from-scratch ptrace debugger.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="break on functions and run")
    r.add_argument("program")
    r.add_argument("function", nargs="+", help="function name(s) to break on")
    r.add_argument("--args", nargs=argparse.REMAINDER, default=[],
                   help="arguments to pass to the program")
    r.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
