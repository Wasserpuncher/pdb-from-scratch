"""End-to-end: actually trace a real process.

This is the test that needs Linux, ptrace permission and gcc, so it is skipped
where it cannot run (including most CI sandboxes). Where it *can* run, it proves
the whole thing: launch a program that calls add() in a five-iteration loop,
break on add, and assert the breakpoint fires exactly five times -- which can
only happen if the 0xCC is planted, the step-over restores the real byte, and
the breakpoint is re-armed each time round the loop.

Run it yourself with:  python -m pytest tests/test_integration.py -v
"""

import ctypes
import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    not os.path.exists("/proc/self/status") or not shutil.which("gcc"),
    reason="needs Linux + gcc",
)


def _ptrace_allowed() -> bool:
    """Can we trace a child at all? Some sandboxes forbid it outright."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return False
    pid = os.fork()
    if pid == 0:
        libc.ptrace(0, 0, 0, 0)          # TRACEME
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.WIFSTOPPED(status) or os.WIFEXITED(status)


@pytest.fixture(scope="module")
def loopprog(tmp_path_factory):
    src = tmp_path_factory.mktemp("dbg") / "loop.c"
    src.write_text(
        "#include <stdio.h>\n"
        "int add(int a,int b){return a+b;}\n"
        "int main(void){int t=0; for(int i=0;i<5;i++) t=add(t,i);"
        " printf(\"%d\\n\",t); return 0;}\n"
    )
    out = str(src.with_suffix(""))
    subprocess.run(["gcc", "-g", "-no-pie", "-O0", "-o", out, str(src)], check=True)
    return out


@pytest.mark.skipif(not _ptrace_allowed(), reason="ptrace not permitted here")
def test_breakpoint_fires_once_per_loop_iteration(loopprog):
    from pdbfs.elf import parse
    from pdbfs.tracer import Tracer

    add = parse(loopprog).func("add").value
    tracer = Tracer.launch([loopprog])
    tracer.set_breakpoint(add, "add")

    hits = 0
    while tracer.continue_past() is not None:
        hits += 1

    # add() is called once per iteration of a five-iteration loop.
    assert hits == 5
    assert tracer.breakpoints[add].hit_count == 5


@pytest.mark.skipif(not _ptrace_allowed(), reason="ptrace not permitted here")
def test_reads_the_argument_registers_at_the_breakpoint(loopprog):
    from pdbfs.elf import parse
    from pdbfs.tracer import Tracer

    add = parse(loopprog).func("add").value
    tracer = Tracer.launch([loopprog])
    tracer.set_breakpoint(add, "add")

    # add(total, i): the running total in rdi, the loop counter in rsi.
    seen = []
    while tracer.continue_past() is not None:
        regs = tracer.get_regs()
        seen.append((regs.rdi & 0xFFFFFFFF, regs.rsi & 0xFFFFFFFF))

    # i counts 0..4; total is the running sum 0,0,1,3,6.
    assert [s for _, s in seen] == [0, 1, 2, 3, 4]
    assert [t for t, _ in seen] == [0, 0, 1, 3, 6]
