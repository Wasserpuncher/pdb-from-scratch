"""The ptrace layer: the part that reaches into another process.

Everything here is a thin wrapper over one syscall, `ptrace(2)`, called through
ctypes because Python has no binding for it. The interesting logic -- what a
breakpoint *is*, how to find an address, how to step over a planted 0xCC -- is
in breakpoint.py and elf.py, where it can be tested. This file is where those
decisions turn into real reads and writes of a real process's memory, and it
needs Linux and the permission to trace a child.

The dance to continue past a breakpoint is the subtle bit, and it is spelled
out in `continue_past`.
"""

from __future__ import annotations

import ctypes
import os
import signal
import struct

from .breakpoint import INT3, Breakpoint

# ptrace request numbers (from <sys/ptrace.h>).
TRACEME = 0
PEEKTEXT = 1
POKETEXT = 4
CONT = 7
SINGLESTEP = 9
GETREGS = 12
SETREGS = 13

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.ptrace.restype = ctypes.c_long
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                         ctypes.c_void_p, ctypes.c_void_p]


class user_regs_struct(ctypes.Structure):
    """x86-64 general registers, in the order the kernel returns them."""
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


def _ptrace(request: int, pid: int, addr: int, data) -> int:
    ctypes.set_errno(0)
    # For GETREGS/SETREGS `data` is a pointer to a struct the kernel fills or
    # reads; for PEEK/POKE it is a plain integer. ctypes needs byref for the
    # struct and a cast for the integer.
    data_arg = ctypes.byref(data) if isinstance(data, ctypes.Structure) else ctypes.c_void_p(data)
    res = _libc.ptrace(request, pid, ctypes.c_void_p(addr), data_arg)
    errno = ctypes.get_errno()
    if res == -1 and errno:
        raise OSError(errno, os.strerror(errno), f"ptrace request {request}")
    return res


class Tracer:
    """Controls one traced child process."""

    def __init__(self, pid: int):
        self.pid = pid
        self.breakpoints: dict[int, Breakpoint] = {}

    # -- launching -------------------------------------------------------

    @classmethod
    def launch(cls, argv: list[str]) -> "Tracer":
        """fork, ask to be traced, exec. The child stops on the exec so the
        parent can plant breakpoints before a single instruction runs."""
        pid = os.fork()
        if pid == 0:
            _ptrace(TRACEME, 0, 0, 0)
            os.execv(argv[0], argv)
            os._exit(127)
        os.waitpid(pid, 0)          # child is stopped at execv
        return cls(pid)

    # -- memory (one word at a time, the way ptrace does it) -------------

    def read_word(self, addr: int) -> int:
        return _ptrace(PEEKTEXT, self.pid, addr, 0) & 0xFFFFFFFFFFFFFFFF

    def write_word(self, addr: int, word: int) -> None:
        _ptrace(POKETEXT, self.pid, addr, word)

    def read_byte(self, addr: int) -> int:
        return Breakpoint.byte_at(self.read_word(Breakpoint.aligned(addr)), addr)

    # -- registers -------------------------------------------------------

    def get_regs(self) -> user_regs_struct:
        regs = user_regs_struct()
        _ptrace(GETREGS, self.pid, 0, regs)
        return regs

    def set_regs(self, regs: user_regs_struct) -> None:
        _ptrace(SETREGS, self.pid, 0, regs)

    # -- breakpoints -----------------------------------------------------

    def set_breakpoint(self, addr: int, label: str = "") -> Breakpoint:
        aligned = Breakpoint.aligned(addr)
        word = self.read_word(aligned)
        bp = Breakpoint(addr, Breakpoint.byte_at(word, addr), label)
        self.write_word(aligned, bp.arm_word(word))
        bp.enabled = True
        self.breakpoints[addr] = bp
        return bp

    def _restore(self, bp: Breakpoint) -> None:
        aligned = Breakpoint.aligned(bp.addr)
        self.write_word(aligned, bp.disarm_word(self.read_word(aligned)))

    def _rearm(self, bp: Breakpoint) -> None:
        aligned = Breakpoint.aligned(bp.addr)
        self.write_word(aligned, bp.arm_word(self.read_word(aligned)))

    # -- running ---------------------------------------------------------

    def continue_past(self) -> int | None:
        """Resume the child. If it is sitting on one of our breakpoints, step
        over it correctly first.

        After a 0xCC fires, the CPU's instruction pointer is one byte *past* the
        0xCC, and the real instruction byte has been clobbered. So: back rip up
        by one, put the real byte back, single-step that one instruction, plant
        the 0xCC again, and only then continue. Skip any of those and you either
        execute a corrupt instruction or never hit the breakpoint twice.
        """
        regs = self.get_regs()
        here = self.breakpoints.get(regs.rip - 1)
        if here and here.enabled:
            regs.rip -= 1                       # rewind onto the real instruction
            self.set_regs(regs)
            self._restore(here)
            _ptrace(SINGLESTEP, self.pid, 0, 0)
            os.waitpid(self.pid, 0)
            self._rearm(here)

        _ptrace(CONT, self.pid, 0, 0)
        _, status = os.waitpid(self.pid, 0)

        if os.WIFEXITED(status):
            return None                         # child is gone; exit code below
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
            regs = self.get_regs()
            bp = self.breakpoints.get(regs.rip - 1)
            if bp:
                bp.hit_count += 1
                return bp.addr
        return None

    def wait_exit(self) -> int:
        _, status = os.waitpid(self.pid, 0)
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
