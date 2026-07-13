"""How a breakpoint actually works: you overwrite a byte.

There is no special "breakpoint" facility in the CPU that a debugger reaches
for here. To stop a program at address X, you read the byte that lives at X,
remember it, and write `0xCC` in its place. `0xCC` is the one-byte encoding of
`int3` -- the breakpoint interrupt. When the CPU reaches it, it traps into the
kernel, which stops the process and hands control to whoever is tracing it.

To *continue*, you have to undo the trick: the real instruction byte is gone,
so you write the saved byte back, step the CPU over that one instruction, then
put `0xCC` back so the breakpoint fires again next time round a loop.

This module is that bookkeeping -- the part that is pure logic and can be
tested without ptrace. The ptrace calls that read and write another process's
memory live in `tracer.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

INT3 = 0xCC


@dataclass
class Breakpoint:
    addr: int
    original_byte: int          # the real instruction byte we replaced
    label: str = ""
    enabled: bool = False
    hit_count: int = 0

    def arm_word(self, word: int) -> int:
        """Given the 8 aligned bytes containing our address, return them with
        `0xCC` patched into the right position.

        ptrace reads and writes memory a machine word at a time, so setting one
        byte means: read the whole word, change one byte, write it back. Getting
        the shift wrong corrupts the seven neighbouring bytes -- which is a great
        way to make a program crash in a way that looks nothing like a bug in
        the program.
        """
        shift = (self.addr & 7) * 8
        return (word & ~(0xFF << shift)) | (INT3 << shift)

    def disarm_word(self, word: int) -> int:
        """The inverse: put the saved original byte back into the word."""
        shift = (self.addr & 7) * 8
        return (word & ~(0xFF << shift)) | (self.original_byte << shift)

    @staticmethod
    def byte_at(word: int, addr: int) -> int:
        """Extract the byte living at `addr` from its aligned word."""
        return (word >> ((addr & 7) * 8)) & 0xFF

    @staticmethod
    def aligned(addr: int) -> int:
        """The word-aligned address ptrace has to actually read."""
        return addr & ~7
