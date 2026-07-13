"""Just enough ELF to turn a function name into an address.

To set a breakpoint on `main`, you need to know where `main` is. That lives in
the ELF symbol table: parse the header to find the section headers, find the
`.symtab` section and its associated string table, and walk the fixed-size
symbol entries. This is all documented, all fixed-layout, and -- unlike ptrace
-- entirely testable, because `readelf -s` will tell you the right answers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

STT_FUNC = 2            # symbol type: a function
PIE_ET_DYN = 3         # a position-independent executable is ET_DYN


class NotELF(Exception):
    pass


@dataclass
class Symbol:
    name: str
    value: int          # address within the file's own address space
    size: int
    is_func: bool


@dataclass
class ELF:
    entry: int
    is_pie: bool
    symbols: dict[str, Symbol]

    def func(self, name: str) -> Symbol | None:
        s = self.symbols.get(name)
        return s if s and s.is_func else None


def parse(path: str) -> ELF:
    with open(path, "rb") as f:
        data = f.read()

    if data[:4] != b"\x7fELF":
        raise NotELF(f"{path} is not an ELF file")
    if data[4] != 2:
        raise NotELF("only 64-bit ELF is supported")

    # ELF64 header: entry at 24, section header offset at 40, then counts.
    e_type = struct.unpack_from("<H", data, 16)[0]
    e_entry = struct.unpack_from("<Q", data, 24)[0]
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off, s_type = struct.unpack_from("<II", data, off)
        s_offset, s_size = struct.unpack_from("<QQ", data, off + 24)
        s_link = struct.unpack_from("<I", data, off + 40)[0]
        s_entsize = struct.unpack_from("<Q", data, off + 56)[0]
        sections.append((name_off, s_type, s_offset, s_size, s_link, s_entsize))

    # Section names live in the section-header string table.
    shstr_off = sections[e_shstrndx][2]

    def sec_name(name_off: int) -> str:
        end = data.index(b"\0", shstr_off + name_off)
        return data[shstr_off + name_off:end].decode("ascii", "replace")

    symbols: dict[str, Symbol] = {}
    for name_off, s_type, s_offset, s_size, s_link, s_entsize in sections:
        if sec_name(name_off) not in (".symtab", ".dynsym"):
            continue
        if s_entsize == 0:
            continue
        str_off = sections[s_link][2]        # the linked string table

        for j in range(s_size // s_entsize):
            eoff = s_offset + j * s_entsize
            st_name, st_info = struct.unpack_from("<IB", data, eoff)
            st_value, st_size = struct.unpack_from("<QQ", data, eoff + 8)
            if st_name == 0:
                continue
            end = data.index(b"\0", str_off + st_name)
            sym_name = data[str_off + st_name:end].decode("ascii", "replace")
            is_func = (st_info & 0xF) == STT_FUNC
            # Prefer .symtab (fuller) but don't overwrite a real address with 0.
            if sym_name not in symbols and st_value:
                symbols[sym_name] = Symbol(sym_name, st_value, st_size, is_func)

    return ELF(entry=e_entry, is_pie=(e_type == PIE_ET_DYN), symbols=symbols)
