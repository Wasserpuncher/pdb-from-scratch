"""ELF symbol resolution, checked against the compiler's own output and readelf."""

import os
import re
import shutil
import struct
import subprocess

import pytest

from pdbfs.elf import NotELF, parse

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    src = tmp_path_factory.mktemp("elf") / "prog.c"
    src.write_text(
        "int helper(int x){return x*2;}\n"
        "int main(void){return helper(21);}\n"
    )
    out = str(src.with_suffix(""))
    subprocess.run(["gcc", "-g", "-no-pie", "-O0", "-o", out, str(src)], check=True)
    return out


def test_finds_main_and_helper(binary):
    elf = parse(binary)
    assert elf.func("main") is not None
    assert elf.func("helper") is not None


def test_addresses_match_readelf(binary):
    if not shutil.which("readelf"):
        pytest.skip("readelf not available")
    elf = parse(binary)
    out = subprocess.run(["readelf", "-s", binary], capture_output=True, text=True).stdout

    want = {}
    for line in out.splitlines():
        m = re.search(r"([0-9a-f]{16})\s+\d+\s+FUNC\s+\S+\s+\S+\s+\S+\s+(\w+)$", line)
        if m:
            want[m.group(2)] = int(m.group(1), 16)

    for name in ("main", "helper"):
        assert elf.func(name).value == want[name], f"{name} address disagrees with readelf"


def test_detects_non_pie(binary):
    assert parse(binary).is_pie is False


def test_detects_pie(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    src = tmp_path / "p.c"
    src.write_text("int main(void){return 0;}\n")
    out = str(src.with_suffix(""))
    subprocess.run(["gcc", "-g", "-fPIE", "-pie", "-O0", "-o", out, str(src)], check=True)
    assert parse(out).is_pie is True


def test_rejects_non_elf(tmp_path):
    junk = tmp_path / "notelf"
    junk.write_bytes(b"MZ\x90\x00" + b"\0" * 200)   # a DOS/PE header, not ELF
    with pytest.raises(NotELF):
        parse(str(junk))


def test_rejects_32bit_elf(tmp_path):
    # A valid ELF magic but the 32-bit class byte.
    fake = tmp_path / "elf32"
    fake.write_bytes(b"\x7fELF\x01" + b"\0" * 200)
    with pytest.raises(NotELF, match="64-bit"):
        parse(str(fake))
