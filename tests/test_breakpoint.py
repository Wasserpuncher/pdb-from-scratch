"""The breakpoint bookkeeping -- the part where a wrong shift silently
corrupts the seven bytes next to your breakpoint. No ptrace needed to test it:
it is pure arithmetic on a machine word."""

import pytest

from pdbfs.breakpoint import INT3, Breakpoint


def test_int3_is_0xcc():
    assert INT3 == 0xCC


def test_arm_patches_only_the_target_byte():
    # A word of recognisable bytes; put a breakpoint on the byte at offset 3.
    word = 0x1122334455667788      # little-endian byte at addr&7==0 is 0x88
    bp = Breakpoint(addr=3, original_byte=0)
    armed = bp.arm_word(word)
    # byte 3 (from the low end) must be 0xCC ...
    assert Breakpoint.byte_at(armed, 3) == 0xCC
    # ... and every other byte must be untouched.
    for i in range(8):
        if i != 3:
            assert Breakpoint.byte_at(armed, i) == Breakpoint.byte_at(word, i)


def test_disarm_is_the_exact_inverse_of_arm():
    word = 0xDEADBEEFCAFEF00D
    for offset in range(8):
        original = Breakpoint.byte_at(word, offset)
        bp = Breakpoint(addr=0x400000 + offset, original_byte=original)
        armed = bp.arm_word(word)
        assert Breakpoint.byte_at(armed, offset) == 0xCC   # the trap is planted
        restored = bp.disarm_word(armed)
        assert restored == word                            # and fully undone


@pytest.mark.parametrize("addr", [0x0, 0x1, 0x7, 0x400123, 0x7fffffffe456])
def test_shift_is_correct_at_every_alignment(addr):
    word = 0x0000000000000000
    bp = Breakpoint(addr=addr, original_byte=0xAB)
    armed = bp.arm_word(word)
    assert Breakpoint.byte_at(armed, addr) == 0xCC
    # The other bytes stayed zero -- the shift didn't spill.
    others = armed & ~(0xFF << ((addr & 7) * 8))
    assert others == 0


def test_aligned_rounds_down_to_the_word():
    assert Breakpoint.aligned(0x400123) == 0x400120
    assert Breakpoint.aligned(0x400120) == 0x400120
    assert Breakpoint.aligned(0x7) == 0x0


def test_byte_at_reads_the_right_lane():
    word = 0xAABBCCDDEEFF0011
    assert Breakpoint.byte_at(word, 0) == 0x11
    assert Breakpoint.byte_at(word, 1) == 0x00
    assert Breakpoint.byte_at(word, 7) == 0xAA


def test_a_real_instruction_survives_the_round_trip():
    # Bytes of `push rbp; mov rbp,rsp` (55 48 89 e5 ...). Planting a breakpoint
    # on the first byte and removing it must give back exactly 0x55.
    word = 0xE5894855  # low byte 0x55
    bp = Breakpoint(addr=0, original_byte=0x55)
    assert Breakpoint.byte_at(bp.disarm_word(bp.arm_word(word)), 0) == 0x55
