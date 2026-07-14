# pdb-from-scratch

**A debugger in pure Python. It sets breakpoints the way real debuggers do: by writing the byte `0xCC` into another process's memory.**

There is no magic "breakpoint" button in a debugger. To stop a program at a
function, you overwrite the first byte of that function with `0xCC` — the
one-byte `int3` instruction — and remember the byte you clobbered. When the CPU
reaches `0xCC`, it traps into the kernel, which stops the process and hands
control to whoever is tracing it. To carry on, you put the real byte back, step
the CPU over that one instruction, and plant `0xCC` again for next time.

That's the entire trick, and this is it running:

```console
$ gcc -g -no-pie -O0 -o loopcount examples/loopcount.c
$ python -m pdbfs run ./loopcount add
total = 10
breakpoint on add at 0x400466

running ...

  hit add (#1)  rdi=0x0 rsi=0x0 rdx=0x0
  hit add (#2)  rdi=0x0 rsi=0x1 rdx=0x1
  hit add (#3)  rdi=0x1 rsi=0x2 rdx=0x2
  hit add (#4)  rdi=0x3 rsi=0x3 rdx=0x3
  hit add (#5)  rdi=0x6 rsi=0x4 rdx=0x4

program exited
  add: 5 hit(s)
```

The `total = 10` on the first line is the *child* talking — its stdout is not
separated from the debugger's, because a debugger that swallowed the program's
output would be a strange debugger. And `-no-pie` is not decoration: with a
position-independent executable the address is different on every run, and the
`0x400466` above would be a lie the moment you tried it.

The program calls `add(total, i)` in a five-iteration loop. The breakpoint fires
five times — once per call — and each time we read the argument registers
straight out of the stopped process: `rsi` is the loop counter `i` going
`0,1,2,3,4`, and `rdi` is the running total `0,0,1,3,6`. Nothing here is
simulated. That is a real child process, stopped on a real trap, and its real
registers.

## Why five hits is the whole proof

Getting the breakpoint to fire *once* is easy. Getting it to fire five times is
the part that separates a working debugger from a broken one, because after the
first hit the real instruction byte is gone — you replaced it with `0xCC`. To
continue correctly you have to:

1. notice the instruction pointer is now one byte *past* the `0xCC`,
2. rewind it back onto the instruction,
3. write the saved byte back so the instruction is whole again,
4. single-step exactly that one instruction,
5. plant `0xCC` again, and only then let the program run.

Skip step 4 and you never hit the breakpoint a second time. Skip step 3 and the
CPU executes a corrupt instruction. The test that asserts **exactly five hits**
is the test that all five steps are right:

```python
def test_breakpoint_fires_once_per_loop_iteration(loopprog):
    add = parse(loopprog).func("add").value
    tracer = Tracer.launch([loopprog])
    tracer.set_breakpoint(add, "add")
    hits = 0
    while tracer.continue_past() is not None:
        hits += 1
    assert hits == 5
```

## Finding the function

To break on `add`, you need to know where `add` is. That comes from the ELF
symbol table — parsed here by hand, and checked against `readelf`:

```console
$ python -m pytest tests/test_elf.py -q
6 passed
```

For a position-independent executable the symbol value is only an *offset*; the
real address is that offset plus wherever the kernel mapped the binary, read
from `/proc/<pid>/maps`. The debugger handles both.

## Verified, not just written

```console
$ python -m pytest -q
19 passed
```

Two layers get tested:

- **The bookkeeping**, which is pure arithmetic and needs no ptrace: planting
  `0xCC` at a byte means reading the aligned 8-byte word, patching one byte, and
  writing it back. A wrong shift silently corrupts the seven *neighbouring*
  bytes — so there is a test that the shift is exact at every alignment, and
  that arming then disarming gives back the original word bit-for-bit.
- **The real thing**: an integration test launches a compiled C program, traces
  it, and checks the breakpoint fires once per loop iteration with the right
  register values. It skips itself where ptrace isn't permitted.

## Use it

```console
$ gcc -g -no-pie -O0 -o loopcount loopcount.c
$ python -m pdbfs run ./loopcount main add
```

```python
from pdbfs.elf import parse
from pdbfs.tracer import Tracer

addr = parse("./loopcount").func("add").value
tracer = Tracer.launch(["./loopcount"])
tracer.set_breakpoint(addr, "add")

while (hit := tracer.continue_past()) is not None:
    regs = tracer.get_regs()
    print(f"add called with {regs.rdi & 0xffffffff}, {regs.rsi & 0xffffffff}")
```

## The parts that bite

- **After `0xCC` fires, rip points one byte past it**, and the real byte is
  gone. Both have to be fixed before continuing. This is the single most common
  way a hand-rolled debugger breaks.
- **ptrace reads and writes memory one word at a time.** Setting one byte is
  read-modify-write on the whole word; the wrong mask damages its neighbours.
- **PIE vs non-PIE.** A symbol address is absolute in a non-PIE and a load-base
  offset in a PIE. Get it wrong and you plant `0xCC` in the middle of some
  unrelated instruction.
- **`GETREGS` wants a pointer to a struct, `POKETEXT` wants an integer.** The
  first version of the ctypes wrapper passed the struct wrong — the integration
  test caught it immediately, which is exactly what integration tests are for.

## Limits

- **Linux, x86-64 only.** ptrace and the register layout are both OS- and
  arch-specific.
- **Breakpoints and register inspection**, not a full debugger. No stepping by
  source line, no stack unwinding, no watchpoints.
- **Needs permission to trace.** Under a restrictive `ptrace_scope` or inside a
  hardened sandbox, tracing is denied and the integration test skips itself.

## Install

```console
$ git clone https://github.com/Wasserpuncher/pdb-from-scratch
$ cd pdb-from-scratch
$ gcc -g -no-pie -O0 -o examples/loopcount examples/loopcount.c
$ python -m pdbfs run examples/loopcount add
```

Python 3.10+, no dependencies. Linux with ptrace.

## License

MIT
