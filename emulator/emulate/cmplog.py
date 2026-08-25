"""Comparison-operand harvester ("cmplog-lite").

A coverage-guided fuzzer stalls at byte-exact gates -- ``if (memcmp(buf, MAGIC,
n))``, ``if (strcmp(tag, "..."))``, length/header checks -- because random
mutation almost never reproduces the expected constant. Real cmplog/redqueen
solves this in the instrumentation; bumping AFL++/unicornafl for it is the
heavier follow-up (see FUZZING_MODES.md). This is the cheap 80%: the emulator
already *reimplements* the common compare functions in Python, so we harvest the
operands it sees into an AFL dictionary (``-x``). AFL then splices those exact
tokens into inputs and walks straight through the gate.

Intended use: enable during a REPLAY pass over the seed corpus to extract a
dictionary, then fuzz with it. It only fires inside the already-hooked compare
APIs (no per-instruction cost), and is deliberately a harvest-time tool rather
than something on the live fork hot-path.

  TAEMU_CMPLOG=1                 enable harvesting
  TAEMU_CMPLOG_DICT=<path>       output dict path (default ./cmplog.dict)
"""
import os
import atexit

ENABLED = "TAEMU_CMPLOG" in os.environ
_DICT_PATH = os.environ.get("TAEMU_CMPLOG_DICT", "cmplog.dict")
_MIN, _MAX = 2, 64
_tokens = set()


def record(*bufs):
    """Record compare operands as candidate dictionary tokens. Cheap no-op
    unless TAEMU_CMPLOG is set."""
    if not ENABLED:
        return
    for b in bufs:
        if not b:
            continue
        b = bytes(b)
        if b.endswith(b"\x00"):          # C strings: drop the terminator
            b = b.rstrip(b"\x00")
        if _MIN <= len(b) <= _MAX and any(b):   # skip empty / all-zero
            _tokens.add(b)


def _esc(b):
    return "".join(f"\\x{c:02x}" for c in b)


def dump(path=None):
    if not ENABLED or not _tokens:
        return
    path = path or _DICT_PATH
    try:
        with open(path, "w") as f:
            for i, t in enumerate(sorted(_tokens)):
                f.write(f'tok{i}="{_esc(t)}"\n')
    except OSError:
        pass


atexit.register(dump)
