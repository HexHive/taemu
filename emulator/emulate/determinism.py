"""Deterministic RNG + clock for reproducible fuzzing/replay.

AFL/unicornafl assume *same input -> same execution*. Three things in this
emulator break that contract and produce flaky crashes + corrupted coverage
feedback:

  * the RNG is a real CSPRNG (Crypto.Random.get_random_bytes / os.urandom),
  * TEE_GetSystemTime / TEE_GetREETime read the wall clock,
  * the persistent object store writes real files under ./emulate/files/, which
    accumulate across fork-server iterations (see gp/utils/persistent_object.py;
    the in-memory backend toggle MEM_STORE_ENABLED lives here).

Everything here is OPT-IN. With no env var set, get_random_bytes() forwards to
the real CSPRNG, now() returns the wall clock, and the persistent store stays on
disk -- i.e. default (interactive) behavior is byte-for-byte unchanged.

Env vars
--------
  TAEMU_DETERMINISM=1     master switch: seeded RNG + frozen clock + in-mem store
  TAEMU_RNG_SEED=<int>    DRBG seed (default 0)
  TAEMU_FAKE_TIME=<int>   frozen epoch seconds (default 0x6745a3c0)
  TAEMU_MEM_STORE=1       in-memory persistent store only (implied by DETERMINISM)

Fork semantics: the DRBG state is just (seed, counter), so fork() copies it like
any other memory. We reset() the counter at the start of every InvokeCommand
iteration (wired in ta_mgr.start_fuzz), so each forked child draws the identical
random stream -> reproducible. The in-memory store likewise resets via copy-on-
write fork, with an explicit store_reset() for the single-process replay path.
"""

import os
import hashlib

from Crypto.Random import get_random_bytes as _csprng

DETERMINISM = "TAEMU_DETERMINISM" in os.environ
_SEED = int(os.environ.get("TAEMU_RNG_SEED", "0"))
_FAKE_TIME = int(os.environ.get("TAEMU_FAKE_TIME", str(0x6745A3C0)))

# In-memory persistent store is on whenever determinism is on, or when explicitly
# requested. persistent_object.py reads this flag.
MEM_STORE_ENABLED = DETERMINISM or "TAEMU_MEM_STORE" in os.environ


class _CtrDRBG:
    """SHA-256 counter DRBG: deterministic, fork-stable, and reset-able.

    Block i = SHA256(seed_le64 || counter_le64). State is two ints, so it is
    trivially copied by fork() and snapshot-able."""

    __slots__ = ("_seed_bytes", "ctr")

    def __init__(self, seed: int):
        self._seed_bytes = (seed & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        self.ctr = 0

    def reset(self):
        self.ctr = 0

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = bytearray()
        while len(out) < n:
            out += hashlib.sha256(
                self._seed_bytes + self.ctr.to_bytes(8, "little")
            ).digest()
            self.ctr += 1
        return bytes(out[:n])


_drbg = _CtrDRBG(_SEED)


def get_random_bytes(n: int) -> bytes:
    """Drop-in replacement for Crypto.Random.get_random_bytes / os.urandom.

    Deterministic under TAEMU_DETERMINISM, real CSPRNG otherwise."""
    if DETERMINISM:
        return _drbg.read(n)
    return _csprng(n)


def now() -> int:
    """Epoch seconds. Frozen under TAEMU_DETERMINISM so time-dependent TAs are
    reproducible; wall clock otherwise."""
    if DETERMINISM:
        return _FAKE_TIME
    import time as _t

    return int(_t.time())


def reset():
    """Reset per-iteration deterministic state. Called at the top of every fuzz
    InvokeCommand iteration (and before a replay run)."""
    if DETERMINISM:
        _drbg.reset()
