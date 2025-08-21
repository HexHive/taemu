from .crypto import *
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .err import *
from .object import *

BIGINTS = {}

def _panic(ql: Qiling, msg: str):
    ql.log.critical(msg)
    ql.arch.regs.arch_pc = 0xdeadbeef


def _require_bigint(ptr: int):
    if ptr not in BIGINTS:
        return None
    return BIGINTS[ptr]


def _read_bigint(ql: Qiling, ptr: int):
    """Read a TEE_BigInt value from emulated memory as Python int.
    Returns (value, BigIntObj) or panics if not initialized.
    """
    obj = _require_bigint(ptr)
    if obj is None:
        _panic(ql, f"bigint buffer not initialized! {hex(ptr)}")
        return None, None
    nbytes = obj.size * 4
    raw = ql.mem.read(ptr, nbytes)
    val = int.from_bytes(raw, byteorder="little", signed=True)
    return val, obj


def _fits_in(val: int, nbytes: int) -> bool:
    # Two's-complement bounds for nbytes
    bits = nbytes * 8
    minv = -(1 << (bits - 1))
    maxv = (1 << (bits - 1)) - 1
    return minv <= val <= maxv


def _write_bigint(ql: Qiling, ptr: int, val: int, dest_obj: BigInt):
    nbytes = dest_obj.size * 4
    if not _fits_in(val, nbytes):
        _panic(ql, f"BigInt overflow: result does not fit in dest ({nbytes} bytes)")
        return False
    ql.mem.write(ptr, val.to_bytes(nbytes, byteorder="little", signed=True))
    return True

def bigint_to_int(ql, ptr):
    if ptr not in BIGINTS:
        ql.log.critical(f"BigInt at {hex(ptr)} not initialized!")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return 0
    bigIntObj = BIGINTS[ptr]
    raw_bytes = ql.mem.read(ptr, bigIntObj.size * 4)
    return int.from_bytes(raw_bytes, "little", signed=True)

def int_to_bigint(ql, ptr, value):
    bigIntObj = BIGINTS[ptr]
    try:
        nr_bytes = value.to_bytes(bigIntObj.size * 4, "little", signed=True)
        ql.mem.write(ptr, nr_bytes)
        return True
    except OverflowError:
        return False


class BigInt:
    def __init__(self, buf, size, ql:Qiling) -> None:
        self.buf = buf
        self.size = size
        ql.mem.write(self.buf, self.size*4*b"\x00")



