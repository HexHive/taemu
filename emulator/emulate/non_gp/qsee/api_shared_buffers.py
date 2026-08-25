import datetime
import functools
import hashlib
import os
import random
import struct
import pwn
from qiling import Qiling
from qiling.os.const import INT, POINTER

import time
from typing import TYPE_CHECKING, Dict
from .api_common import _ret

if TYPE_CHECKING:
    from emulate.emulator_no_loader import HookData
    from emulate.ta_mgr import TAEMU



class _Buffer:
    def __init__(self, addr: int, size: int):
        self.addr = addr
        self.size = size
        self.secure_read_prepared = False
        self.nosecure_read_prepared = False

class QseeSharedBuffers:
    def __init__(self):
        self.bufs: Dict[int, _Buffer] = {}

def get_qsee_shared_buffers(emu: 'TAEMU') -> QseeSharedBuffers:
    """
    Optional state holder.

    You can pre-populate:
        hook_data.qsee_secure_tag_ranges = [
            (0x0a, start, end),
            (0x0d, start, end),
        ]

    If no ranges are configured, qsee_is_s_tag_area() permissively accepts
    tags 0x0a and 0x0d.
    """
    if not hasattr(emu, "qsee_shared_buffers"):
        emu.qsee_shared_buffers = QseeSharedBuffers()

    return emu.qsee_shared_buffers


def qsee_is_s_tag_area(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "vmid": INT,
        "start": POINTER,
        "end": POINTER
    })
    vmid = args['vmid']
    area_start = args['start']
    area_end = args['end']
    ql.log.info("qsee_is_s_tag_area(%#x, %#0x, %#0x)", vmid, area_start, area_end)

    # Check if the range is mapped inside qiling
    for start, end, perms, info, _ in ql.mem.get_mapinfo():
        if start <= area_start < area_end <= end:
            ql.log.info("qsee_is_s_tag_area: %#x is in the %s area, vmid %#x.", start, info, vmid)
            _ret(ql, 1)
            return
        
    ql.log.warning("qsee_is_s_tag_area: %#x is not in any mapped area, vmid %#x.", area_start, vmid)
    _ret(ql, 0)


def qsee_register_shared_buffer(ql: Qiling, hook_data: 'HookData'):
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
        "size": POINTER,
    })

    addr = args["addr"]
    size = args["size"]

    shared_buffers = get_qsee_shared_buffers(hook_data.emu)

    ql.log.info(
        "qsee_register_shared_buffer(addr=%#x, size=%#x)",
        addr, size
    )

    if addr == 0 or size == 0:
        ql.log.warning("qsee_register_shared_buffer: invalid buffer")
        _ret(ql, -1)
        return

    shared_buffers.bufs[addr] = _Buffer(addr, size)

    _ret(ql, 0)


def qsee_prepare_shared_buf_for_secure_read(ql: Qiling, hook_data: 'HookData'):
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
        "size": POINTER,
    })

    addr = args["addr"]
    size = args["size"]

    shared_buffers = get_qsee_shared_buffers(hook_data.emu)

    ql.log.info(
        "qsee_prepare_shared_buf_for_secure_read(addr=%#x, size=%#x)",
        addr, size
    )

    buf = shared_buffers.bufs.get(addr)
    if buf is None:
        # Keep this permissive; many TAs do not care if this is exact.
        ql.log.warning(
            "qsee_prepare_shared_buf_for_secure_read: %#x was not registered",
            addr
        )
        _ret(ql, 0)
        return

    if size > buf.size:
        ql.log.warning(
            "qsee_prepare_shared_buf_for_secure_read: size %#x exceeds registered size %#x",
            size, buf.size
        )

    buf.secure_read_prepared = True

    _ret(ql, 0)


def qsee_prepare_shared_buf_for_nosecure_read(ql: Qiling, hook_data: 'HookData'):
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
        "size": POINTER,
    })

    addr = args["addr"]
    size = args["size"]

    shared_buffers = get_qsee_shared_buffers(hook_data.emu)

    ql.log.info(
        "qsee_prepare_shared_buf_for_nosecure_read(addr=%#x, size=%#x)",
        addr, size
    )

    buf = shared_buffers.bufs.get(addr)
    if buf is None:
        ql.log.warning(
            "qsee_prepare_shared_buf_for_nosecure_read: %#x was not registered",
            addr
        )
        _ret(ql, 0)
        return

    if size > buf.size:
        ql.log.warning(
            "qsee_prepare_shared_buf_for_nosecure_read: size %#x exceeds registered size %#x",
            size, buf.size
        )

    # Real function probably cleans/flushes cache so the non-secure side sees writes.
    # No-op in emulation.
    buf.nosecure_read_prepared = True

    _ret(ql, 0)


def qsee_deregister_shared_buffer(ql: Qiling, hook_data: 'HookData'):
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
    })

    addr = args["addr"]
    shared_buffers = get_qsee_shared_buffers(hook_data.emu)

    ql.log.info("qsee_deregister_shared_buffer(addr=%#x)", addr)
    if addr not in shared_buffers.bufs:
        ql.log.warning(
            "qsee_deregister_shared_buffer: %#x was not registered",
            addr
        )
        _ret(ql, 0)
        return

    del shared_buffers.bufs[addr]

    _ret(ql, 0)

__all__ = [
    "qsee_is_s_tag_area",
    "qsee_register_shared_buffer",
    "qsee_prepare_shared_buf_for_secure_read",
    "qsee_prepare_shared_buf_for_nosecure_read",
    "qsee_deregister_shared_buffer",
]