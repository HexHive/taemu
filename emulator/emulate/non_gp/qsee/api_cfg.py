from collections import defaultdict
from dataclasses import dataclass
import datetime
from enum import Enum
import functools
import hashlib
import os
import random
import struct
from colorama import Fore
import pwn
from qiling import Qiling
from qiling.os.const import LONGLONG, STRING, INT, BYTE, POINTER, UINT

import time
from typing import TYPE_CHECKING, Dict
from .api_common import _ret, _read_u32

if TYPE_CHECKING:
    from emulate.emulator_no_loader import HookData
    from emulate.ta_mgr import TAEMU


__all__ = ["qsee_cfg_getpropval"]


def qsee_cfg_getpropval(ql: Qiling, hook_data: 'HookData'):
    args = ql.os.resolve_fcall_params({
        "prop": STRING,
        "prop_len": UINT,
        "prop_type": UINT,
        "out": POINTER,
        "out_len": UINT,
        "ret_size": POINTER,
    })

    prop = args["prop"]
    if len(prop) != args["prop_len"] - 1:
        ql.log.warning("qsee_cfg_getpropval: prop length mismatch %d != %d", len(prop), args["prop_len"] - 1)
    out = args["out"]
    out_len = args["out_len"]
    ret_size = args["ret_size"]

    cfg = {
        "enable_set_bandwidth": pwn.p32(1),
        "fp_sensor_name": b"Stargate\x00",
        "fp_sensor_version": pwn.p32(0),
        "enable_finger_id": pwn.p32(0),
        "enable_soter": pwn.p32(0),
    }

    val = cfg.get(prop)
    if val is None:
        ql.log.warning("qsee_cfg_getpropval: unknown prop %r, returning empty value", prop)
        val = b"\x00"

    if ret_size:
        ql.mem.write(ret_size, pwn.p32(len(val)))

    blob = pwn.p32(args["prop_type"]) + pwn.p32(len(val)) + val

    if not out:
        ql.log.warning("qsee_cfg_getpropval(%r): null out buffer", prop)
        _ret(ql, 0)
        return

    if out_len < len(blob):
        ql.log.warning(
            "qsee_cfg_getpropval(%r): short buffer %d < %d, writing truncated blob",
            prop, out_len, len(blob)
        )
        blob = blob[:out_len]

    ql.mem.write(out, blob)
    ql.log.info("qsee_cfg_getpropval(%r) -> %d bytes", prop, len(val))
    _ret(ql, 0)
