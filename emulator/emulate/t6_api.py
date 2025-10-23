from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from Crypto.Random import get_random_bytes
from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE
import time as pytime
from .common import crash, crash_notimpl

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf, TEE_MemCompare, malloc, free
from .gp.utils.printf import parse_fmt_str, fixup_format


def GetBootSeed(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    out = ql.os.resolve_fcall_params({"buf": POINTER, "size": INT})
    buf = out["buf"]
    size = out["size"]
    try:
        ql.mem.write(buf, size * b"A")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def debug_log2(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {
                "filename": STRING,
                "linenumber": INT,
                "nr1": INT,
                "nr2": INT,
                "format": STRING,
            }
        )
        linenumber = p["linenumber"]
        filename = p["filename"]
        nr1 = p["nr1"]
        nr2 = p["nr2"]
        format_param = p["format"]
        final_params = {
            "filename": STRING,
            "linenumber": linenumber,
            "nr1": nr1,
            "nr2": nr2,
            "format": STRING,
        }
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        format_param = fixup_format(format_param)
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        ql.log.info(f"{hook_data.func_name}: {filename}({linenumber}): {out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def debug_log(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {"log_level": INT, "filename": STRING, "format": STRING}
        )
        log_level = p["log_level"]
        filename = p["filename"]
        format_param = p["format"]
        final_params = {"log_level": INT, "filename": STRING, "format": STRING}
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        format_param = fixup_format(format_param)
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        ql.log.info(f"{hook_data.func_name}: {log_level}, {filename}{out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def check_license(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
