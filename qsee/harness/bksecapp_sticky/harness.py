from .params import *
from qiling import Qiling
import struct, os

# === bksecapp §5 sticky-flag (byte_A100) dynamic confirmation =================
# SBKSEC-7 §5 (CWE-372): byte_A100 (BSS, VA 0xa100) selects random-IV mode.
# It is set to 1 by cmd 41 BkWrapFunctionRandomIV (@0x21c0, UNCONDITIONAL) and
# cmd 42, and is NEVER cleared by cmd 29 BkWrapFunction / cmd 30 BkUnwrapFunction
# (byte-exact: those handlers contain no store to 0xa100). Consequence: a cmd 41
# leaves the flag set, and a *subsequent* cmd 29 "wrap" silently takes the
# random-IV path instead of the deterministic serial-number-IV path.
#
# This harness drives the REAL dispatcher (bksecapp_tz_app_cmd_handler@0x050C)
# three times in one process (TAEMU_MULTI_CMD=3; guest memory persists across
# ops, CPU context restored per op):
#   op#0  cmd 29  (fresh, byte_A100==0)  -> expect SERIAL-IV path  @0x1e80
#   op#1  cmd 41  (sets byte_A100=1)     -> expect RANDOM-IV path  @0x1e40 (by design)
#   op#2  cmd 29  (IDENTICAL to op#0)    -> expect RANDOM-IV path  @0x1e40 (THE BUG)
# The op#0 vs op#2 contrast (same command, divergent IV path) is the dynamic
# proof of the sticky-state confusion. We also read byte_A100 entering each op
# (0 -> 0 -> 1) confirming cmd 29 never resets it and cmd 41 set it.
#
# NB: the AES core (qsee_cipher_*) is identity-stubbed in this emulator, so the
# crypto-construction defects §1-4 (no MAC / static IV / caller IV) are NOT
# faithfully reproducible here and are reported CONFIRMED-IN-BINARY (capstone).
# This harness only exercises CONTROL FLOW (the byte_A100 branch + the
# dispatcher), which is real TA code and crypto-independent.

AFL_EXIT  = 0x13370
CMD_BASE  = 0x51000000
RSP_BASE  = 0x52000000
REGION    = 0x4000
CMDLEN    = 0x1004          # dispatcher requires cmd_len==rsp_len==0x1004

# Qiling loads this PIE TA at a fixed bias (confirmed in the run log:
# TA_CreateEntryPoint @0x555555557ba0 == BASE + json 0x3ba0).
BASE          = 0x555555554000
VA_BYTE_A100  = BASE + 0xa100   # the sticky mode flag (BSS global, VA 0xa100)
VA_SERIAL_IV  = BASE + 0x1e80   # BkWrapInner default path: bl qsee_read_serial_num
VA_RANDOM_IV  = BASE + 0x1e40   # BkWrapInner random  path: bl qsee_prng_getdata

CMD_WRAP      = 29          # BkWrapFunction        (default IV = serial)
CMD_WRAP_RIV  = 41          # BkWrapFunctionRandomIV(sets byte_A100=1)

_OP = {"i": -1}            # current op index (set in place_input_callback)


def _read_flag(ql):
    try:
        return ql.mem.read(VA_BYTE_A100, 1)[0]
    except Exception:
        return -1


def _stop(ql):
    # halt this op cleanly at the IV-selection branch, BEFORE BkWrapInner's
    # end-of-function write (an incidental asan redzone hit @lr 0x1fd4 that is
    # tangential to §5 and would otherwise abort the multi-op loop).
    try:
        ql.emu_stop()
    except Exception:
        ql.arch.uc.emu_stop()


def _hook_serial(ql, *a):
    print(f"[sticky] OP#{_OP['i']} IV-PATH=SERIAL (deterministic serial-num IV; "
          f"byte_A100={_read_flag(ql)}) @0x1e80 qsee_read_serial_num")
    _stop(ql)


def _hook_random(ql, *a):
    print(f"[sticky] OP#{_OP['i']} IV-PATH=RANDOM (byte_A100={_read_flag(ql)}) "
          f"@0x1e40 qsee_prng_getdata")
    _stop(ql)


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((CMD_BASE, "cmd_buf"), (RSP_BASE, "rsp_buf")):
        try:
            ql.mem.map(base, REGION, info=f"[bksecapp_sticky] {name}")
        except Exception as e:
            ql.log.warning(f"[bksecapp_sticky] map {name} @ {hex(base)}: {e}")
    # observe which IV source the REAL BkWrapInner branch selects
    ql.hook_address(_hook_serial, VA_SERIAL_IV)
    ql.hook_address(_hook_random, VA_RANDOM_IV)
    print(f"[bksecapp_sticky] init: hooks @0x1e80(serial)/0x1e40(random); "
          f"byte_A100 init={_read_flag(ql)}")


def _build_cmd(cmd_id, plen=0x10):
    buf = bytearray(REGION)
    struct.pack_into("<I", buf, 0, cmd_id)        # scratch_cmd[0..4] = cmd_id
    struct.pack_into("<I", buf, 4, plen)          # REQ[0..3] = wrap length (<=0x100, !=0)
    buf[8:8 + plen] = bytes(range(plen))          # REQ[4..]  = plaintext
    return bytes(buf)


def place_input_callback(ql: Qiling, input: bytes, idx: int):
    # op index: mc-replay passes the op# as idx; single-replay passes -1.
    _OP["i"] = idx if idx is not None and idx >= 0 else _OP["i"] + 1
    # cmd_id comes from the record (rec[0..4]); default to cmd 29.
    cmd_id = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else CMD_WRAP

    ql.mem.write(CMD_BASE, _build_cmd(cmd_id))
    ql.mem.write(RSP_BASE, bytes(REGION))

    setup_params_fuzz(ql, cmd_id, 0,
                      [NoneParam(), NoneParam(), NoneParam(), NoneParam()])
    ql.arch.regs.x0 = CMD_BASE
    ql.arch.regs.x1 = CMDLEN
    ql.arch.regs.x2 = RSP_BASE
    ql.arch.regs.x3 = CMDLEN
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[sticky] === OP#{_OP['i']} cmd={cmd_id} "
          f"byte_A100(before)={_read_flag(ql)} ===")
    return True
