from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === gatekeeper (4d573443) structure-aware fuzz harness ================
# Target: klee MiTEE gatekeeper 4d573443-6a56-4272-ac6f2425af9ef9bb.
#
# ABI (re-derived from the binary, NOT the lapis IN+8 family):
#   TA_InvokeCommandEntryPoint @0x203C0. paramTypes==0x65 checked @0x20430 BEFORE
#   any params[i].buffer deref (GlobalConfusion-safe). cmd-id {0,1,2,3} via jump
#   table @0x204a8. Handlers parse DIRECTLY from params[0].buffer; bound = p0.size.
#     param0 = MEMREF_INPUT  (request)   [x26]   size [x26+8]
#     param1 = MEMREF_OUTPUT (response)  [x26+0x10] size [x26+0x18]
#
# Wire formats (from RE doc + disasm):
#   cmd0 ENROLL  : {u32 uid, u32 cur_phdl_len, u8 phdl[], u32 cur_pw_len, u8 pw[],
#                   u32 new_pw_len, u8 pw[]}
#                  - cur_phdl_len==0 => first-enroll (gen random SID); ==58 => verify+reuse SID.
#   cmd1 VERIFY  : {u32 uid, u64 challenge, u32 phdl_len(==58), u8 phdl[58],
#                   u32 provided_pw_len, u8 pw[]}
#   cmd2 DELETE_USER : {u32 uid}
#   cmd3 DELETE_ALL  : {} (unauthenticated)
#
# STRUCTURE-AWARE STRATEGY: craft a VALID frame, then mutate the embedded length
# fields (cur_phdl_len/cur_pw_len/new_pw_len/phdl_len/provided_pw_len) -- the asan
# param-redzones (req buf @0xbbbb*, resp buf @0xbbbc*) catch any OOB the dense
# length-walk parser misses. AFL byte0 selects the mode; the rest mutate lengths.

PTYPES = 0x65
REQSZ  = 0x1000        # param0 INPUT (redzoned)
RESPSZ = 0x1000        # param1 OUTPUT (redzoned)

CMD_ENROLL = 0
CMD_VERIFY = 1
CMD_DELUSER = 2
CMD_DELALL = 3

def u32(x): return struct.pack("<I", x & 0xFFFFFFFF)
def u64(x): return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

# ---- valid-frame builders (lengths overridable for mutation) ----
def build_enroll(uid=1000, cur_phdl_len=None, cur_phdl=b"", cur_pw_len=None,
                 cur_pw=b"", new_pw_len=None, new_pw=b"1234"):
    cur_phdl_len = len(cur_phdl) if cur_phdl_len is None else cur_phdl_len
    cur_pw_len   = len(cur_pw)   if cur_pw_len   is None else cur_pw_len
    new_pw_len   = len(new_pw)   if new_pw_len   is None else new_pw_len
    b  = u32(uid)
    b += u32(cur_phdl_len) + cur_phdl
    b += u32(cur_pw_len)   + cur_pw
    b += u32(new_pw_len)   + new_pw
    return b

def build_verify(uid=1000, challenge=0x4141414142424242, phdl_len=None,
                 phdl=None, pw_len=None, pw=b"1234"):
    # default phdl: 58-byte v2 handle (version=2 byte, then 8+8+8 + 1 + 32)
    if phdl is None:
        phdl = bytes([2]) + u64(0xdead) + u64(0) + u64(0) + bytes([1]) + b"\x00"*32
        assert len(phdl) == 58, len(phdl)
    phdl_len = len(phdl) if phdl_len is None else phdl_len
    pw_len   = len(pw)   if pw_len   is None else pw_len
    b  = u32(uid)
    b += u64(challenge)
    b += u32(phdl_len) + phdl
    b += u32(pw_len)   + pw
    return b

FORCE = os.environ.get("GK_MODE")     # "enroll_first","enroll_phdl","verify","delall","gc"

def _frame_from_afl(inp):
    """Map an AFL input to (cmd, request_bytes). byte0 picks mode; bytes 1.. mutate
    the length fields inside an otherwise-valid frame."""
    if len(inp) < 1:
        return None
    mode = inp[0] % 6
    rest = inp[1:]
    def w(i, default):  # read a u32 from rest at slot i, else default
        off = i*4
        if len(rest) >= off+4:
            return struct.unpack_from("<I", rest, off)[0]
        return default

    if mode == 0:   # ENROLL first-enroll (cur_phdl_len==0); mutate new_pw_len
        return CMD_ENROLL, build_enroll(cur_phdl_len=0, new_pw_len=w(0, 4), new_pw=b"1234")
    if mode == 1:   # ENROLL first-enroll; mutate cur_pw_len (should be bounded)
        return CMD_ENROLL, build_enroll(cur_phdl_len=0, cur_pw_len=w(0, 0), new_pw=b"1234")
    if mode == 2:   # ENROLL with cur_phdl present: mutate cur_phdl_len (verify path)
        return CMD_ENROLL, build_enroll(cur_phdl_len=w(0, 58), cur_phdl=b"\x02"+b"\x00"*57,
                                        cur_pw=b"1234", new_pw=b"5678")
    if mode == 3:   # VERIFY: mutate phdl_len
        return CMD_VERIFY, build_verify(phdl_len=w(0, 58), pw_len=w(1, 4))
    if mode == 4:   # VERIFY: mutate provided_pw_len (bounded against p1.size)
        return CMD_VERIFY, build_verify(pw_len=w(0, 4))
    # mode 5: DELETE_USER / DELETE_ALL alternation
    if (inp[0] & 0x40):
        return CMD_DELALL, b""
    return CMD_DELUSER, u32(w(0, 1000))

def _forced():
    if FORCE == "enroll_first":
        nl = int(os.environ.get("GK_NEWPWLEN", "4"), 0)
        return CMD_ENROLL, build_enroll(cur_phdl_len=0, new_pw_len=nl, new_pw=b"1234")
    if FORCE == "enroll_cpw":
        cl = int(os.environ.get("GK_CURPWLEN", "0"), 0)
        return CMD_ENROLL, build_enroll(cur_phdl_len=0, cur_pw_len=cl, new_pw=b"1234")
    if FORCE == "enroll_phdl":
        pl = int(os.environ.get("GK_PHDLLEN", "58"), 0)
        return CMD_ENROLL, build_enroll(cur_phdl_len=pl, cur_phdl=b"\x02"+b"\x00"*57,
                                        cur_pw=b"1234", new_pw=b"5678")
    if FORCE == "verify":
        pl = int(os.environ.get("GK_PHDLLEN", "58"), 0)
        pw = int(os.environ.get("GK_PWLEN", "4"), 0)
        return CMD_VERIFY, build_verify(phdl_len=pl, pw_len=pw)
    if FORCE == "delall":
        return CMD_DELALL, b""
    return None

def place_input_callback(ql: Qiling, input: bytes, _: int):
    forced = _forced()
    if forced is not None:
        cmd, req = forced
    else:
        r = _frame_from_afl(input)
        if r is None:
            return False
        cmd, req = r

    # GlobalConfusion probe (separate mode): flip param0 to VALUE w/ poison ptr.
    if FORCE == "gc":
        poison = 0x4142434445
        command_params = [
            ValueParam(poison & 0xFFFFFFFF, (poison >> 32) & 0xFFFFFFFF),
            MemRefParam(bytes(RESPSZ), RESPSZ),
            NoneParam(), NoneParam(),
        ]
        setup_params_fuzz(ql, CMD_ENROLL, PTYPES, command_params)
        print("[GK] GC-probe: param0=VALUE poison=0x4142434445 (expect REJECT @paramTypes gate)")
        return True

    req = req[:REQSZ].ljust(min(len(req), REQSZ), b"\x00")
    print(f"[GK] cmd={cmd} reqlen={len(req)} (req buf redzoned 0x{REQSZ:x}, resp 0x{RESPSZ:x})")
    command_params = [
        MemRefParam(req, REQSZ),            # param0 INPUT (request)
        MemRefParam(bytes(RESPSZ), RESPSZ), # param1 OUTPUT (response)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
