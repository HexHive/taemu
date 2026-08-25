from .params import *
from qiling import Qiling
import struct, os

# === storsec (Samsung S24 secure-storage broker) structure-aware fuzz harness =
# Target: Samsung S24 Ultra (SM-S928B) Storsecapp QTEE TA, storsec.ta
#         (qcom.tz.storsecapp). UNREPORTED.
#
# Staging (see storsec.json): GP lifecycle stubbed (returns TEE_SUCCESS);
# InvokeCommand points DIRECTLY at the StorsecApp command handler @0x108.
# Handler ABI (confirmed by disassembly of the prologue @0x108):
#   x0 = req_ptr   (!= NULL, @0x124)
#   w1 = req_len   (must be > 0xb,  @0x134 "Request length too small")
#   x2 = resp_ptr  (!= NULL, @0x12c)
#   w3 = resp_len  (must be > 0xf,  @0x170 "Response length too small")
# cmd = BE32(req[0..4])  (@0x184-0x1a4):
#   0 = CMD_SET_SECURE_WP_CONFIG  -> @0x1b4
#   1 = CMD_GET_SECURE_WP_CONFIG  -> @0x204
#   else "Unsupported command"
# Each cmd:
#   * req_len >= 0x3a                                  (@0x1c4 / @0x218)
#   * innerLen = LE32(req[8..0xc])                     (@0x1cc / @0x220)
#   * (req_len - 0x3a) >= innerLen   else "Invalid request length"
# SET: qsee_stor_write_wp_config(x0 = req + innerLen)  (@0x290..0x2d0)
# GET: resp_len >= 0x4a (@0x2dc); reads req[innerLen] (1 byte, in-bounds);
#      qsee_stor_read_wp_config(x0 = resp) (@0x2ec..0x334); ret -> BE32 resp[4..8]
#
# All copy lengths/pointers in the handler are derived from these checked fields,
# so the static read says BOTH commands are bounded. This harness DYNAMICALLY
# confirms that: it lets AFL drive cmd / req_len / resp_len / innerLen / body
# across their FULL ranges (so every bound -- req_len<0xc, req_len<0x3a,
# innerLen>req_len-0x3a, resp_len<0x4a -- is crossable), then watches for an OOB.
#
# Tight OOB detection: the request buffer is placed so it ABUTS an unmapped guard
# page -- req_buf + req_len == end of the mapped req region. Therefore if the
# handler (or the modeled write_wp_config, which reads a WP-config blob from
# x0 = req + innerLen) reads/writes past the claimed req_len it faults on the
# guard -> the emulator reports an AFL crash. Likewise resp is guard-abutted at
# resp_buf + resp_len.

AFL_EXIT = 0x13370

# Mapped regions. We keep a generous mapping but place the live request/response
# at the TOP so any over-access crosses the (unmapped) end-of-region guard.
REQ_REGION  = 0x51000000
RESP_REGION = 0x52000000
REGION_MAP  = 0x4000          # 16 KiB mapped per region (1 guard page beyond)
GUARD_PAD   = 0x1000          # keep at least this much unmapped right after

# field offsets within the request the handler parses
CMD_OFF   = 0x00             # BE32 command id
INNER_OFF = 0x08             # LE32 inner length (req[8..0xc])

# Deterministic single-seed override (valid SET request, success path):
FORCE_CMD     = os.environ.get("SS_CMD")        # "0"/"1"/hex
FORCE_REQLEN  = os.environ.get("SS_REQLEN")
FORCE_RESPLEN = os.environ.get("SS_RESPLEN")
FORCE_INNER   = os.environ.get("SS_INNER")


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((REQ_REGION, "req"), (RESP_REGION, "resp")):
        try:
            ql.mem.map(base, REGION_MAP, info=f"[storsec] {name}")
        except Exception as e:
            ql.log.warning(f"[storsec] map {name} @ {hex(base)}: {e}")
    # --- PAC-strip hook ---------------------------------------------------------
    # storsec's handler (unlike tz_hdm/tz_iccc) is built with ARMv8.3 pointer
    # authentication: the prologue @0x10c is `pacib x30,sp`, error epilogues use
    # `autibsp`, success epilogue @0x364 is `retab`. This unicorn build does not
    # model PAC, so `pacib x30,sp` leaves PC stuck and the run faults at the very
    # 2nd handler instruction. We neutralize PAC the way a no-PAC build would
    # behave: pac*/aut* are NOPs (return-addr unchanged); retaa/retab become a
    # plain `ret` (PC = x30). We pre-scan the exec segment for every PAC opcode
    # so EVERY reachable path (both commands + all error branches) is covered.
    try:
        ta_base = ql.mem.get_lib_base("storsec.ta")
        import struct as _st
        from capstone import Cs as _Cs, CS_ARCH_ARM64 as _A, CS_MODE_LITTLE_ENDIAN as _L
        _PAC_NOP = {"pacia", "pacib", "paciasp", "pacibsp", "paciza", "pacizb",
                    "autia", "autib", "autiasp", "autibsp", "autiza", "autizb",
                    "xpaci", "xpacd", "xpaclri"}
        _PAC_RET = {"retaa", "retab"}
        raw = ql.mem.read(ta_base, 0x1cfc)               # exec LOAD seg
        _md = _Cs(_A, _L)
        _pac_sites = {}
        for ins in _md.disasm(bytes(raw), 0):
            if ins.mnemonic in _PAC_NOP:
                _pac_sites[ta_base + ins.address] = ("nop", ins.size)
            elif ins.mnemonic in _PAC_RET:
                _pac_sites[ta_base + ins.address] = ("ret", ins.size)
        def _pac_strip(ql, addr, size):
            site = _pac_sites.get(addr)
            if site is None:
                return
            kind, isz = site
            if kind == "nop":
                ql.arch.regs.arch_pc = addr + isz          # skip pac*/aut*
            else:  # retaa/retab -> ret
                ql.arch.regs.arch_pc = ql.arch.regs.x30
        ql.hook_code(_pac_strip)
        print(f"[storsec] PAC-strip hook installed: {len(_pac_sites)} sites "
              f"(ta_base={ta_base:#x})")
    except Exception as e:
        print(f"[storsec] PAC-strip hook failed: {e}")
    print(f"[storsec] init: req@{hex(REQ_REGION)} resp@{hex(RESP_REGION)} "
          f"(mapped {hex(REGION_MAP)}, guard-abutted placement)")


def _u32_le(b, off):
    return struct.unpack_from("<I", b, off)[0] if len(b) >= off + 4 else 0


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # ---- decode attacker-controlled fields from the AFL input -----------------
    # Layout of the fuzz input (little-endian control header, then body):
    #   [0:4]  cmd selector       [4:8]  req_len    [8:12] resp_len
    #   [12:16] inner_len         [16:]  request body bytes
    # We map each control field across its full meaningful range so AFL can cross
    # every length/offset bound; the body fills the request payload region.
    if FORCE_CMD is not None:
        cmd     = int(FORCE_CMD, 0) & 0xFFFFFFFF
        req_len = int(FORCE_REQLEN, 0) if FORCE_REQLEN else 0x3a
        resp_len= int(FORCE_RESPLEN, 0) if FORCE_RESPLEN else 0x4a
        inner   = int(FORCE_INNER, 0) if FORCE_INNER is not None else 0
        body    = b"\x41" * 0x200
    else:
        sel       = _u32_le(input, 0)
        req_raw   = _u32_le(input, 4)
        resp_raw  = _u32_le(input, 8)
        inner_raw = _u32_le(input, 12)
        body      = input[16:] if len(input) > 16 else b""
        # cmd: bias toward {0,1} (valid) but allow others (Unsupported branch)
        cmd     = (sel % 4) if (sel & 0xF) < 12 else sel
        # req_len across [0 .. REGION_MAP] so <0xc, <0x3a, and large all reachable
        req_len = req_raw % (REGION_MAP + 1)
        # resp_len across [0 .. REGION_MAP] so <0x10, <0x4a, and large reachable
        resp_len= resp_raw % (REGION_MAP + 1)
        # inner_len across a range that spans the (req_len-0x3a) boundary plus over
        inner   = inner_raw % (REGION_MAP + 1)

    # ---- guard-abutted placement ---------------------------------------------
    # Put the request so req_buf + req_len lands exactly at the end of the mapped
    # region (REQ_REGION+REGION_MAP), i.e. an over-read past req_len faults. Clamp
    # req_len to the mapping so the buffer itself is always fully mapped.
    eff_req_len = min(req_len, REGION_MAP)
    req_buf = REQ_REGION + (REGION_MAP - eff_req_len)
    eff_resp_len = min(resp_len, REGION_MAP)
    resp_buf = RESP_REGION + (REGION_MAP - eff_resp_len)

    # ---- build the request buffer --------------------------------------------
    buf = bytearray(eff_req_len)
    if eff_req_len >= 4:
        # cmd is parsed LITTLE-endian by the handler @0x184-0x1a4 (ldrb req[0]
        # then bfi req[1]<<8|req[2]<<16|req[3]<<24).
        struct.pack_into("<I", buf, CMD_OFF, cmd & 0xFFFFFFFF)      # LE32 cmd
    if eff_req_len >= INNER_OFF + 4:
        struct.pack_into("<I", buf, INNER_OFF, inner & 0xFFFFFFFF)  # LE32 innerLen
    # fill the remainder (from 0xc onward) with body / 'A's so the source the
    # storage primitive reads (req+innerLen) is well-defined.
    fill_start = INNER_OFF + 4
    if eff_req_len > fill_start:
        n = eff_req_len - fill_start
        chunk = (body * ((n // max(len(body), 1)) + 1))[:n] if body else (b"\x41" * n)
        buf[fill_start:fill_start + n] = chunk

    # clear the live windows, then stamp the request
    ql.mem.write(REQ_REGION, b"\x00" * REGION_MAP)
    ql.mem.write(RESP_REGION, b"\x00" * REGION_MAP)
    if eff_req_len:
        ql.mem.write(req_buf, bytes(buf))

    # keep the GP param plumbing satisfied (unused: ABI overridden below)
    setup_params_fuzz(ql, cmd & 0xFFFF, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # handler(x0=req, w1=req_len, x2=resp, w3=resp_len); benign return -> AFL exit.
    # NB: we pass the *claimed* req_len/resp_len (which may exceed eff_*_len only
    # when AFL picks a value > REGION_MAP; in that case the buffer is the full
    # mapping and the >region claim is itself the over-claim we want to test).
    ql.arch.regs.x0  = req_buf
    ql.arch.regs.x1  = req_len & 0xFFFFFFFF
    ql.arch.regs.x2  = resp_buf
    ql.arch.regs.x3  = resp_len & 0xFFFFFFFF
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[storsec] cmd={cmd:#x} req_len={req_len:#x} resp_len={resp_len:#x} "
          f"innerLen={inner:#x} req_buf={req_buf:#x} resp_buf={resp_buf:#x}")
    return True
