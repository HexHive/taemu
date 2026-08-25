from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === micrtk (8aaaf201-2460-0000-23f21637c175b4d4) structure-aware fuzz =====
# Xiaomi MiTEE device-key ECDSA-P256 signer ("Micrtk"). Staged misa-style.
#
# ABI (re-derived from the binary @0x231B0):
#   paramTypes==0x65 @0x23204 (GC-safe, BEFORE any buffer deref).
#   Split: `mvn w8,cmd; tst w8,#0xff00; b.ne 0x23294`  =>
#     - PUBLIC path (cmd byte1 != 0xFF, i.e. 0x80xx) @0x23294: requires
#       params[0].size==0x2000 (INPUT) AND params[1].size==0x1000 (OUTPUT);
#       input u32 "cmd_len" at IN+8 must be < 0x1FF1.   <-- emulator-reachable, UNAUTH
#     - INTERNAL path (0xFFxx) @0x23218/0x23240: NO size precondition; gated by
#       is_ta_sign_allowed (gpd.client.identity == TRUSTED_APP + UUID ACL @0x77000).
#       NOT reachable w/o modeling the client identity (default = TEE_LOGIN_PUBLIC).
#
#   Public cmd jump table @0x23374 (idx bytes @0x1680): 0x8001 get_fid->0x27210,
#     0x8002 get_version->?, 0x8003 cert_validity->0x277D0, 0x8004 data_prepare->0x27A58,
#     0x8005 data_load->0x28110.
#   Public handler ABI: x0 = OUTPUT.buf+0x10, x1 = OUTPUT.buf+8 (writes result);
#     INPUT.buf + its u32 cmd_len@+8 carry the request body.
#
# cmd_data_load (0x8005) is the richest parser (AES-CBC + PKCS7 + TLV) BUT the
# AES-decrypt/TLV walk is gated behind root_verify_sha256 (bl @0x28280) against a
# hardcoded preload-root EC-P256 pubkey -> unreachable w/o Xiaomi preload-key
# control; only the pre-verify length checks (sig==0x40 @+4, IV==0x10 @+0x48,
# cipher_len = cmd_len-0x9c %16==0) run on attacker bytes, all in-bounds (<0x2000).
#
# STRATEGY: drive all 5 public cmds; mutate the input header (cmd_len) and the
# data-load length fields (the pre-sig-verify ones). asan redzones on the 0x2000
# INPUT + 0x1000 OUTPUT catch any OOB the bounds miss.

PTYPES = 0x65
INSZ  = 0x2000     # param0 INPUT  (redzoned) -- REQUIRED ==0x2000
OUTSZ = 0x1000     # param1 OUTPUT (redzoned) -- REQUIRED ==0x1000

PUB_CMDS = [0x8001, 0x8002, 0x8003, 0x8004, 0x8005]

def u32(x): return struct.pack("<I", x & 0xFFFFFFFF)
def u32be(x): return struct.pack(">I", x & 0xFFFFFFFF)

def build_input(cmd_len=0x100, body=b""):
    # input layout: the public path reads a u32 "cmd_len" at IN+8 (< 0x1FF1).
    # The 0x10-byte-ish header then body. We keep IN[0:8] zero, cmd_len@8.
    hdr = b"\x00"*8 + u32(cmd_len) + b"\x00"*4
    buf = hdr + body
    return buf[:INSZ].ljust(INSZ, b"\x00")

def build_dataload_body(cmd_len=0xB0):
    # cmd_data_load pre-sig-verify length fields (BE via read_u32BE @0x2a058):
    #   [u32 BE cipher_len @ +0][... sig(0x40) ...][u32 BE 0x40 @ +0x44? actually
    #    code reads +4 ==0x40, +0x48 ==0x10]. We satisfy the shape so the parser
    #   advances to root_verify (which then fails gracefully -> no OOB).
    # cmd_len must be >0x9b and (cmd_len-0x9c)%16==0. 0xB0-0x9c=0x14 (not /16) -> use 0xAC: 0xAC-0x9c=0x10 (/16 ok)
    body  = u32be(0x40)            # +0 (a length field read first)
    body += u32be(0x40)            # +4 == 0x40 (sig len) REQUIRED
    body += b"S"*0x40              # +8 sig bytes (will fail verify)
    body += u32be(0x10)            # +0x48 == 0x10 (IV len) REQUIRED
    body += b"I"*0x10              # IV
    body += b"C"*0x10              # 1 ciphertext block
    return body

FORCE = os.environ.get("MK_MODE")   # "get_fid","get_version","cert_validity","prepare","data_load","gc"
FORCE_CMD = os.environ.get("MK_CMD")
FORCE_CLEN = os.environ.get("MK_CLEN")

def _forced():
    cmd_map = {"get_fid":0x8001,"get_version":0x8002,"cert_validity":0x8003,
               "prepare":0x8004,"data_load":0x8005}
    if FORCE in cmd_map:
        cmd = cmd_map[FORCE]
        clen = int(FORCE_CLEN,0) if FORCE_CLEN else (0xAC if cmd==0x8005 else 0x100)
        body = build_dataload_body(clen) if cmd==0x8005 else b"\x00"*0x80
        return cmd, build_input(clen, body)
    if FORCE_CMD:
        cmd = int(FORCE_CMD,0)
        clen = int(FORCE_CLEN,0) if FORCE_CLEN else 0x100
        return cmd, build_input(clen, b"\x00"*0x80)
    return None

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if FORCE == "gc":
        # GlobalConfusion probe: param0 -> VALUE poison. paramTypes!=0x65? no, we keep
        # 0x65 but pass a VALUE in slot0; the entry checks paramTypes==0x65 only (it does
        # NOT re-check each slot's type), so a VALUE in slot0 is read as {a,b}; the public
        # path then does ldr x25,[x23] = p0.buf = (in this emu) the VALUE's storage ptr...
        # Real test: does it deref p0.buf before validating? It reads [x23] (the param
        # struct slot), which the emu fills with the value inline -> not an attacker ptr.
        poison = 0x4142434445
        command_params = [ValueParam(poison & 0xFFFFFFFF, (poison>>32)&0xFFFFFFFF),
                          MemRefParam(bytes(OUTSZ), OUTSZ), NoneParam(), NoneParam()]
        setup_params_fuzz(ql, 0x8005, PTYPES, command_params)
        print("[MK] GC-probe param0=VALUE")
        return True

    forced = _forced()
    if forced is not None:
        cmd, inbuf = forced
    else:
        if len(input) < 2:
            return False
        cmd = PUB_CMDS[input[0] % len(PUB_CMDS)]
        # mutate cmd_len from input[1:5]; bias into the valid window for data_load
        if len(input) >= 5:
            clen = struct.unpack_from("<I", input, 1)[0]
        else:
            clen = 0x100
        if cmd == 0x8005:
            # keep in the (0x9b, 0x1FF1) window and mostly 16-aligned-after-0x9c
            clen = 0x9c + 0x10 + (clen % 0x800 & ~0xF)
            body = build_dataload_body(clen)
        else:
            clen = (clen % 0x1FF0)
            body = (input[5:] + b"\x00"*0x80)[:0x80]
        inbuf = build_input(clen, body)

    print(f"[MK] cmd={cmd:#x} cmd_len={struct.unpack_from('<I',inbuf,8)[0]:#x} "
          f"(IN redzoned 0x{INSZ:x}, OUT 0x{OUTSZ:x})")
    command_params = [
        MemRefParam(inbuf, INSZ),           # param0 INPUT
        MemRefParam(bytes(OUTSZ), OUTSZ),   # param1 OUTPUT
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
