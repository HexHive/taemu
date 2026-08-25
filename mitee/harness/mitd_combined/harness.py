from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === MITD combined length-field fuzz: explore nonce_len/pkg_len/extra_len jointly ==
# Target: klee mitd 8aaaf201-…0008, cmd 0x9002 mitd_data_sign @0x21CE0.
# Gate: paramTypes==0x65, params[0].size==0x2000, params[1].size==0x1000.
# Handler: x0=IN+0x10, w1=*(u32*)(IN+8) in_len, x2=OUT+0x10.
#
# Input content (@IN+0x10): [u32 nonce_len][nonce..][u32 pkg_len][pkg..][u32 extra_len][extra..]
# Reads are via sub_23668 (`ldr w0,[x0]`, UNBOUNDED) at content+0 / content+nonce_len+4
#   / content+nonce_len+8+pkg_len. AFL drives all three lengths -> covers BOTH the
#   F10 sum-overflow (OOB write) AND the unbounded-offset OOB read in one campaign.

CMD = 0x9002
PTYPES = 0x65
INSZ = 0x2000
OUTSZ = 0x1000

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 12:
        return False
    nonce_len = struct.unpack_from("<I", input, 0)[0]
    pkg_len   = struct.unpack_from("<I", input, 4)[0]
    extra_len = struct.unpack_from("<I", input, 8)[0]

    # Build content placing the three length fields where the parser reads them, so
    # that for SMALL lengths the layout is internally consistent (lets the parser
    # advance into the copy/malloc path = F10), while LARGE lengths drive the OOB read.
    nb = nonce_len if nonce_len <= 0x40 else 0
    pb = pkg_len   if pkg_len   <= 0x40 else 0
    content = bytearray()
    content += struct.pack("<I", nonce_len) + b"N"*nb
    # place pkg_len at content+nonce_len+4 only when in-bounds, else leave zeros (the
    # read there will be whatever is at that offset; for OOB it faults first).
    off_pkg = 4 + nb if nb == nonce_len else len(content)
    # we just append sequentially for the small/consistent case
    content += struct.pack("<I", pkg_len) + b"P"*pb
    content += struct.pack("<I", extra_len) + b"E"*16

    header = b"\x00"*8 + struct.pack("<I", INSZ - 0x10) + b"\x00"*4
    buf = (header + bytes(content))[:INSZ].ljust(INSZ, b"\x00")
    print(f"[MITD-C] nonce={nonce_len:#x} pkg={pkg_len:#x} extra={extra_len:#x}")
    command_params = [
        MemRefParam(buf, INSZ),
        MemRefParam(bytes(OUTSZ), OUTSZ),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)
    return True
