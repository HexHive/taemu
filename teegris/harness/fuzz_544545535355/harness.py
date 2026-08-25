# Cert-parser-targeted mutational fuzz harness for teessu (544545535355).
# Goal: drive the hand-rolled X.509/DER parser (cert_parcer.c, x509_certificate_parse
# @0x25230) which is reached by the cert-family commands. Per the dispatcher RE
# (TA_InvokeCommandEntryPoint @0x162d0, param-validator @0x16b94):
#   cmd 0x52 (handler 0xee40): ptypes=0x605 (p0 MEMREF_INPUT, p2 MEMREF_OUTPUT),
#       p0.size <= 0x10c -> SHORTEST attacker-data->parser path (depth 4). PRIMARY.
#   cmd 0xaa (handler 0x11cb4): ptypes=0x605, p0.size<=0x10c (same depth-4 path).
#   cmd 0x68 (handler 0xe6a4):  ptypes=0x65  (p0 MEMREF_INPUT, p1 MEMREF_OUTPUT), p0.size<=0x10c.
#   cmd 0x3f (handler 0x10ab0): ptypes=0x65, p0.size<=0x22 (small).
#   cmd 0x79 (handler 0xf5d8):  ptypes=0x15  (p0 MEMREF_INPUT, p1 VALUE_INPUT).
#   cmd 0x92 (handler 0xbb58):  ptypes=0x60  (p1 MEMREF_OUTPUT only).
# The validator also does TEE_CheckMemoryAccessRights(READ,p0) / (WRITE,p1/p2);
# the params are redzoned (params.py) so an OOB read past p0.size (DER over-read)
# or OOB write past the response trips CRASH_PC.
from .params import *
from qiling import Qiling
import struct

# cmd -> expected paramTypes word (GP nibble-encoded), from dispatcher RE.
CMD_PTYPES = {
    0x52: 0x605,
    0xaa: 0x605,
    0x68: 0x65,
    0x3f: 0x65,
    0x79: 0x15,
    0x92: 0x60,
}
# bias the cert-parser-richest cmds (0x52/0xaa/0x68 carry the DER blob in p0)
CMDS = [0x52, 0x52, 0x52, 0xaa, 0xaa, 0x68, 0x68, 0x3f, 0x79, 0x92]
# p0 (DER blob) size gate is EXACT (validator @0x17010: p0.size == gate_exact,
# else "Incorrect parameters3. in:%x, exp:%x"). For cmd 0x52/0xaa/0x68 the exact
# gate is 0x10c; cmd 0x3f is 0x22. Bias the exact values heavily (else coverage
# stays ~0), plus a few off-by-one probes of the size check itself.
SIZE_CHOICES = [0x10c, 0x10c, 0x10c, 0x10c, 0x10c, 0x10c, 0x22, 0x22, 0x10b, 0x10d, 0x21, 0x23]
# per-cmd exact p0.size gate (validator EXACT slot); used when the cmd is one of
# these so the gate is hit deterministically most of the time.
CMD_P0SIZE = {0x52: 0x10c, 0xaa: 0x10c, 0x68: 0x10c, 0x3f: 0x22}
OUT_SIZE = 0x1000   # generous output buffer (no validator size gate on outputs)


def _u32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    sel = input[1]
    # 7/8 use the correct gate ptypes (reach the handler); 1/8 raw-fuzz the
    # ptypes word to probe the validator itself.
    if (sel & 0xE0) == 0xE0:
        ptypes = struct.unpack_from('<H', input, 4)[0]
    else:
        ptypes = CMD_PTYPES[cmd]
    szsel = input[2]
    # 6/8 of the time use the cmd's exact gate (deterministically pass the size
    # check); else draw from SIZE_CHOICES to probe off-by-one / wrong sizes.
    if (szsel & 0xC0) != 0xC0 and cmd in CMD_P0SIZE:
        p0size = CMD_P0SIZE[cmd]
    else:
        p0size = SIZE_CHOICES[szsel % len(SIZE_CHOICES)]
    body = input[6:]                       # DER/cert blob bytes
    der = bytes(body[:p0size]).ljust(p0size, b'\x00')

    command_params = []
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):                # VALUE_*
            a = struct.unpack_from('<H', input, 4)[0] if len(input) >= 6 else 0
            command_params.append(ValueParam(a, 0))
        elif pt == 5:                      # MEMREF_INPUT -> the DER blob in p0
            if i == 0:
                command_params.append(MemRefParam(der, p0size))
            else:
                command_params.append(MemRefParam(der, p0size))
        elif pt in (6, 7):                 # MEMREF_OUTPUT / INOUT
            command_params.append(MemRefParam(b'\x00' * OUT_SIZE, OUT_SIZE))
        else:
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
