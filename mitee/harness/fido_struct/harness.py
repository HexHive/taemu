#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === NEW-BUG hunt: structure-aware mutational fuzz of fido_ctap CTAP frames ===
# Stays inside a well-formed GP-invoke + CTAP envelope and mutates the CBOR map
# contents (keys, element types, lengths, listSize, nested maps) so the parser is
# always reached, but the *structure* varies -- targeting parser bugs beyond F9.
#
# Frame: param0 = [authsel][ctap_cmd][CBOR map]. GP cmd_id=0 (case 0 -> CTAP_Process),
#   paramTypes 0x65, out>0x7F. authsel/ctap_cmd/CBOR all drawn from AFL input so the
#   fuzzer explores the whole CTAP2 + vendor command surface and the psk/credential
#   CBOR grammar. listSize kept moderate (<=64) so we don't just re-find F9; we want
#   DIFFERENT crashes (type confusion, nested-map overflow, off-by-one).

PTYPES = 0x65
OUTSZ = 0x608
# CTAP command bytes worth exercising (psk + credential + standard CTAP2)
CMDS = [0x01, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x50, 0x51, 0x60, 0x61, 0x70, 0x71]
AUTHSEL = [0x00, 0x01, 0x02, 0x09, 0x0F]

def _cbor_len(major, n):
    if n < 24: return bytes([major | n])
    if n < 0x100: return bytes([major | 24, n])
    if n < 0x10000: return bytes([major | 25]) + struct.pack(">H", n)
    return bytes([major | 26]) + struct.pack(">I", n)

def _cbor_elem(b):
    # build a small CBOR element chosen by a byte: bstr/tstr/uint/array/map/bool
    t = b & 7
    if t == 0: return b"\x40"                      # empty byte-string
    if t == 1: return bytes([0x41, b])             # 1-byte byte-string
    if t == 2: return bytes([0x60])                # empty text-string
    if t == 3: return bytes([(b % 24)])            # small uint
    if t == 4: return bytes([0x80])                # empty array
    if t == 5: return bytes([0xA0])                # empty map
    if t == 6: return bytes([0xF4 + (b & 1)])      # false/true
    return bytes([0x41, b])

def _build(data):
    # data drives: authsel, cmd, map_len, and per-entry (key, value-shape)
    if len(data) < 4:
        data = data + b"\x00" * 4
    authsel = AUTHSEL[data[0] % len(AUTHSEL)]
    cmd = CMDS[data[1] % len(CMDS)]
    nkeys = 1 + (data[2] % 6)                       # 1..6 map entries
    cbor = bytes([0xA0 | nkeys]) if nkeys < 24 else _cbor_len(0xA0, nkeys)
    idx = 3
    for k in range(nkeys):
        keyb = data[idx % len(data)]; idx += 1
        valb = data[idx % len(data)]; idx += 1
        # key: small uint (the parser switches on int keys: 2=credentialIdlist, 9=pskInfo)
        cbor += bytes([keyb % 24])
        if (valb & 7) == 4 or k == 0:
            # value = array of empty byte-strings (the F9-class path) with MODERATE len
            n = 1 + (data[idx % len(data)] % 64); idx += 1
            cbor += _cbor_len(0x80, n) + b"\x40" * n
        elif (valb & 7) == 5:
            # value = nested map of 1..4 int:bstr pairs
            m = 1 + (data[idx % len(data)] % 4); idx += 1
            cbor += bytes([0xA0 | m])
            for _ in range(m):
                cbor += bytes([data[idx % len(data)] % 24]); idx += 1
                cbor += _cbor_elem(data[idx % len(data)]); idx += 1
        else:
            cbor += _cbor_elem(valb)
    return bytes([authsel, cmd]) + cbor

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 4:
        return False
    data = _build(input)
    if len(data) > 0x2800:
        data = data[:0x2800]
    command_params = [
        MemRefParam(data, max(len(data), 0x40)),
        MemRefParam(bytes(OUTSZ), OUTSZ),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0, PTYPES, command_params)
    return True
