# from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === xiaomi_tam (655a4b46) — Xiaomi Trusted App Manager (OTrP/TEEP) =========
# Staged build sha 6411a55e… (klee). Dispatch RE'd from the staged .ta:
#   TA_InvokeCommandEntryPoint @0x300d8:
#     a1=w20=cmd_id, a2=w19=paramTypes, a3=x21=&params.
#     GATE: cmp w19,#0x2615 (paramTypes==0x2615) ; b.ne -> NOT_SUPPORTED.
#       cbz w20 (cmd_id MUST be 0) else NOT_SUPPORTED.
#       0x2615 nibbles = p0=MEMREF_INPUT(5), p1=VALUE_INPUT(1),
#                        p2=MEMREF_OUTPUT(6), p3=VALUE_OUTPUT(2).
#     param0.buffer (x0=[x21]) -> json_loads(buf,0,&err) @0x463a8 ->
#       json_object_iter / iter_key (first JSON key) -> OTrP_handle_message.
#   GlobalConfusion: NOT applicable — paramTypes==0x2615 pins p0 to a memref
#     before deref. The ONLY unauthenticated surface is the Jansson parse +
#     first-key extraction (install/update/delete need a JWS x5c chain that
#     verifies against a CA in TEE storage we don't hold).
#
# HUNT: json_loads expects a NUL-terminated C string. If the param buffer is
#   not NUL-terminated within `size`, Jansson over-reads past the REE buffer.
#   We pass param0 size == len(json) with NO trailing NUL so the redzone
#   (asan) catches any over-read past the buffer == pre-auth OOB read.
#
# Modes:
#   J655_NULTERM=1  -> append a NUL inside the buffer (benign, for valid-shape runs)
#   J655_FIRSTKEY=<key> -> wrap AFL bytes as {"<key>": <afl-json>} to drive the
#                          first-key dispatch into a chosen OTrP handler.
#   default: raw AFL input is the JSON buffer (over-read hunt + parser fuzz).

NULTERM = "J655_NULTERM" in os.environ
RAW = "J655_RAW" in os.environ          # pass AFL bytes verbatim as JSON (over-read hunt)
FIRSTKEY = os.environ.get("J655_FIRSTKEY")
PTYPES = 0x2615
CMD = 0

VALID_KEYS = [b"GetDeviceTEEStateTBSRequest", b"CreateSDTBSRequest",
              b"InstallTATBSRequest", b"UpdateRootCaRequest",
              b"DeleteTATBSRequest", b"TBSRequest"]


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        return False
    if RAW:
        jbuf = input            # verbatim — for the json_loads NUL-over-read hunt
    elif FIRSTKEY is not None:
        key = FIRSTKEY.encode()
        # build a JSON object whose first key is `key`; value carries AFL bytes
        # (as a JSON string, escaped) so the per-request parser sees attacker data
        payload = input.replace(b"\\", b"\\\\").replace(b'"', b'\\"')
        payload = bytes(b for b in payload if 0x20 <= b < 0x7f)
        jbuf = b'{"' + key + b'":"' + payload + b'"}'
    else:
        # raw AFL bytes as the JSON document (parser + over-read hunt). Bias the
        # first byte toward a valid leading key so AFL reaches OTrP dispatch.
        if input[0] < 0x80 and len(input) > 4:
            k = VALID_KEYS[input[0] % len(VALID_KEYS)]
            jbuf = b'{"' + k + b'":' + input[1:] + b'}'
        else:
            jbuf = input
    body = jbuf + (b"\x00" if NULTERM else b"")
    size = len(body)
    print(f"[655a] cmd=0 paramTypes=0x2615 json_len={len(jbuf)} nulterm={NULTERM} buf[:40]={jbuf[:40]!r}")
    command_params = [
        MemRefParam(body, size),          # param0 MEMREF_INPUT (redzoned) = JSON
        ValueParam(0, 0),                 # param1 VALUE_INPUT
        MemRefParam(bytes(0x2000), 0x2000),  # param2 MEMREF_OUTPUT (response JSON)
        ValueParam(0, 0),                 # param3 VALUE_OUTPUT
    ]
    setup_fuzz(ql, CMD, PTYPES, command_params, input)
    return True
