# Generic mutational fuzz harness for skm (000000534b4d), shipping SFDZE1.
# Dispatcher RE (objdump of teegris/tas/skm_sfdze1/...534b4d.ta):
#   TA_InvokeCommandEntryPoint @0x19e58 -> skm_invoke_acl_check @0x1ba94 (RETURN-0
#   stub on this build) -> param_types low nibble == 7 gate (0x19ed8 and w8,w22,#0xf;
#   0x19edc cmp w8,#7; b.ne -12002) -> TEES_IsREESharedMemory -> request parse
#   @0x408bc -> inner dispatcher skm_taCmdExecute @0x19320 (binary-search over a
#   32-bit REE cmd id). Request framing: param[0] = [u32 cmd_id][payload...] (the
#   inner dispatcher reads the cmd id from the request and recurses skm_tlvGet
#   @0x2460c over the payload — <tag:u8><len:u16><value> TLV).
# Cmd ids extracted from the 0x19320 ladder: 0x1b3,0x1b4 (small),0xab07 (DRK
#   probe),0xb810,0xb811,0xb914,0xba17,0xbb18,0xbb19,0xbb20,0xbb21,0xbc23.
# KNOWN finding (RE/triage/teegris_midtier_hunt.md): DER-decoder OOB stack write
#   sub_16040 @0x16224/0x16378, reached via getDrkCertificate/readDrkCertificateUID
#   behind skm_openSecureObject -> TEES_CheckSecureObjectCreator x2 +
#   TEES_UnwrapSecureObject (AEAD). In THIS emulator those are no-op return-0/1
#   stubs (teegris_api.py), so the "unwrapped plaintext" buffer keeps the REE bytes
#   -> the DER decoder parses REE-controlled bytes (the AEAD gate is bypassed
#   in-emu). So a crash at 0x16224/0x16378 = DEDUP of the KNOWN gated bug; the
#   NEW-bug target is a crash on a DIRECT path (skm_tlvGet, or a cmd whose TLV/len
#   parse is not behind UnwrapSecureObject). param[0]/[1] are redzoned (params.py)
#   so OOB read past req size / OOB write past resp trips CRASH_PC.
from .params import *
from qiling import Qiling
import struct

GATE_PTYPES = 0x7  # param[0] MEMREF (low nibble 7). vary other nibbles for 2nd memref.
PTYPES_CHOICES = [0x7, 0x77, 0x17, 0x67, 0x57, 0x75, 0x77]
# bias to the DRK-cert / SO-unwrap cmds (the DER-decoder reachers) + the small
# ids + the direct readDrk; keep a couple of unknowns for the "else" arm.
CMDS = [0xbb20, 0xbb21, 0xbb19, 0xbb18, 0xbc23, 0xb810, 0xb811, 0xb914, 0xba17,
        0xab07, 0x1b3, 0x1b4, 0x1, 0x2]
REQ_SIZES = [0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x4, 0x8, 0x1000, 0x2000]
RSP_SIZES = [0x100, 0x100, 0x200, 0x40, 0x20, 0x400, 0x10, 0x8, 0x1000, 0x80]
MAXBUF = 0x2200


def _make_tlv(body: bytes, n: int) -> bytes:
    # skm_tlvGet @0x2460c envelope (verified by objdump): <0xFE start><u16
    # total_len LE><records...>, gated `total_len + 3 <= req_size` (0x24658). Each
    # record (walk @0x24724) is <tag:u8><len:u16 LE><value> with the running offset
    # advanced by (len + 3) — the offset-arith bug target (declared len may exceed
    # the bytes actually present). Build n records into the body, then wrap with the
    # 0xFE envelope so the parser passes its start-byte/total-len gates and reaches
    # the record walk. Bias total_len to a value that passes the gate most of the
    # time but sometimes overshoots (probe).
    recs = bytearray()
    off = 0
    for _ in range(n):
        if off + 3 > len(body):
            break
        tag = body[off]; off += 1
        ln = struct.unpack_from('<H', body, off)[0]; off += 2
        # emit value bytes (clamped to what's left) but keep DECLARED len untouched
        val = body[off:off + (ln & 0x1FF)]; off += len(val)
        recs += bytes([tag]) + struct.pack('<H', ln) + val
    # total_len: 5/8 = actual record bytes (passes gate); 3/8 = an over/under value
    # drawn from the body (probe the total_len + 3 <= req_size gate edge).
    if body and (body[0] & 0xE0) == 0xE0 and len(body) >= 3:
        total_len = struct.unpack_from('<H', body, 1)[0]
    else:
        total_len = len(recs)
    return b'\xfe' + struct.pack('<H', total_len & 0xFFFF) + bytes(recs)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    ptypes = PTYPES_CHOICES[input[1] % len(PTYPES_CHOICES)]
    req_size = min(REQ_SIZES[input[2] % len(REQ_SIZES)], MAXBUF)
    rsp_size = min(RSP_SIZES[input[3] % len(RSP_SIZES)], MAXBUF)
    tlv_n = (input[4] % 8) + 1
    body = input[8:]

    # build the request buffer. SFDZE1 entry framing (TA_InvokeCommandEntryPoint
    # @0x19fa8): param[0].size must be > 7; then [u32 cmd_id][u32 inner_len][payload],
    # with `inner_len + 8 <= param[0].size` (0x19fe8) AND `inner_len <= 0x2000`
    # (0x19ff4), else -12003. memcpy(stack, param[0]+8, inner_len) then
    # skm_taCmdExecute(cmd_id, payload, inner_len). The payload is recursed by
    # skm_tlvGet @0x2460c as <tag:u8><len:u16><value> TLV.
    payload = _make_tlv(body, tlv_n)
    # honest framing 7/8; 1/8 corrupt inner_len to probe the framing gate itself.
    if (input[1] & 0xE0) == 0xE0:
        inner_len = struct.unpack_from('<H', (body[:2].ljust(2, b'\x00')))[0]
    else:
        inner_len = min(len(payload), max(0, req_size - 8), 0x2000)
    req = bytearray(struct.pack('<I', cmd & 0xFFFFFFFF) +
                    struct.pack('<I', inner_len & 0xFFFFFFFF) + payload)
    # ensure param[0].size accommodates the framing (>7 and >= inner_len+8)
    req_size = max(req_size, inner_len + 8, 8)
    req_size = min(req_size, MAXBUF)
    if len(req) < req_size:
        req = req.ljust(req_size, b'\x00')
    else:
        req = req[:req_size]
    req = bytes(req)

    command_params = []
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):
            a = int.from_bytes(body[:4].ljust(4, b'\x00'), 'little')
            command_params.append(ValueParam(a, 0))
        elif pt in (4, 5, 6, 7):
            if i == 0:
                command_params.append(MemRefParam(req, req_size))
            elif pt == 5:  # out only
                command_params.append(MemRefParam(b'\x00' * rsp_size, rsp_size))
            else:
                command_params.append(MemRefParam(b'\x00' * rsp_size, rsp_size))
        else:
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
