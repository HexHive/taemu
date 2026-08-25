from .params import *
from qiling import Qiling
import struct, os

# === uefi_sec garnet — QUEFI-NEW-1 cross-device build-presence (VARIANT / PATCHED) ===
#
# garnet's GP SetVariable request builder @0x7d84 (the analogue of the S928B @0x6c4 /
# peridot @0xae4 QUEFI-NEW-1 sink) CLAMPS the DATA copy vs the scratch capacity, so the
# S928B/peridot heap-OOB write is ABSENT. This harness drives the security-relevant
# **clamp + DATA-copy logic** of the real builder (entered at the clamp @0x7e2c, with the
# scratch as a real asan-redzoned qsee_malloc(0x10000) chunk) and shows:
#   - oversized DataSize, clamp ON  -> `subs w22,(cap-used),DataSize; b.hs 0x7e9c` is NOT
#                                      taken -> REJECT path (no DATA copy) -> NO asan crash
#                                      (this is the PATCHED behaviour, on the real binary)
#   - oversized DataSize, CLAMP_OFF -> force the branch to the copy path 0x7e9c -> the real
#                                      DATA copy @0x7eec runs DataSize bytes into the scratch
#                                      -> OOB past scratch+0x10000 -> asan CRASH_PC
#                                      (positive control: the detector works AND the clamp is
#                                      the ONLY thing preventing the overflow)
#
# Why enter at the clamp: the builder's upstream NAME marshal @0x36c0 dereferences an SCM
# request-context object (builder x0 = [TzSetVariable.sp+0x38]) that is far upstream of the
# bug; modeling it adds risk and obscures the point. The security logic is the clamp +
# DATA copy, which we drive directly and faithfully (the clamp instructions and the copy
# call @0x7eec are the REAL ones; only CLAMP_OFF forces the branch).
#
# Clamp+copy disasm (re-derived, objdump/capstone):
#   0x7e2c ldr w8,[x19]      ; w8 = scratch capacity  (x19 = &header, header[0] = 0x10000)
#   0x7e30 ldr w25,[sp]      ; w25 = bytes already used (header+NAME) -> we set [sp]=0x14
#   0x7e34 sub w8,w8,w25     ; remaining = cap - used
#   0x7e38 subs w22,w8,w23   ; w22 = remaining - DataSize   (w23 = attacker DataSize)
#   0x7e3c b.hs #0x7e9c      ; copy ONLY if remaining >= DataSize; else REJECT @0x7e40
#   0x7e9c ... (copy path)   ; 0x7eec mov x0,x24(DataBuffer); mov w1,w23(DataSize); bl 0x2274
#   0x7f80 ret               ; the function's normal return

AFL_EXIT   = 0x13370
CLAMP_ENTRY = 0x7e2c     # we enter the builder at the clamp
CLAMP_END   = 0x7f80     # the builder's normal ret
REGISTRAR   = 0x2274     # CopyMem-with-region-tracking; modelled as an asan-checked memcpy
BHS_CLAMP   = 0x7e3c     # the `b.hs #0x7e9c` (copy-path branch)
COPY_PATH   = 0x7e9c

SCRATCH_USER = 0x55000000
SCRATCH_CAP  = 0x10000   # = garnet's qsee_malloc(0x10000)  (VARIANT size, not 0x20000)
USED         = 0x14      # header bytes already consumed before the DATA copy

HEADER_BASE  = 0x51100000     # x19 = &header; header[0] = capacity
DATA_BASE    = 0x52000000     # attacker DATA source (large)
DATA_MAP_SZ  = 0x40000        # 256 KiB

DEF_DATALEN = int(os.environ.get("UEFI_DATALEN", str(0x10100)), 0) & 0xFFFFFFFF
CLAMP_OFF   = os.environ.get("CLAMP_OFF", "0") == "1"


def _registrar_hook(ql):
    # Model garnet's registrar/CopyMem @0x2274: copy w1 bytes from x0 into the scratch at
    # the running fill cursor (= USED + prior copies). For the DATA copy @0x7eec, w1 =
    # DataSize, so a DataSize > (cap - USED) overruns the 0x10000 chunk. Detection uses the
    # emulator's SOFTWARE asan path `is_access_valid` (the same path the real hooked
    # memcpy/strcpy/TEE_MemMove use) -- a raw uc.mem_write does NOT trip the per-access
    # mem hooks, so we must check the redzones explicitly, exactly like a modelled CopyMem.
    src = ql.arch.regs.x0
    n   = ql.arch.regs.w1 & 0xFFFFFFFF
    base = _registrar_hook.base
    lr = ql.arch.regs.lr
    # Distinguish the two real copy sites by return address (faithful destinations, no
    # drifting cursor): the DATA copy @0x7eec (lr=0x7ef0) writes at scratch+USED (= the
    # `used` the clamp checked against), the NAME copy @0x7eac (lr=0x7eb0) writes at
    # scratch+0. This matches the real binary, where the clamp guarantees USED+DataSize<=cap.
    if base is not None and lr == base + 0x7ef0:        # DATA copy
        dst = SCRATCH_USER + USED
    elif base is not None and lr == base + 0x7eb0:      # NAME copy
        dst = SCRATCH_USER
    else:
        dst = SCRATCH_USER + _registrar_hook.cursor
    print(f"[uefi_garnet] REGISTRAR copy (lr={lr:#x}): src={src:#x} n={n:#x} -> dst={dst:#x} "
          f"end+n={dst + n:#x} scratch_end={SCRATCH_USER + SCRATCH_CAP:#x}")
    if n:
        # software asan check (sets arch_pc=CRASH_PC=0xdeadbeef if dst..dst+n hits a redzone)
        if _registrar_hook.emu is not None and not asan.is_access_valid(
                ql, _registrar_hook.emu.HEAP, dst, n, "uefi_garnet_CopyMem", is_write=True):
            return  # CRASH_PC set -> AFL/replay crash; do not continue
        try:
            buf = ql.arch.uc.mem_read(src, n)
            # clip the actual poke to mapped space so it doesn't raise UC_ERR (the asan
            # verdict above is the security signal; the poke is just to populate the chunk)
            wend = min(dst + n, SCRATCH_USER + SCRATCH_CAP)
            if wend > dst:
                ql.arch.uc.mem_write(dst, bytes(buf[:wend - dst]))
        except Exception as e:
            ql.log.warning(f"[uefi_garnet] registrar copy n={n:#x} dst={dst:#x}: {e}")
        _registrar_hook.cursor += n
    ql.arch.regs.x0 = 0
    ql.arch.regs.pc = ql.arch.regs.x30
_registrar_hook.cursor = 0
_registrar_hook.emu = None
_registrar_hook.base = None


def init_fuzz(emu, sid):
    ql = emu.ql
    _registrar_hook.emu = emu      # for the software asan check in the registrar model
    for base_, size, name in ((HEADER_BASE, 0x1000, "header"),
                              (DATA_BASE, DATA_MAP_SZ, "data")):
        try:
            ql.mem.map(base_, size, info=f"[uefi_garnet] {name}")
        except Exception as e:
            ql.log.warning(f"[uefi_garnet] map {name}: {e}")

    # Allocate the scratch exactly like malloc_core: 0x10000 user region with asan
    # redzones before/after, so an OOB write past 0x10000 trips CRASH_PC.
    RZ = asan.ASAN_REDZONE_SIZE
    total = ((SCRATCH_CAP + 2 * RZ + 0xFFF) & ~0xFFF)
    region = (SCRATCH_USER - RZ) & ~0xFFF
    try:
        ql.mem.map(region, total + 0x2000, info="[uefi_garnet] scratch_chunk")
    except Exception as e:
        ql.log.warning(f"[uefi_garnet] scratch map: {e}")
    user = SCRATCH_USER
    asan.asan_hook_redzone_mem_rw(SCRATCH_USER - RZ, RZ, ql)
    emu.HEAP["redzones"][SCRATCH_USER - RZ] = RZ
    after = user + SCRATCH_CAP
    after_sz = (region + total + 0x2000) - after
    asan.asan_hook_redzone_mem_rw(after, after_sz, ql)
    emu.HEAP["redzones"][after] = after_sz
    emu.HEAP["allocated"][user] = SCRATCH_CAP

    base = ql.mem.get_lib_base("uefi_sec_garnet.ta")
    _registrar_hook.base = base

    def _code_hook(ql, addr, size):
        if addr == base + 0x7e38:           # `subs w22, (cap-used), DataSize`
            r = ql.arch.regs
            rem = r.w8 & 0xffffffff
            ds = r.w23 & 0xffffffff
            print(f"[uefi_garnet] CLAMP @0x7e38: remaining(cap-used)={rem:#x} "
                  f"DataSize(w23)={ds:#x} -> "
                  f"{'COPY (0x7e9c)' if rem >= ds else 'REJECT (0x7e40)'}")
        if CLAMP_OFF and addr == base + BHS_CLAMP:
            # positive control: force the COPY path (0x7e9c) regardless of the clamp.
            ql.arch.regs.pc = base + COPY_PATH
        if addr == base + 0x7e40:
            # REJECT path reached (clamp fired). The real downstream is a log call + the
            # canary epilogue (we skipped the prologue, so the saved-canary slot is
            # uninitialised, and post-copy code @0x7f84 inits more buffers we didn't stage).
            # The DATA copy did NOT run -> this IS the patched, no-copy outcome. Jump to the
            # post-DATA-copy stop marker @0x7ef0 (= InvokeCommand_end) to end cleanly.
            print("[uefi_garnet] REJECT path @0x7e40 reached -> clamp prevented the copy "
                  "(no OOB); ending cleanly at the stop marker")
            ql.arch.regs.pc = base + 0x7ef0
        if addr == base + REGISTRAR:
            _registrar_hook(ql)
    ql.hook_code(_code_hook)

    print(f"[uefi_garnet] init: scratch@{hex(user)} cap={hex(SCRATCH_CAP)} "
          f"after_rz@{hex(after)} used={hex(USED)} ; clamp-entry@{hex(CLAMP_ENTRY)} "
          f"CLAMP_OFF={CLAMP_OFF}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    data_len = DEF_DATALEN
    if "UEFI_DATALEN" not in os.environ:
        data_len = (struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0)
        data_len = data_len % (DATA_MAP_SZ + 1)

    _registrar_hook.cursor = USED      # the DATA copy starts after the header+NAME bytes

    # header[0] = scratch capacity (0x10000)
    hdr = bytearray(0x40)
    struct.pack_into("<I", hdr, 0, SCRATCH_CAP)
    ql.mem.write(HEADER_BASE, bytes(hdr) + b"\x00" * (0x1000 - 0x40))
    # DATA: attacker marker bytes
    ql.mem.write(DATA_BASE, b"\x41" * DATA_MAP_SZ)

    setup_params_fuzz(ql, 1, 3, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    r = ql.arch.regs
    r.x19 = HEADER_BASE                 # &header (clamp `ldr w8,[x19]` = cap)
    r.x20 = SCRATCH_USER               # NAME-copy dst base (0x7eac path; unused here, USED=0)
    r.x23 = max(data_len, 0) & 0xFFFFFFFF   # w23 = DataSize (the clamped attacker length)
    r.x24 = DATA_BASE                  # DataBuffer source (0x7eec DATA copy `mov x0,x24`)
    r.x21 = 0x80000002                 # w21 used by the reject path (add w22,w21,#7)
    # [sp] = used bytes (clamp `ldr w25,[sp]`); the entry sp is the InvokeCommand stack.
    try:
        ql.mem.write_ptr(r.sp + 0x00, USED)
    except Exception as e:
        ql.log.warning(f"[uefi_garnet] [sp]<-used write: {e}")
    r.x30 = AFL_EXIT

    print(f"[uefi_garnet] clamp-entry@{hex(CLAMP_ENTRY)} DataSize={data_len:#x} "
          f"scratch_cap={hex(SCRATCH_CAP)} used={hex(USED)} "
          f"({'CLAMP_OFF -> expect OOB' if CLAMP_OFF else 'clamp ON -> expect REJECT/no-OOB'})")
    return True
