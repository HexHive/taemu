# === F7 / 68bcd09d bioagent — GlobalConfusion probe + set/get bounds drive =========
# Staged-from-scratch klee build (Invoke @0x13208, text base 0x13000).
#
# Invoke dispatch (re-derived from staged .ta):
#   cmp w1,#1; b.eq 0x13290 (cmd1 GET) ; cbnz w1,err (cmd!=0,1) ; else cmd0 SET.
#   SET (cmd0): paramTypes MUST be 5 (param0=MEMREF_IN) or 0x55 (param0,1=MEMREF_IN).
#     entry checks `[x19+0x18]`(params[1].size) < 0x401 (<=0x400) BEFORE buffer deref.
#     then CheckMemRights+memmove(g_auth_token_id,params[0].buf,0x20) [requires
#     params[0].size>=0x20], memmove(g_fp_list,params[1].buf,params[1].size<=0x400)
#     into a TEE_Malloc(0x400) buffer. Then ACL: caller UUID via GetPropertyAsIdentity
#     -> on the emulator the caller UUID is NOT in the 6-entry allowlist -> ACL DENY
#     (zeroes globals, returns 0xFFFF0007) — but the SIZE checks + the two memmoves run
#     before the ACL check, so OOB in the copies (if any) trips here regardless.
#   GET (cmd1): paramTypes in {0x66,0x666,0x6066,0x6666}. Requires g_verdict_valid_flag
#     (else "not init" -65530). Copies back each field only when out_size>=src_len:
#     params[0]>=0x20<-auth_token, params[1]>=8<-timestamp, params[2]>=fp_len<-fp_list,
#     params[3]>=method_len<-method. Fully bounded.
#
# MODE (env TAEMU_F7_MODE):
#   gc       : GlobalConfusion probe (flip param slots to VALUE poison)
#   set      : cmd0 SET, vary params[0].size / params[1].size to probe the copies
#   get      : cmd1 GET, vary out sizes (verdict not armed -> "not init", but still
#              exercises the paramTypes/size gating)
from .params import *
from qiling import Qiling
import struct, os

# PIE base the mitee loader maps the TA at (observed in the crash memory map).
TA_BASE = 0x555555554000
# .data struct-descriptor pointers (each {ptr@+0, len@+4/8}) that Create would have
# filled. Create is redirected to a no-op gadget (its TEE_Malloc uses unmodeled
# zx_heap_vmo), so init_fuzz allocates the buffers and wires these pointers itself.
G_METHOD_DESC      = 0x29008   # {ptr, len}  -> 32-byte method buffer
G_FPLIST_DESC      = 0x29018   # {ptr, len}  -> 1024-byte fp-list buffer
G_AUTHTOKEN_DESC   = 0x29028   # {ptr, len}  -> 32-byte auth-token-id buffer
G_VALIDFLAG_DESC   = 0x29000   # {ptr}       -> 1-byte g_verdict_valid_flag


def init_fuzz(ta_mgr, sid):
    """Runs after OpenSession, before the fuzz Invoke. Stand in for the redirected
    Create: allocate the 3 verdict buffers + the valid-flag byte and wire the .data
    struct descriptors so the SET/GET copy paths have valid backing memory."""
    ql = ta_mgr.ql
    def alloc(n):
        return ql.mem.map_anywhere(max(n, 0x1000), minaddr=0xcccc0000, perms=3, info="bioagent_global")
    method_buf = alloc(0x20)
    fplist_buf = alloc(0x400)
    authtok_buf = alloc(0x20)
    flag_buf = alloc(0x10)
    # write {ptr,len} descriptors (ptr is 8 bytes, len is 4 bytes at +8 per Create)
    ql.mem.write_ptr(TA_BASE + G_METHOD_DESC, method_buf)
    ql.mem.write(TA_BASE + G_METHOD_DESC + 8, struct.pack("<I", 0x0f))   # "not implemented" len
    ql.mem.write_ptr(TA_BASE + G_FPLIST_DESC, fplist_buf)
    ql.mem.write(TA_BASE + G_FPLIST_DESC + 8, struct.pack("<I", 0x400))
    ql.mem.write_ptr(TA_BASE + G_AUTHTOKEN_DESC, authtok_buf)
    ql.mem.write(TA_BASE + G_AUTHTOKEN_DESC + 8, struct.pack("<I", 0x20))
    # GET reads g_verdict_valid_flag as the BYTE at [0x27dc0]-deref == VA 0x29000 itself
    # (ldr x8,[0x27dc0]; ldrb [x8]); 0x29000 holds the flag byte directly. Arm it so GET
    # exercises the copy-back paths (otherwise it short-circuits "not init").
    # Also seed the fp_list/method lengths so GET copies a realistic blob back.
    if os.environ.get("F7_ARM_VALID", "1") == "1":
        ql.mem.write(TA_BASE + G_VALIDFLAG_DESC, b"\x01")
    print(f"[F7 68bcd init_fuzz] method={method_buf:#x} fplist={fplist_buf:#x} "
          f"authtok={authtok_buf:#x} flag={flag_buf:#x} armed={os.environ.get('F7_ARM_VALID','1')}")


MODE   = os.environ.get("TAEMU_F7_MODE", "gc")
POISON = int(os.environ.get("F7_POISON", "0x4142434445"), 0)
FLIP   = os.environ.get("F7_FLIP", "0,1")
FLIP_SLOTS = [int(x) for x in FLIP.split(",") if x != ""]
GC_CMD = int(os.environ.get("F7_CMD", "0"), 0)

P0SZ = int(os.environ.get("F7_P0SZ", "0x20"), 0)    # params[0].size (set: auth token)
P1SZ = int(os.environ.get("F7_P1SZ", "0x400"), 0)   # params[1].size (set: fp list)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if MODE == "gc":
        # bioagent set/get gate paramTypes BEFORE buffer deref; this confirms it.
        pt = 0
        for i in FLIP_SLOTS:
            pt |= (0x1 << (4 * i))
        params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
        lo, hi = POISON & 0xffffffff, (POISON >> 32) & 0xffffffff
        for i in FLIP_SLOTS:
            params[i] = ValueParam(lo, hi)
        print(f"[F7 68bcd GC] cmd={GC_CMD:#x} pt={pt:#06x} POISON={POISON:#x} FLIP={FLIP_SLOTS}")
        setup_params_fuzz(ql, GC_CMD, pt, params)
        return True

    if MODE == "set":
        # cmd0 SET. paramTypes 0x55 (both memref-in). vary the two sizes from env/AFL.
        p0sz = P0SZ
        p1sz = P1SZ
        if len(input) >= 4 and "F7_P1SZ" not in os.environ:
            # AFL explores params[1].size around the 0x400 boundary
            p1sz = struct.unpack_from("<I", input, 0)[0] % 0x800
        p0 = bytes([0x55]) * max(p0sz, 0)
        p1 = bytes([0x66]) * max(p1sz, 0)
        print(f"[F7 68bcd set] cmd0 p0sz={p0sz:#x} p1sz={p1sz:#x} (fp_list copy into 0x400 buf)")
        params = [MemRefParam(p0, p0sz), MemRefParam(p1, p1sz), NoneParam(), NoneParam()]
        setup_params_fuzz(ql, 0, 0x55, params)
        return True

    if MODE == "get":
        # cmd1 GET. paramTypes 0x6666 (4 memref-out). vary out sizes.
        sizes = [P0SZ, 8, 0x400, 0x20]
        if len(input) >= 4:
            sizes[2] = struct.unpack_from("<I", input, 0)[0] % 0x800
        params = [
            MemRefParam(bytes(sizes[0]), sizes[0]),
            MemRefParam(bytes(sizes[1]), sizes[1]),
            MemRefParam(bytes(sizes[2]), sizes[2]),
            MemRefParam(bytes(sizes[3]), sizes[3]),
        ]
        print(f"[F7 68bcd get] cmd1 out_sizes={[hex(s) for s in sizes]}")
        setup_params_fuzz(ql, 1, 0x6666, params)
        return True

    print("[F7 68bcd] unknown MODE")
    setup_params_fuzz(ql, GC_CMD, 0, [NoneParam()] * 4)
    return True
