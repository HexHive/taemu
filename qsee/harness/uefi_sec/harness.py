from .params import *
from qiling import Qiling
import struct, os

# === S10 reproduction harness: qcom.tz.uefisecapp (SM-S928B) ================
# Reproduces BOTH S10 sinks in secpkcs7_get_cert_chain_from_sig_index@0xe61c,
# reached via the real validate_pkcs7_and_get_public_key@0x13f28:
#
#   QUEFI-7  (raw-DER chain-buffer heap OOB, NO self-cap): one cert whose DER
#            length > 0x2800 makes the collector's per-cert uefi_memcpy
#            (0xe7a8 first cert / 0xe864 loop) overrun the qsee_malloc(0x2800)
#            chunk -> asan after-redzone native write hook -> CRASH_PC.
#            This is the PRIMARY dynamic repro (fault-detectable).
#
#   QUEFI-1  (4-slot struct-array global OOB, self-caps): >4 chaining certs
#            drive `++count` past 4 so uefi_memcpy(records+0x7d8*count,...) writes
#            past slot 3. The dest is a GLOBAL (g_cert_chain_records@0x23d88), not
#            redzoned, and the OOB lands on the mapped count word -> self-cap
#            (S10 §5). Not a fault; OBSERVED via the recorded count.
#
# Staging (uefi_sec.json): GP lifecycle stubbed -> TEE_SUCCESS; InvokeCommand ->
# validate@0x13f28. validate's ABI (from RE):
#   x0 = request ptr (parsed by the now-stubbed secpkcs7_parse_buffer)
#   w1 = pkcs7 DER length  (must be != 0)
#   x2 = signed-payload ptr (hashed by the now-stubbed pkcs7_secboot_hash)
#   w3 = payload length    (must be != 0)
#   w4 = trust_class       (guarded <= 4 at 0x13f90; any of 0..4 reaches the sink)
#   x5,x6,x7 = scratch out ptrs (each cbz-checked != 0)
# The parse leaves + collector callees are inline-stubbed in qsee_api.u_* and
# read their synthetic chain from the control page below.

AFL_EXIT = 0x13370

# --- guest pages (mapped once in init_fuzz) --------------------------------
# Must agree with the constants in qsee_api.py (the inline stubs read these).
CTL_BASE    = 0x53000000     # control page: n_certs / der_len / dn_match
CTX_PTR     = 0x53001000     # dummy PKCS#7 ctx
DN_PTR      = CTL_BASE + 0x40   # shared DN bytes (memcmp match)
DER_PTR     = CTL_BASE + 0x80   # cert DER source bytes (QUEFI-7 copy source)
PARSED_PTR  = 0x53002000     # 2008-B parsed-cert struct (QUEFI-1 copy source)
CTL_SIZE    = 0x4000         # covers CTL_BASE .. CTX/PARSED region

REQ_BASE    = 0x51000000     # pkcs7 request buffer (stub-ignored, just mapped)
REQ_SIZE    = 0x4000
PAY_BASE    = 0x52000000     # signed-payload buffer (stub-ignored, mapped)
PAY_SIZE    = 0x2000
SCRATCH     = 0x54000000     # x5/x6/x7 scratch out slots
SCRATCH_SZ  = 0x4000

# Cert DER source span (QUEFI-7 reads up to der_len bytes from DER_PTR). Map it
# big enough that the *read* stays in-bounds while the WRITE overflows the
# 0x2800 heap dest -- so the detector sees the heap OOB write, not a read fault.
DER_SPAN    = 0x8000

CTL_N_OFF   = 0x00           # u32 n_certs
CTL_LEN_OFF = 0x04           # u32 der_len (== w24, QUEFI-7 size)
CTL_DN_OFF  = 0x08           # u32 dn_match flag (informational)

# QUEFI-7 default: one cert, DER length just over the 0x2800 heap chunk so the
# first-cert uefi_memcpy@0xe7a8 overruns immediately. Env-overridable.
DEF_NCERTS  = int(os.environ.get("UEFI_NCERTS", "1"), 0)
DEF_DERLEN  = int(os.environ.get("UEFI_DERLEN", str(0x2900)), 0) & 0xFFFF
TRUST_CLASS = int(os.environ.get("UEFI_TRUST", "1"), 0)


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in (
        (CTL_BASE, CTL_SIZE, "ctl"),
        (REQ_BASE, REQ_SIZE, "req"),
        (PAY_BASE, PAY_SIZE, "payload"),
        (SCRATCH, SCRATCH_SZ, "scratch"),
    ):
        try:
            ql.mem.map(base, size, info=f"[uefi_sec] {name}")
        except Exception as e:
            ql.log.warning(f"[uefi_sec] map {name} @ {hex(base)}: {e}")
    # DER source page is large (read span > write span); map separately if the
    # control page doesn't already cover it.
    try:
        ql.mem.map(DER_PTR & ~0xFFF, ((DER_SPAN + 0xFFF) & ~0xFFF) + 0x1000,
                   info="[uefi_sec] der_src")
    except Exception:
        pass  # may overlap CTL page; fine
    print(f"[uefi_sec] init: ctl@{hex(CTL_BASE)} req@{hex(REQ_BASE)} "
          f"der_src@{hex(DER_PTR)} parsed@{hex(PARSED_PTR)}")

    # Optional control-flow trace (UEFI_DBG=1): print ta-relative block addrs so
    # we can see exactly which path validate@0x13f28 takes. Diagnostic only.
    if os.environ.get("UEFI_DBG"):
        base = ql.mem.get_lib_base("uefi_sec.ta")
        _seen = {"n": 0}
        def _blk(q, addr, size):
            rel = addr - base
            # skip the memset/memcpy byte-fill helper inner loops (0x16400+) to
            # keep the trace readable; show everything else.
            if 0 <= rel < 0x1d000 and not (0x16400 <= rel < 0x16600) and _seen["n"] < 4000:
                _seen["n"] += 1
                print(f"[blk] ta+{rel:#06x}", flush=True)
        ql.hook_block(_blk)

    if os.environ.get("UEFI_PROBE"):
        base = ql.mem.get_lib_base("uefi_sec.ta")
        # dump regs at the two QUEFI-7 copy sites and the slot path
        probes = {0xe758: "slot0_path", 0xe790: "get_DER_call",
                  0xe7a8: "Q7_memcpy(x0=dst,x2=len)", 0xe7ac: "Q7_len_update",
                  0xe864: "Q7_memcpy_loop", 0xe824: "Q1_memcpy"}
        def _probe(q, addr, size):
            rel = addr - base
            if rel in probes:
                r = q.arch.regs
                print(f"[probe] ta+{rel:#x} {probes[rel]}: "
                      f"x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x} "
                      f"x19={r.x19:#x} x20={r.x20:#x} x22={r.x22:#x} x24={r.x24:#x}",
                      flush=True)
        ql.hook_code(_probe)

    if os.environ.get("UEFI_Q1OBS"):
        # QUEFI-1 OBSERVER: the struct-array sink writes into the GLOBAL
        # g_cert_chain_records@0x23d88 (not the heap), and the record-4 write
        # lands ON the live count word at records+0x7d8*4 = 0x25ce8 (mapped) ->
        # self-cap (S10 5), NO fault. So we OBSERVE: snapshot the count word and
        # the dst at each append, and dump the record-4 window post-collector.
        base = ql.mem.get_lib_base("uefi_sec.ta")
        RECS = base + 0x23d88
        CNT  = base + 0x23d88 + 0x1f60      # = records + 8032 (count word)
        def _q1(q, addr, size):
            rel = addr - base
            if rel in (0xe78c, 0xe844):     # the two ++count store sites
                r = q.arch.regs
                cnt = int.from_bytes(q.mem.read(CNT, 4), "little")
                # x8 just-incremented value being stored; dst was records+0x7d8*old
                print(f"[q1] ta+{rel:#x} ++count store: count(after)={r.x8} "
                      f"records@{RECS:#x} count_word@{CNT:#x}", flush=True)
            elif rel == 0xe718:             # collector epilogue (loop exited)
                cnt = int.from_bytes(q.mem.read(CNT, 4), "little")
                # window straddling slot3-end / count word / record-4 area: the
                # record-4 memcpy wrote the parsed-cert struct STARTING at the
                # count word, so bytes at count_word.. are the struct's version
                # field (2) + struct body (0x42..) -> visible OOB evidence.
                w = q.mem.read(CNT, 0x20)
                print(f"[q1] COLLECTOR-EXIT: g_cert_chain_count = {cnt} "
                      f"(slot capacity=4, self-capped); count_word@{CNT:#x}", flush=True)
                print(f"[q1] OOB evidence mem[count_word .. +0x20] = {w.hex()}",
                      flush=True)
        ql.hook_code(_q1)


def _write_ctl(ql, n_certs, der_len):
    # zero the control region, then stamp the synthetic-chain parameters.
    ql.mem.write(CTL_BASE, b"\x00" * 0x100)
    ql.mem.write(CTL_BASE + CTL_N_OFF,   struct.pack("<I", n_certs & 0xFFFFFFFF))
    ql.mem.write(CTL_BASE + CTL_LEN_OFF, struct.pack("<I", der_len & 0xFFFF))
    ql.mem.write(CTL_BASE + CTL_DN_OFF,  struct.pack("<I", 1))
    # shared DN bytes used by the collector's memcmps (4 bytes is enough)
    ql.mem.write(DN_PTR, b"\xDE\xAD\xBE\xEF")
    # cert DER source bytes (what QUEFI-7 concatenates into the heap chunk)
    ql.mem.write(DER_PTR, (b"\x41" * min(der_len, DER_SPAN)) or b"\x41")
    # parsed-cert struct (QUEFI-1 source): the stub fills +0x20/+0x60. Its
    # FIRST 4 bytes are the parsed X.509 *version* (pbl_secx509 forces <= 2). On
    # the real device the record-4 OOB write puts THIS small value onto the count
    # word -> ++count re-reads <=3 -> the loop self-caps at exactly one OOB record
    # (S10 5). We mirror that: byte[0..4] = 2 so the count self-caps faithfully.
    pc = bytearray(b"\x42" * 0x7D8)
    pc[0:4] = struct.pack("<I", 2)        # X.509 version field (<=2), as in-TA
    ql.mem.write(PARSED_PTR, bytes(pc))


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives der_len across [0 .. 0xFFFF] so the 0x2800 overflow boundary is
    # DISCOVERED (an all-zero seed -> der_len 0, safe; AFL finds > 0x2800). For a
    # deterministic single-seed repro set UEFI_DERLEN.
    n_certs = DEF_NCERTS
    der_len = DEF_DERLEN
    if "UEFI_DERLEN" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        der_len = v & 0xFFFF                      # 16-bit, mirrors the in-TA cap
        # optional: let bytes [4] pick n_certs in [1..6] to also exercise QUEFI-1
        n_certs = (input[4] % 6 + 1) if len(input) >= 5 else 1

    _write_ctl(ql, n_certs, der_len)
    ql.mem.write(REQ_BASE, b"\x30\x82\x00\x00" + b"\x00" * 0x40)   # fake DER head
    ql.mem.write(PAY_BASE, b"\x00" * 0x40)

    # keep the GP param machinery satisfied (overridden below)
    setup_params_fuzz(ql, 0x2003, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # validate_pkcs7_and_get_public_key(x0=req, w1=pkcs7_len, x2=payload,
    #   w3=payload_len, w4=trust_class, x5/x6/x7=scratch); benign return -> AFL exit
    ql.arch.regs.x0 = REQ_BASE
    ql.arch.regs.x1 = 0x40            # pkcs7 len (non-zero)
    ql.arch.regs.x2 = PAY_BASE
    ql.arch.regs.x3 = 0x20           # payload len (non-zero)
    ql.arch.regs.x4 = TRUST_CLASS & 0xFFFFFFFF
    ql.arch.regs.x5 = SCRATCH + 0x000
    ql.arch.regs.x6 = SCRATCH + 0x800
    ql.arch.regs.x7 = SCRATCH + 0x1000
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[uefi_sec] validate(pkcs7) n_certs={n_certs} der_len={der_len:#x} "
          f"trust={TRUST_CLASS} -> collector@0xe61c "
          f"(QUEFI-7 if der_len>0x2800; QUEFI-1 if n_certs>4)")
    return True
