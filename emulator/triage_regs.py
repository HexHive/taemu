#!/usr/bin/python3
# Replay a fuzz crash seed and dump PC + regs at the moment of the fault.
# Usage (inside ta_emu container, cwd=/srv/emulator):
#   python3 triage_regs.py <harness_dir> <seed>
# Hooks UC_HOOK_MEM_INVALID + UC_HOOK_CODE (last-insn tracking) so we can report
# the faulting PC/lr/x0..x4 even for raw UC_ERR_FETCH/READ/WRITE_UNMAPPED that
# bypass the redzone CRASH_PC redirect.
import sys, os, runpy

harness_dir = os.path.abspath(sys.argv[1])
seed = os.path.abspath(sys.argv[2])
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from emulate.ta_mgr import TAEMU as TAManager  # noqa

BASE = 0x555555554000
LAST = {"pc": 0, "lr": 0, "prev": 0}

def reg(ql, name):
    try:
        return ql.arch.regs.read(name)
    except Exception:
        return -1

def dump(ql, tag):
    print(f"[REGS] {tag}", flush=True)
    for n in ("PC","LR","SP","X0","X1","X2","X3","X4","X5","X6","X8","X29","X30"):
        v = reg(ql, n)
        off = (v - BASE) if (v and BASE < v < BASE+0x400000) else None
        extra = f"  (vaddr {off:#x})" if off is not None else ""
        print(f"  {n:4} = {v:#018x}{extra}", flush=True)
    for label,key in (("last_good_pc","pc"),("prev_pc","prev")):
        v=LAST[key]
        off=(v-BASE) if BASE<v<BASE+0x400000 else None
        print(f"  {label} = {v:#018x}" + (f"  (vaddr {off:#x})" if off is not None else ""), flush=True)

def install_hooks(ql):
    def code_cb(ql, address, size, ud=None):
        LAST["prev"] = LAST["pc"]
        LAST["pc"] = address
        LAST["lr"] = reg(ql, "LR")
    def mem_invalid_cb(ql, access, address, size, value, ud=None):
        print(f"[FAULT] access={access} addr={address:#x} size={size} value={value:#x}", flush=True)
        dump(ql, f"at fault (access={access})")
        return False
    ql.hook_code(code_cb)
    ql.hook_mem_unmapped(mem_invalid_cb)
    ql.hook_mem_invalid(mem_invalid_cb)

_orig = TAManager.start_fuzz
def patched(self, *a, **k):
    install_hooks(self.ql)
    try:
        return _orig(self, *a, **k)
    except Exception as e:
        print(f"[EXC] {type(e).__name__}: {e}", flush=True)
        try: dump(self.ql, "in except")
        except Exception: pass
        raise
TAManager.start_fuzz = patched

# stage TA into rootfs/
ta = next(os.path.join(harness_dir,f) for f in os.listdir(harness_dir) if f.endswith(".ta"))
os.system(f"cp {ta} rootfs/ ; cp {ta[:-3]}.json rootfs/")
ta_root = "rootfs/" + os.path.basename(ta)
harness_py = os.path.join(harness_dir, "harness.py")

sys.argv = ["emulate", "--fuzz_replay", seed, "--fuzz_harness", harness_py, ta_root]
runpy.run_module("emulate", run_name="__main__", alter_sys=True)
