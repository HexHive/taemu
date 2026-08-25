from dataclasses import dataclass
from pwn import *
import json
import importlib
import pkgutil
import inspect
import subprocess
import pathlib
import io
from qiling import Qiling
from capstone import Cs
from pathlib import Path
from qiling.const import QL_ARCH, QL_OS 
from elftools.elf.relocation import RelocationSection
from . import gp_api
from . import scrypto_api
from . import beanpod_api
from . import teegris_api
from . import mitee_api
from . import t6_api
from . import tc_api
from . import qsee_api
from . import optee_api
from .gp import (
    bigint_ops,
    crypto,
    general_objects,
    persistent_objects,
    properties,
    session,
    transient_objects,
)
from unicorn.arm64_const import UC_ARM64_INS_MRS, UC_ARM64_REG_PC
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from .custom.mitee_loader import mitee_read_relocs, mitee_relr_relocs, mitee_rela_relocs
from .custom.qsee_loader import qsee_read_relocs
from .custom.teegris_32_loader import teegris_32_rel
from .custom.tc_loader import tc_read_relcall
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .ta_mgr import TAEMU

@dataclass
class HookData:
    emu: 'TAEMU'
    func_name: str

def _is_emu_impl(f):
    """True only for a real API implementation: a callable actually defined in
    one of our ``emulate.*`` modules. This rejects names that leaked into an API
    module's namespace via ``from pwn import *`` (e.g. pwnlib's ``listen`` /
    ``connect`` / ``remote``) -- otherwise a TA importing a libc symbol that
    happens to collide with a pwnlib export would get hooked to the pwnlib
    object and blow up when called. Also rejects sub-modules picked up by
    getattr."""
    return (
        callable(f)
        and not inspect.ismodule(f)
        and getattr(f, "__module__", "").startswith("emulate")
    )


def get_api_impl(func_name, strict=False, implmented_apis=None):
    if func_name == "write":
        func_name = "_write"
    if func_name == "open":
        func_name = "_open"
    if func_name == "close":
        func_name = "_close"
    if func_name == "read":
        func_name = "_read"
    if func_name == "__stack_chk_fail":
        func_name = "stack_chk_fail"
    if implmented_apis is not None:
        if func_name not in implmented_apis:
            return gp_api.default_func
    api_func = getattr(gp_api, func_name, None)
    if _is_emu_impl(api_func):
        return api_func
    package = importlib.import_module("emulate.gp")
    for _, modname, ispkg in pkgutil.iter_modules(
        package.__path__, package.__name__ + "."
    ):
        if not ispkg:  # only import .py modules, skip subpackages if you want
            api_func = getattr(importlib.import_module(modname), func_name, None)
            if _is_emu_impl(api_func):
                return api_func
    for mod in (scrypto_api, beanpod_api, teegris_api, mitee_api, t6_api, tc_api, qsee_api, optee_api):
        api_func = getattr(mod, func_name, None)
        if _is_emu_impl(api_func):
            return api_func
    if strict:
        return None
    return gp_api.default_func


def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    # ql.log.info(f'PC {hex(ql.arch.regs.pc)} {ql.mem.read(ql.arch.regs.pc, 4).hex()}')
    pass

def unicorn_why(ql: Qiling, address: int, size: int):
    return

def nop_instruction(ql: Qiling, offset, lib_name):
    # nops the instructions at an address
    ql.patch(offset, b"\x00\x00\xa0\xe1", lib_name)


def is_ql_resolve(addr):
    if addr >= ql_resolve_mem and addr <= ql_resolve_mem+ql_resolve_mem_size:
        return True
    return False

counter = 0
ql_resolve_mem = 0x99999000
ql_resolve_mem_size = 0x1000

def fixup_got(ql: Qiling, ta_path, ta_elf: ELF, is_mitee=False):
    # ... :/
    # ta_path is a Path from hook_ta_dl but a plain str from the libscrypto.so
    # branch below (os.path.join), so go through basename rather than .name.
    ta_base = ql.mem.get_lib_base(os.path.basename(str(ta_path)))
    for section in ta_elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if section.name != ".rela.dyn":
            continue
        for rel in section.iter_relocations():
            reloc_addr = rel.entry["r_offset"]
            r_type = rel.entry["r_info_type"]
            addend = rel.entry.get("r_addend", None)
            print(f"  relocation at 0x{reloc_addr:x}, type={r_type}, addend={addend}")
            ql.mem.write_ptr(ta_base + reloc_addr, ta_base + addend)


def hook_ta_dl(
    ql: Qiling,
    ta_path:Path,
    ta_elf: ELF,
    emu,
    is_mitee=False,
    is_tc=False,
    is_qsee=False,
    is_optee=False
):
    hook_dict = {}
    counter = 0
    ta_base = ql.mem.get_lib_base(ta_path.name)
    ta_elf.address = ta_base
    ql.mem.map(ql_resolve_mem, ql_resolve_mem_size, info="dl_resolve")
    for func, addr in ta_elf.plt.items():
        if func not in ta_elf.got:
            continue
        ql.log.info(
            f"hooking api function {func}, {hex(addr)}, {hex(ql_resolve_mem+counter)}"
        )
        ql.mem.write(
            ta_elf.got[func],
            (ql_resolve_mem + counter).to_bytes(ql.arch.pointersize, "little"),
        )
        hook_dict[func] = (ta_elf.got[func], ql_resolve_mem + counter)
        ql.hook_address(
            get_api_impl(func),
            ql_resolve_mem + counter,
            user_data=HookData(emu, func),
        )
        counter += ql.arch.pointersize
    if is_mitee:
        to_hook = mitee_read_relocs(ta_path)
        for func, off in to_hook:
            ql.mem.write(
                ta_base + off,
                (ql_resolve_mem + counter).to_bytes(ql.arch.pointersize, "little"),
            )
            # ql.log.info(
            #     f"[mitee] hooking plt relocation function {func}, {hex(off)}, {hex(ql_resolve_mem+counter)}"
            # )
            ql.hook_address(
                get_api_impl(func),
                ql_resolve_mem + counter,
                user_data=HookData(emu, func),
            )
            counter += ql.arch.pointersize

    if is_qsee:
        # QSEE GPApp TAs come in two flavours:
        #  (1) dynamically linked against an external libcmnlib -> JUMP_SLOTs have
        #      a zero symbol value (true imports); every named slot must be modeled.
        #  (2) statically link libcmnlib in (Samsung S24 tz_hdm/tz_iccc) -> each
        #      JUMP_SLOT's symbol value is the function's REAL in-binary vaddr.
        # Model only the leaf APIs we have Python impls for, and let the TA's own
        # dispatch (GPAppLib_handleRequest, CApp_*, cmnlib_*) run NATIVELY by
        # pointing its GOT slot at the baked-in code.
        for qsee_reloc in qsee_read_relocs(ta_path):
            funcname = qsee_reloc.name
            off = qsee_reloc.offset
            sym_val = qsee_reloc.symbol_value
            impl = get_api_impl(funcname, implmented_apis=emu.implemented_apis)
            if impl is not gp_api.default_func:
                intercept_addr = ql_resolve_mem + counter
                counter += ql.arch.pointersize
                ql.mem.write(
                    ta_base + off,
                    intercept_addr.to_bytes(ql.arch.pointersize, "little"),
                )
                ql.log.info(
                    "[qsee] hooking import %s (got %#x) -> py impl", funcname, off
                )
                ql.hook_address(impl, intercept_addr, user_data=HookData(emu, funcname))
            elif sym_val != 0:
                # statically-linked internal symbol: point the GOT at the real code
                ql.mem.write(
                    ta_base + off,
                    (ta_base + sym_val).to_bytes(ql.arch.pointersize, "little"),
                )
                ql.log.info(
                    "[qsee] internal %s (got %#x) -> native %#x",
                    funcname, off, ta_base + sym_val,
                )
            else:
                # unmodeled external import: sentinel hook so an accidental call
                # does not fetch from a null GOT slot
                intercept_addr = ql_resolve_mem + counter
                counter += ql.arch.pointersize
                ql.mem.write(
                    ta_base + off,
                    intercept_addr.to_bytes(ql.arch.pointersize, "little"),
                )
                ql.log.warning(
                    "[qsee] unmodeled import %s (got %#x) -> default_func", funcname, off
                )
                ql.hook_address(impl, intercept_addr, user_data=HookData(emu, funcname))

    if is_tc:
        # IGNORE ME!!
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        to_hook = tc_read_relcall(ta_path)
        ql.mem.map(0x7000, 0x1000, info="dl_resolve tc (hack)")
        for func, off in to_hook:
            encoding, count = ks.asm(f"bl {0x7000+counter}", addr=off)
            ql.log.info(
                f"[tc] hooking inline arm call relocation function {func}, {hex(off)}, {hex(0x7000+counter)}"
            )
            ql.hook_address(
                get_api_impl(func),
                0x7000 + counter,
                user_data=HookData(emu, func),
            )
            ql.mem.write(off, bytes(encoding))
            counter += ql.arch.pointersize
    if is_optee:
        def redirect_execution(ql: Qiling, addr):
            ql.arch.regs.pc = addr
        for sym, addr in ta_elf.sym.items():
            api_func =  get_api_impl(sym, strict=True)
            if api_func is None: continue
            counter += ql.arch.pointersize
            ql.log.info(
                f"[optee] hooking {sym}@{hex(addr)}->{hex(ql_resolve_mem+counter)}"
            )
            ql.hook_address(
                redirect_execution,
                addr,
                user_data=ql_resolve_mem + counter
            )
            ql.hook_address(
                api_func, 
                ql_resolve_mem+counter,
                user_data=HookData(emu, sym),
            )
    if "00000000-0000-0000-0000-4b45594d5354.ta" in str(ta_path):
        # load libscrypto.so to emulate ASN1 stuff
        lib_path = os.path.join(os.path.dirname(ta_path), "lib64", "libscrypto.so")
        
        ql2 = Qiling(
            [lib_path],
            rootfs=os.path.dirname(ta_path),
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
        )
        print(ql2.mem.get_mapinfo())
        base_addr = 0x555555400000
        curr_base = base_addr
        orig_base = None
        for entry in ql2.mem.get_mapinfo():
            start, end, perm, name, _ = entry
            size = end - start
            if name != "libscrypto.so": continue
            if orig_base is None:
                orig_base = start
            if perm == 'r-x':
                perm = UC_PROT_READ | UC_PROT_EXEC
            else:
                perm = UC_PROT_READ | UC_PROT_WRITE
            offset = start - orig_base
            ql.mem.map(curr_base + offset, size, perm, "libscrypto.so")
            # the mapping above is empty; copy the segment's actual bytes in,
            # otherwise every call into libscrypto executes zeroed memory
            ql.mem.write(curr_base + offset, bytes(ql2.mem.read(start, size)))
        print(ql.mem.get_mapinfo())
        # handle relocations of libscrypto.so
        lib_elf = ELF(lib_path)
        lib_elf.address = base_addr
        fixup_got(ql, lib_path, lib_elf)
        # hook API calls in libscrpyto.so
        for func, addr in lib_elf.plt.items():
            if func not in lib_elf.got:
                continue
            ql.log.info(
                f"hooking api function {func}, {hex(addr)}, {hex(ql_resolve_mem+counter)}"
            )
            ql.mem.write(
                lib_elf.got[func],
                (ql_resolve_mem + counter).to_bytes(ql.arch.pointersize, "little"),
            )
            ql.hook_address(
                get_api_impl(func),
                ql_resolve_mem + counter,
                user_data=HookData(emu, func),
            )
            counter += ql.arch.pointersize 
        # redirect API calls to libscrpyto in the TA
        for func, entry in hook_dict.items():
            got_addr, _ = entry
            if func in lib_elf.symbols and func not in ("printf"):
                ql.log.info(
                    f"linking TA function [{func}] to libscrypto: [{hex(lib_elf.symbols[func])}]"
                )
                ql.mem.write_ptr(
                    got_addr, lib_elf.symbols[func]
                )

def hook_ta_custom(
    ql: Qiling,
    ta_path: Path,
    ta_elf: ELF,
    emu: 'TAEMU',
):
    # inline hooks for TAs
    ta_base = ql.mem.get_lib_base(ta_path.name)
    ta_elf.address = ta_base
    ta_info = emu.ta_info
    if "inline" in ta_info:
        addr_map = defaultdict(list)
        for func_name, info in ta_info['inline'].items():
            addr_map[info["addr"]].append((func_name, info))
        # ghidra sometimes maps several API stubs to one address (a shared thunk
        # or faulty decompilation). Previously this hard-exit()ed the whole TA;
        # instead install ONE hook per address, preferring a name that resolves
        # to a real impl (not default_func), and just warn. A hard metadata
        # quirk shouldn't make an otherwise-loadable TA un-runnable.
        for addr, entries in addr_map.items():
            names = [n for n, _ in entries]
            if len(names) > 1:
                ql.log.warning(
                    f"inline addr {hex(addr)} shared by {names}; hooking one (json quirk)"
                )
            chosen_name, chosen_info = entries[0]
            for n, info in entries:
                if get_api_impl(n, implmented_apis=emu.implemented_apis) is not gp_api.default_func:
                    chosen_name, chosen_info = n, info
                    break
            hook_type = chosen_info['type']
            if hook_type == "gp_api" or hook_type == "tee" or hook_type == "tee_std":
                target = ta_base + addr if ta_elf.pie else addr
                ql.log.info(f'hooking inline api function {chosen_name}, {hex(addr)}')
                ql.hook_address(
                    get_api_impl(chosen_name, implmented_apis=emu.implemented_apis),
                    target,
                    user_data=HookData(emu, chosen_name),
                )

def teegris_32_setup(ql: Qiling, ta_path, ta_base):
    rels = teegris_32_rel(ta_path)
    for rel in rels:
        v = ql.mem.read_ptr(ta_base + rel)
        ql.mem.write_ptr(ta_base + rel, v + ta_base)

def _optee_force_ret0(ql: Qiling, *args):
    # neutralize a function: set its return value to 0 and return to the caller
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def optee_setup(ql: Qiling, ta_path, ta_base, emu):
    ql.hook_intno(optee_api.optee_syscall, 2, user_data=emu)

    # Reproducer aid: TAEMU_FORCE_RET0 is a comma-separated list of image-base-
    # relative offsets (Ghidra vaddr - 0x100000) of functions to force-return 0.
    # Used to model preconditions the emulator cannot satisfy (e.g. an attacker-
    # supplied *validly-signed* image: stub the RSA/ECC signature verifier so the
    # documented post-verification bug is reachable).
    for tok in os.environ.get("TAEMU_FORCE_RET0", "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        off = int(tok, 0)
        ql.hook_address(_optee_force_ret0, ta_base + off)
        ql.log.info(
            f"[optee] TAEMU_FORCE_RET0: {hex(ta_base + off)} (off {hex(off)}) -> return 0"
        )

    # Reproducer aid: TAEMU_SET_GLOBAL="off=val,..." writes a 4-byte value to a
    # global (image-base-relative offset) after relocation -- e.g. to set a
    # verify-state flag a successful (key-gated) init would have set.
    for tok in os.environ.get("TAEMU_SET_GLOBAL", "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        off_s, val_s = tok.split("=")
        off = int(off_s, 0)
        val = int(val_s, 0) & 0xFFFFFFFF
        ql.mem.write(ta_base + off, val.to_bytes(4, "little"))
        ql.log.info(
            f"[optee] TAEMU_SET_GLOBAL: [{hex(ta_base + off)}] (off {hex(off)}) = {hex(val)}"
        )

def qsee_setup(ql: Qiling, ta_path:Path, ta_base, emu: 'TAEMU'):
    reloc_offsets = mitee_rela_relocs(ta_path)
    ta_base = ql.mem.get_lib_base(ta_path.name)
    for off in reloc_offsets:
        reloc_off = ql.mem.read_ptr(ta_base + off)
        # ql.log.info(f"[mitee] fixing relcation at {hex(off)} for {hex(reloc_off)}")
        ql.mem.write_ptr(ta_base + off, ta_base + reloc_off)
    def handle_retab(ql: Qiling, user_data):
        # PAC (FEAT_PAuth) is not implemented by this Unicorn build, so every
        # ARMv8.3 pointer-authentication instruction raises exception #1. The
        # ORIGINAL handler unconditionally did `pc = lr`, which is only correct
        # for an authenticated RETURN (retab/retaa). bksecapp (unlike tz_hdm/
        # tz_iccc, which contain NO PAC ops) signs the return address in EVERY
        # function PROLOGUE with `pacib x30, sp` / `pacibsp`; treating that as a
        # return made every prologue immediately `ret` to lr (the call site),
        # so no function body ever ran. We therefore decode the faulting
        # instruction and:
        #   * authenticated return  (retab/retaa)        -> pc = lr
        #   * authenticated branch   (braa/brab Xn)       -> pc = Xn
        #   * authenticated call     (blraa/blrab Xn)     -> lr = pc+4; pc = Xn
        #   * sign / authenticate    (pac*/aut*/xpac*)    -> NO-OP, pc += 4
        # (PAC is a no-op here because we don't model the signing bits; the
        # pointers stay un-signed throughout, so a later aut*/retab just passes
        # the raw pointer through, which is exactly what we want for emulation.)
        pc = ql.arch.regs.arch_pc
        try:
            code = ql.mem.read(pc, 4)
            ins = next(ql.arch.disassembler.disasm(bytes(code), pc), None)
        except Exception:
            ins = None
        if ins is None:
            # unknown -> fall back to the legacy behaviour (return to lr)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
        m = ins.mnemonic
        if m in ("retaa", "retab"):
            ql.arch.regs.arch_pc = ql.arch.regs.lr
        elif m in ("braa", "brab", "braaz", "brabz"):
            # branch to authenticated register (first operand)
            reg = ins.op_str.split(",")[0].strip()
            try:
                ql.arch.regs.arch_pc = getattr(ql.arch.regs, reg)
            except Exception:
                ql.arch.regs.arch_pc = ql.arch.regs.lr
        elif m in ("blraa", "blrab", "blraaz", "blrabz"):
            reg = ins.op_str.split(",")[0].strip()
            ql.arch.regs.lr = pc + 4
            try:
                ql.arch.regs.arch_pc = getattr(ql.arch.regs, reg)
            except Exception:
                ql.arch.regs.arch_pc = pc + 4
        else:
            # pacia/pacib/paciasp/pacibsp/autia/autib/autiasp/autibsp/xpac... ::
            # sign/authenticate in place -> no-op, just step over it.
            ql.arch.regs.arch_pc = pc + 4
    ql.hook_intno(handle_retab, 1)
    has_pac = emu.ta_info.get("has_pac", False)
    if has_pac:
        def hook_pointer_authentication(ql: Qiling, port, size):
            code_bytes = ql.mem.read(ql.arch.regs.arch_pc, 4)
            for (address, size, mnemonic, op_str) in ql.arch.disassembler.disasm_lite(code_bytes, ql.arch.regs.arch_pc, count=1):
                if mnemonic in ("pacib", "bti", "btic", "pacda", "pacib"):
                    # nop it out
                    next_addr = ql.arch.regs.arch_pc + size
                    ql.uc.reg_write(UC_ARM64_REG_PC, next_addr)
                elif mnemonic in ("retab",):
                    ql.log.debug("retabbed")
                    ql.arch.regs.arch_pc = ql.arch.regs.lr
        
        emu.ql.log.warning("hooking pointer authentication, expect slowdown")
        ql.hook_code(hook_pointer_authentication)


def mitee_setup(ql: Qiling, ta_path:Path, ta_base:int):
    # 1: setup tls for mrs
    TLS_MEM_BASE = 0xEEE000
    THREAD_STACK_BASE = 0xF00000
    THREAD_STACK_SIZE = 0x10000
    CANARY = 0xCACACACACACACACA
    ql.mem.map(TLS_MEM_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE, info="[fuchsia] tls")
    ql.mem.map(
        THREAD_STACK_BASE,
        THREAD_STACK_SIZE,
        UC_PROT_READ | UC_PROT_WRITE,
        info="[fuchsia] thread-stack",
    )
    THREAD_STACK_ADDR = THREAD_STACK_BASE + THREAD_STACK_SIZE - 0x10
    TLS_ADDR = TLS_MEM_BASE + 0x10

    def hook_mrs(ql: Qiling, port, size):
        code_bytes = ql.mem.read(ql.arch.regs.arch_pc, 4)
        for ins in ql.arch.disassembler.disasm(code_bytes, ql.arch.regs.arch_pc):
            assert ins.mnemonic == "mrs"
            target_reg = ins.op_str.split(",")[0]
            exec(f"ql.arch.regs.{target_reg} = {TLS_ADDR}")
        return (0, TLS_ADDR)

    ql.mem.write_ptr(TLS_ADDR - 0x8, THREAD_STACK_ADDR)
    ql.mem.write_ptr(TLS_ADDR - 0x10, CANARY)
    ql.hook_insn(hook_mrs, UC_ARM64_INS_MRS)
    # 2: fixup data relocations
    reloc_offsets = mitee_relr_relocs(ta_path)
    ta_base = ql.mem.get_lib_base(ta_path.name)
    for off in reloc_offsets:
        reloc_off = ql.mem.read_ptr(ta_base + off)
        # ql.log.info(f"[mitee] fixing relcation at {hex(off)} for {hex(reloc_off)}")
        ql.mem.write_ptr(ta_base + off, ta_base + reloc_off)


def trace_block(ql: Qiling, address, size):
    for start, end, _, label, _ in ql.mem.get_mapinfo():
        if start <= address < end:
            ql.log.info("basic block at %#x - %#x ([%s] + %#x)", address, address+size, label, address - start)
            return
    ql.log.info("basic block at %#x - %#x", address, address+size)
