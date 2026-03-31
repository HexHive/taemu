from elftools.elf.dynamic import DynamicSegment
from pwn import *
import json
import importlib
import pkgutil
import inspect
import subprocess
import pathlib
import io
from qiling import Qiling
from qiling.utils import ql_get_module
from capstone import Cs
from pathlib import Path
from elftools.elf.elffile import ELFFile
from qiling.const import QL_ARCH, QL_OS 
from elftools.elf.relocation import RelocationSection
from . import gp_api
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
from .custom.qsee_loader import qsee_fix_got, qsee_read_relocs
from .custom.teegris_32_loader import teegris_32_rel
from .custom.tc_loader import tc_read_relcall
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM


class HookData:
    def __init__(self, emu, func_name):
        self.emu = emu
        self.func_name = func_name


def get_api_impl(func_name, strict=False):
    if func_name == "write":
        func_name = "_write"
    if func_name == "open":
        func_name = "_open"
    if func_name == "close":
        func_name = "_close"
    if func_name == "__stack_chk_fail":
        func_name = "stack_chk_fail"
    api_func = getattr(gp_api, func_name, None)
    if api_func is not None:
        return api_func
    package = importlib.import_module("emulate.gp")
    for _, modname, ispkg in pkgutil.iter_modules(
        package.__path__, package.__name__ + "."
    ):
        if not ispkg:  # only import .py modules, skip subpackages if you want
            api_func = getattr(importlib.import_module(modname), func_name, None)
            if api_func is not None and not inspect.ismodule(api_func):
                return api_func
    api_func = getattr(beanpod_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(teegris_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(mitee_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(t6_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(tc_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(qsee_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(optee_api, func_name, None)
    if api_func is not None:
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

def fixup_got(ql: Qiling, ta_path:Path, ta_elf: ELF, is_mitee=False):
    # ... :/
    ta_base = ql.mem.get_lib_base(ta_path.name)
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
        to_hook = qsee_fix_got(ql, ta_path, ta_elf, ql_resolve_mem+counter)
        ql.log.info(f"[qsee] leftover relocations: {len(to_hook)}")
        for qsee_reloc in to_hook:
            funcname = qsee_reloc.name
            off = qsee_reloc.offset
            sym = qsee_reloc.symbol_value
            ql.mem.write(
                ta_base + off,
                (ql_resolve_mem + counter).to_bytes(ql.arch.pointersize, "little"),
            )
            ql.log.info(
                f"[qsee] hooking plt relocation function {funcname}, {hex(off)}, {hex(ql_resolve_mem+counter)}"
            )
            func_impl = get_api_impl(funcname)
            if func_impl is None:
                ql.log.warning(f"[qsee] function {funcname} not found")
            ql.hook_address(
                # qsee_api._wrap_fcall_with_debug_log(func_impl),
                func_impl,
                ql_resolve_mem + counter,
                user_data=HookData(emu, funcname),
            )
            counter += ql.arch.pointersize
    
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
        for func_name, info in ta_info["inline"].items():
            addr_map[info["addr"]].append(func_name)
        # Print functions that share the same addr
        shared_funcs = False
        for addr, funcs in addr_map.items():
            if len(funcs) > 1:
                print(f"Address {addr} is shared by: {', '.join(funcs)}")
                shared_funcs = True
        if shared_funcs:
            print(f"fix the json, probably due to faulty decompilation")
            exit(-1)
        for fname, info in ta_info["inline"].items():
            addr = info["addr"]
            hook_type = info["type"]
            if hook_type == "gp_api" or hook_type == "tee" or hook_type == "tee_std":
                # ql.log.info(f"hooking inline api function {fname}, {hex(addr)}")
                if ta_elf.pie:
                    ql.hook_address(
                        get_api_impl(fname),
                        ta_base + addr,
                        user_data=HookData(emu, fname),
                    )
                else:
                    ql.hook_address(
                        get_api_impl(fname),
                        addr,
                        user_data=HookData(emu, fname),
                    )


def teegris_32_setup(ql: Qiling, ta_path, ta_base):
    rels = teegris_32_rel(ta_path)
    for rel in rels:
        v = ql.mem.read_ptr(ta_base + rel)
        ql.mem.write_ptr(ta_base + rel, v + ta_base)

def optee_setup(ql: Qiling, ta_path, ta_base, emu):
    ql.hook_intno(optee_api.optee_syscall, 2, user_data=emu)

def qsee_setup(ql: Qiling, ta_path:Path, ta_base):
    reloc_offsets = mitee_rela_relocs(ta_path)
    ta_base = ql.mem.get_lib_base(ta_path.name)
    for off in reloc_offsets:
        reloc_off = ql.mem.read_ptr(ta_base + off)
        # ql.log.info(f"[mitee] fixing relcation at {hex(off)} for {hex(reloc_off)}")
        ql.mem.write_ptr(ta_base + off, ta_base + reloc_off)
    def handle_retab(ql: Qiling, user_data):
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    ql.hook_intno(handle_retab, 1)

    # TODO: Check if it gets slower because of this
    def hook_pointer_authentication(ql: Qiling, port, size):
        code_bytes = ql.mem.read(ql.arch.regs.arch_pc, 4)
        inss = list(ql.arch.disassembler.disasm(code_bytes, ql.arch.regs.arch_pc))
        assert len(inss) == 1
        ins = inss[0]
        if ins.mnemonic in ("pacib", "bti", "btic", "pacda", "pacib"):
            # nop it out
            next_addr = ql.arch.regs.arch_pc + ins.size
            ql.uc.reg_write(UC_ARM64_REG_PC, next_addr)
            return
        elif ins.mnemonic in ("retab",):
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
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
    ql.log.info("basic block at 0x%x" % (address))
