from pwn import *
import json
import importlib
import pkgutil
import pathlib
from qiling import Qiling
from qiling.utils import ql_get_module
from capstone import Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from . import gp_api 
from . import beanpod_api
from . import teegris_api
from .gp import bigint_ops, crypto, general_objects, persistent_objects, properties, session, transient_objects


def __get_os_module(osname: str):
    return ql_get_module(f".os.{osname.lower()}.syscall")


def get_api_impl(func_name):
    api_func = getattr(gp_api, func_name, None)
    if api_func is not None:
        return api_func
    package = importlib.import_module('emulate.gp') 
    for _, modname, ispkg in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        if not ispkg:  # only import .py modules, skip subpackages if you want
            api_func = getattr(importlib.import_module(modname), func_name, None)
            if api_func is not None:
                return api_func
    api_func = getattr(beanpod_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(teegris_api, func_name, None)
    if api_func is not None:
        return api_func
    return gp_api.default_func


def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    buf = ql.mem.read(address, size)
    libld_base = ql.mem.get_lib_base("libld-l4.so")
    for insn in md.disasm(buf, address):
        ql.log.debug(
            f"{hex(insn.address-libld_base)}:: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}"
        )


def nop_instruction(ql: Qiling, offset, lib_name):
    # nops the instructions at an address
    ql.patch(offset, b"\x00\x00\xa0\xe1", lib_name)

counter = 0
ql_resolve_mem = 0x99999000

def fixup_got(ql: Qiling, ta_path, ta_elf:ELF):
    # ... :/
    ta_base = ql.mem.get_lib_base(ta_path.split("/")[-1])
    with open(ta_path, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            if section.name != ".rela.dyn":
                continue
            for rel in section.iter_relocations():
                reloc_addr = rel.entry['r_offset']
                r_type = rel.entry['r_info_type']
                addend = rel.entry.get('r_addend', None)
                print(f"  relocation at 0x{reloc_addr:x}, type={r_type}, addend={addend}")
                ql.mem.write_ptr(ta_base + reloc_addr, ta_base + addend)


def hook_ta_dl(ql: Qiling, ta_path, ta_elf:ELF):
    counter = 0
    ta_base = ql.mem.get_lib_base(ta_path.split("/")[-1])
    print(hex(ta_base + 0x1c50), ql.mem.read_ptr(ta_base + 0x1c50))
    ta_elf.address = ta_base
    ql.mem.map(ql_resolve_mem, 0x1000,info="dl_resolve")
    for func, addr in ta_elf.plt.items():
        ql.mem.write(ta_elf.got[func], (ql_resolve_mem+counter).to_bytes(4, "little"))
        ql.log.info(f'hooking api function {func}, {hex(addr)}, {hex(ql_resolve_mem+counter)}')
        ql.hook_address(get_api_impl(func), ql_resolve_mem+counter, user_data=func)
        counter += 4

def hook_ta_plt(ql: Qiling, ta, ta_elf: ELF):
    ta_base = ql.mem.get_lib_base(ta.split("/")[-1])
    ta_elf.address = ta_base
    return
    for func, addr in ta_elf.plt.items():
        ql.log.info(f'hooking api function {func}, {hex(addr)}')
        ql.hook_address(get_beanpod_api_impl(func), addr, user_data=func)


def trace_block(ql: Qiling, address, size):
    ql.log.debug("basic block at 0x%x" % (address))

