from pwn import *
import json
from qiling import Qiling
from qiling.utils import ql_get_module
from capstone import Cs
from . import gp_api 
from . import beanpod_api


global TA_ELF


def __get_os_module(osname: str):
    return ql_get_module(f".os.{osname.lower()}.syscall")


def get_api_impl(func_name):
    api_func = getattr(gp_api, func_name, None)
    if api_func is not None:
        return api_func
    api_func = getattr(beanpod_api, func_name, None)
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

def hook_ta_dl(ql: Qiling, ta_path, ta_elf:ELF):
    counter = 0
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

