from typing import Callable, TYPE_CHECKING
from qiling import Qiling
from qiling.core_hooks import AddressHookCallback
from qiling.os.const import INT, POINTER
from dataclasses import dataclass


if TYPE_CHECKING:
    from emulator.emulate.ta_mgr import TAEMU

@dataclass
class HookData:
    emu: 'TAEMU'
    func_name: str

class QseeMem:
    def __init__(self, emu:'TAEMU'):
        self.emu = emu
        self.ql = emu.ql
        self.mem_base = self.ql.mem.map_anywhere(0x1000, minaddr=0x130000, info="qsee_mem")
        self.next = self.mem_base
    
    def new_callback(self, callback:'AddressHookCallback'):
        addr = self.next
        self.next += self.ql.arch.pointersize
        self.ql.hook_address(callback, addr, user_data=HookData(self.emu, "qsee_noop_callback"))
        return addr

def get_qsee_mem_manager(emu:'TAEMU') -> QseeMem:
    if not hasattr(emu, "_qsee_mem"):
        emu._qsee_mem = QseeMem(emu)
    return emu._qsee_mem

def noop_callback(ql:Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "function": POINTER,
        "arg1": POINTER,
        "arg1len": INT,
        "arg2": POINTER,
        "arg2len": INT,
    })
    function = args['function']
    arg1 = args['arg1']
    arg1len = args['arg1len']
    arg2 = args['arg2']
    arg2len = args['arg2len']
    ql.log.info("qsee_callback(addr:%#x, ptr:%#x/%#x, ptr:%#x/%#x)", function, arg1, arg1len, arg2, arg2len)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
