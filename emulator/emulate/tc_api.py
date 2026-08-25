from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp_api import printf 


def taskstorage_openssesion(ql, hook_data):
    ql.mem.map(0x6969000, 0x1000, info="[tc] session data (hack)")
    ql.mem.write_ptr(0x6969000, 0x40)
    session = ql.mem.read_ptr(ql.arch.regs.r3)
    ql.mem.write_ptr(session, 0x6969000)
    ql.emu_stop()


def get_current_session_id(ql, hook_data):
    ql.os.fcall.cc.setReturnValue(69)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def uart_printf_func(ql, hook_data):
    hook_data.func_name = "printf"
    printf(ql, hook_data)


def quit_early(ql, hook_data):
    ql.emu_stop()
