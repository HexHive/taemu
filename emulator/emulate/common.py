CRASH_PC = 0xDEADBEEF
CRASH_PC_2 = 0xDEADBEEE
NOTIMPL_PC = 0xCAFECAFE
HEAP_MEM = 0xAAAAA000


def crash(ql, func_name):
    ql.log.critical(
        f"=================[lr: {ql.arch.regs.lr:#0x}] [{func_name}] memory corruption detected!!"
    )
    ql.arch.regs.arch_pc = CRASH_PC


def crash_notimpl(ql, msg):
    ql.log.critical(f"=================[lr: {ql.arch.regs.lr:#0x}] {msg}")
    ql.arch.regs.arch_pc = NOTIMPL_PC
