CRASH_PC = 0xdeadbeef
CRASH_PC_2 = 0xdeadbeee
NOTIMPL_PC = 0xcafecafe
HEAP_MEM=0xaaaaa000

def crash(ql, func_name):
    ql.log.critical(f'=================[lr: {ql.arch.regs.lr:#0x}] [{func_name}] memory corruption detected!!')
    ql.arch.regs.arch_pc = CRASH_PC

def crash_notimpl(ql, msg):
    ql.log.critical(f'=================[lr: {ql.arch.regs.lr:#0x}] {msg}')
    ql.arch.regs.arch_pc = NOTIMPL_PC
