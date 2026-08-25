from qiling import Qiling


def log_regs(ql: Qiling, label: str) -> None:
    ql.log.debug(
        "%s pc=%#0x lr=%#0x sp=%#0x x0=%#0x x1=%#0x x2=%#0x x3=%#0x",
        label,
        ql.arch.regs.arch_pc,
        ql.arch.regs.lr,
        ql.arch.regs.sp,
        ql.arch.regs.x0,
        ql.arch.regs.x1,
        ql.arch.regs.x2,
        ql.arch.regs.x3,
    )
