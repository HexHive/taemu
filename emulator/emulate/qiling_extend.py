from qiling import Qiling
from qiling.const import QL_ARCH


class QilingExtend(Qiling):

    def __init__(
        self,
        *args,
        emu=None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.emu = emu

    def get_emu(self):
        return self.emu

    def get_caller_pc(self):
        """
        Get the PC of the caller function.
        Support architectures: ARM, ARM64, X86, X86_64

        Returns:
            int: The PC of the caller function.
        """

        if self.arch.type == QL_ARCH.ARM:
            # FIXME: ONLY compatible with arm v5/v6 calling convention
            return self.arch.regs.lr
        elif self.arch.type == QL_ARCH.ARM64:
            return self.arch.regs.lr
        elif self.arch.type == QL_ARCH.X86:
            return self.mem.read_ptr(self.arch.regs.ebp + self.arch.pointersize)
        elif self.arch.type == QL_ARCH.X86_64:
            return self.mem.read_ptr(self.arch.regs.rbp + self.arch.pointersize)
        else:
            raise ValueError(f"Unsupported architecture: {self.arch.type}")
