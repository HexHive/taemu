from qiling import Qiling


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
