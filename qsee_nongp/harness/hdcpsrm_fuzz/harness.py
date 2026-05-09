# from params import *
from typing import TYPE_CHECKING
import pwn
from qiling import Qiling
from pathlib import Path


if TYPE_CHECKING:
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams
    from emulator.emulate.non_gp.qsee.params import setup_qsee_fuzz
else:
    from emulate.non_gp.qsee.params import QseeCommandParams
    from emulate.non_gp.qsee.params import setup_qsee_fuzz

filename = Path(__file__).stem.replace("_fuzz", "")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    """
    AFL bytes -> py-params
    """
    print(f"{filename.upper()} custom harness!!!! Placing input: {input}")

    REQ_LEN = 0xc
    RSP_LEN = 0x20936
    if len(input) < 4:
        return False

    cmds = [
        1,
        2,
        3,
        4,
        5,
    ]
    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat(
        {
            0: pwn.p32(cmd),  # Cmd id
            4: input[1:],
        },
    )

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(
        ql, cmd_params, input
    )  # assume the session is already set
    return True
