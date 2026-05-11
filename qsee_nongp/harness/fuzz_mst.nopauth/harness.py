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
    ql.log.info("%s custom harness!!!! Placing input: %s", filename.upper(), input.hex()[:10])

    REQ_LEN = 0xABC
    RSP_LEN = 0x8
    if len(input) < 8:
        return False

    cmds = [0xa0001, 0xa0000]
    cmd = cmds[input[0] % len(cmds)]

    print(f"cmd: {cmd:#0x}")
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
