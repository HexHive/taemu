from typing import TYPE_CHECKING
import pwn
from qiling import Qiling
from pathlib import Path


if TYPE_CHECKING:
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz
else:
    from emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz

filename = Path(__file__).stem.replace("_fuzz", "")


def place_input_callback(ql: Qiling, input: bytes, iters: int):
    del iters  # We are not using pers iters
    ql.log.info("%s custom harness!!!! Placing input: %s", filename.upper(), input[:10])

    REQ_LEN = 0xC
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
        }
    )

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)  # assume the session is already set
    return True
