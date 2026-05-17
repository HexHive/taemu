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

    REQ_LEN = 0xADF8
    RSP_LEN = 0xAE00
    if len(input) < 8:
        return False
    # This one is tough to reverse
    cmds = [
        0xC000C02,
        0xC000C03,
        0xC000C04,
        0xC000C05,
        0xC000C06,
        0xC000C07,
        0xC000C08,
        0xC000C09,
        0xC000C10,
        0xC000C11,
        0xC000C12,
        0xC000C13,
        0xC000C15,
        0xC000C16,
        0xC000C17,
        0xC000C18,
        0xC000C19,
        0xC000C1C,
        0xC000C1E,
        0xC000C14,
        0xC000C1F,
        0xC000C20,
    ]
    cmd = cmds[input[0] % len(cmds)]

    # If cmd is 0xc0de0003, then next DWORD determines the boorloader command: bc00, bc01, bc02, bc03, bc04, bc05
    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
