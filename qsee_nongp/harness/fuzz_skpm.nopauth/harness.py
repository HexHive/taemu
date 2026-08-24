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

    # Example setup
    REQ_LEN = 0x500C
    RSP_LEN = 0x500C
    if len(input) < 8:
        return False

    cmds = [
        1,
        2,
        5,
        6,
        10,
        0xC,
        0xD,
        0xE,
        0xF,
        0x10,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x1E,
        0x1F,
        0x20,
        0x21,
        0x22,
        0x23,
        0x28,
        0x29,
        0x32,
        0x33,
        0x34,
        0x3C,
        0x3D,
        0x3E,
        0x46,
    ]
    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
