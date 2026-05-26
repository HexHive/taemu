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

    REQ_LEN = 0x4418
    RSP_LEN = 0x4418
    if len(input) < 8:
        return False

    cmds = [
        1,
        0x102,
        0x103,
        0x104,
        0x105,
        0x106,
        0x107,
        0x108,
        0x109,
        0x10A,
        0x10B,
        0x10C,
        0x10D,
        0x10E,
        0x10F,
        0x110,
        0x111,
        0x112,
        0x113,
        0x114,
        0x115,
        0x116,
        0x117,
    ]
    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
