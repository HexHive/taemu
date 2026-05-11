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
    REQ_LEN = 0x1000
    RSP_LEN = 0x03C0
    if len(input) < 8:
        return False

    cmds = [
        0x66,
        0x67,
        0x68,
        0x69,
        0x6A,
        0x6B,
        0x6C,
        0x6D,
        0x6E,
        0x6F,
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7B,
        0x7C,
        0x7D,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,
        0x90,
        0x91,
        0x92,
        0x93,
        0x96,
        0x97,
        0x7A,
        0x7E,
        0x7F,
        0x94,
        0x95,
        0x98,
        0x99,
        0x9A,
        0xCA,
        0xCB,
        0xCC,
        0xCD,
        0xCE,
        0xCF,
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xD4,
        0xD6,
        0xD7,
        0xD8,
        0xD9,
        0xDA,
        0xDB,
        0xDC,
        0xDD,
        0xE3,
        0xF9,
        0xFC,
        0xFA,
    ]

    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p8(cmd), 2: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
