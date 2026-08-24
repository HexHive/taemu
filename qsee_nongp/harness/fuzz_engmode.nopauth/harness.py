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

    REQ_LEN = 0x21C7D
    RSP_LEN = 0x20936
    if len(input) < 8:
        return False

    cmds = [
        1,
        2,
        3,
        0xB,
        0xC,
        0x10,
        0x14,
        0x15,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
    ]
    cmd = cmds[input[0] % len(cmds)] | 0xC000

    data = pwn.flat(
        {
            0: b"\x01",  # payload_version em_context_make_request:218, has to be 0x01
            1: pwn.p32(cmd),  # Cmd id
            5: input[1:],
        },
    )

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(
        ql, cmd_params, input
    )  # assume the session is already set
    return True
