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
    REQ_LEN = 0x1C8
    RSP_LEN = 0x1C8
    if len(input) < 8:
        return False

    ## I can see commands, but preprocessing in TA is weird
    # cmds = [
    #     273,
    #     258,
    #     262,
    #     259,
    #     260,
    #     261,
    #     263,
    #     274,
    #     275,
    #     264,
    #     265,
    #     266,
    #     267,
    #     268,
    #     293,
    #     269,
    #     276,
    #     277,
    #     278,
    #     279,
    #     280,
    #     281,
    #     270,
    #     271,
    #     272,
    #     282,
    #     283,
    #     284,
    #     285,
    #     286,
    #     287,
    #     288,
    #     289,
    #     290,
    #     291,
    #     292,
    # ]
    # cmd = cmds[input[0] % len(cmds)]
    # data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = input

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
