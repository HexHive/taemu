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
    REQ_LEN = 0x1680C
    RSP_LEN = 0x1680C
    if len(input) < 8:
        return False

    cmds = [
        0,
        1,
        4,
        5,
        6,
        7,
        8,
        10,
        11,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        42,
        43,
        45,
        46,
        49,
        130,
        150,
        151,
        152,
        153,
        154,
        201,
        202,
        203,
        300,
        301,
        302,
        303,
        304,
        311,
        312,
        313,
        314,
        315,
        316,
        317,
        318,
        1332,
        1333,
        1334,
        1335,
        1336,
        1337,
        1338,
        1339,
        1340,
        1341,
        1342,
        1343,
        1344,
        1345,
        1346,
        1347,
        1348,
        1349,
        1350,
        1351,
        1352,
        1353,
        1354,
        1355,
        1356,
        1357,
        1358,
        1359,
        1360,
        1361,
    ]

    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
