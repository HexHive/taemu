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

    REQ_LEN = 0x1412C
    RSP_LEN = 0x1412C
    if len(input) < 8:
        return False

    cmds = [
        16,
        32,
        48,
        64,
        80,
        96,
        112,
        128,
        144,
        256,
        272,
        288,
        304,
        320,
        336,
        352,
        357,
        368,
        373,
        528,
        544,
        560,
        576,
        592,
        608,
        624,
        640,
        656,
        657,
        768,
        784,
        800,
        816,
        832,
        848,
        864,
        880,
        883,
        884,
        885,
        886,
        896,
        899,
        900,
        901,
        902,
        912,
        913,
        914,
        1024,
        1025,
        1026,
        1056,
        1057,
        1072,
        1088,
        1104,
        1120,
        1136,
        1137,
        1138,
        1152,
        1153,
        1154,
        1155,
        1291,
        1293,
        1294,
        1295,
        1296,
        1297,
        1298,
        1299,
        1300,
        1301,
        1302,
        1536,
        1537,
        1538,
        1539,
        1540,
        1541,
        1542,
        1543,
        1544,
        1545,
        1546,
        1547,
        1548,
        1549,
        1550,
        1552,
        1553,
        1554,
        1555,
        1556,
        1557,
        1558,
        1559,
        1560,
        1561,
        1562,
        1563,
        1564,
        1565,
        1566,
        1567,
        1568,
        1569,
        1570,
        1571,
        1572,
        1573,
        1574,
        1575,
        1576,
        1577,
        1578,
        1579,
        1580,
        1581,
        1582,
        1584,
        1808,
        1809,
        1810,
        1811,
        1812,
        1813,
        1824,
        1825,
        1826,
        1827,
        1828,
        1829,
        1830,
        1831,
        1832,
        1833,
        1834,
        1841,
        1842,
        1843,
        2048,
        2064,
        2080,
        2096,
        2112,
    ]

    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
