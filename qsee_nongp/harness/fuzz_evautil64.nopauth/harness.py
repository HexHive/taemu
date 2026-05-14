import struct
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
    ql.log.info("%s custom harness!!!! Placing input: %s", filename.upper(), input[:10])

    # Example setup
    REQ_LEN = 0x24
    RSP_LEN = 0x8

    if len(input) < 9:
        return False

    cmd_idx,buf1_len,buf2_len,dest,*_ = struct.unpack(">BHHI", input[:9])
    
    buf1_len &= 0xff
    buf2_len &= 0xff

    cmds = [0, 1]
    cmd = cmds[cmd_idx % len(cmds)]

    buf1_addr = ql.mem.map_anywhere(
        buf1_len, minaddr=0x140000, info=f"evautil_buffer1_{iters}"
    )
    buf2_addr = ql.mem.map_anywhere(
        buf2_len, minaddr=0x140000, info=f"evautil_buffer2_{iters}"
    )

    data = pwn.flat(
        {
            0 * 4: pwn.p32(cmd),
            
            # secure buf?
            1 * 4: pwn.p64(buf1_addr),
            3 * 4: buf1_len,
            
            5 * 4: pwn.p64(buf2_addr),
            7 * 4: buf2_len,
            
            8 * 4: dest,
        }
    )

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"
    # TODO: Add `unmap_when_done(...)` to the params.
    # TODO: Handle Out of memory errors.
    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)
    cmd_params.add_region(buf1_addr, buf1_len)
    cmd_params.add_region(buf2_addr, buf2_len)
    setup_qsee_fuzz(ql, cmd_params, input)
    return True
