from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from ..gp.utils.err import *
from ..gp.utils.param import *

RPMSESSIONS = {}
RPMSESSION_BUFFER_L2_MEM = 0x920000

RPMSESSIONS_L1 = None
RPMSESSION_BUFFER_L1_MEM = 0x980000


def ut_pf_rpmb_open(ql: Qiling, func_name):
    global RPMSESSIONS_L1

    ret = TEE_SUCCESS
    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_open: ")
    else:
        ql.log.info("ut_pf_rpmb_open: more than one L1 rpmb session, could be wrong!")
    m = ql.mem.map_anywhere(
        0x1000, minaddr=RPMSESSION_BUFFER_L1_MEM, info="Rpmsession_L1_buffer"
    )
    RPMSESSIONS_L1 = m

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_rpmb_read_data_blocks(ql: Qiling, func_name):
    global RPMSESSIONS_L1
    params = ql.os.resolve_fcall_params(
        {"sessionID": UINT, "buf": POINTER, "size": UINT}
    )
    para_sessionID = params["sessionID"]
    para_buf = params["buf"]
    para_size = params["size"]

    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_read_data_blocks: empty session")
    else:
        content = bytes(ql.mem.read(RPMSESSIONS_L1, para_size))
        ql.mem.write(para_buf, content)

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_rpmb_close(ql: Qiling, func_name):
    global RPMSESSIONS_L1

    ret = TEE_SUCCESS
    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_close: empty session")
    else:
        ql.mem.unmap(RPMSESSIONS_L1, 0x1000)
        RPMSESSIONS_L1 = None

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_RpmbOpenSession(ql: Qiling, func_name):
    global RPMSESSIONS
    params = ql.os.resolve_fcall_params({"sessionID": UINT})
    para_sessionID = params["sessionID"]

    ret = TEE_SUCCESS
    if para_sessionID in RPMSESSIONS:
        RPMSESSIONS[para_sessionID]["opened"] = True
    else:
        RPMSESSIONS[para_sessionID] = {"opened": True, "content": b""}

    ql.os.fcall.cc.setReturnValue(para_sessionID)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_RpmbCloseSession(ql: Qiling, func_name):
    global RPMSESSIONS
    params = ql.os.resolve_fcall_params({"sessionID": UINT})
    para_sessionID = params["sessionID"]

    ret = TEE_SUCCESS
    if para_sessionID in RPMSESSIONS:
        RPMSESSIONS[para_sessionID]["opened"] = False

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_RpmbReadData(ql: Qiling, func_name):
    global RPMSESSIONS
    params = ql.os.resolve_fcall_params(
        {"sessionID": UINT, "buffer": POINTER, "size": UINT, "retSize": POINTER}
    )
    para_sessionID = params["sessionID"]
    para_buffer = params["buffer"]
    para_size = params["size"]
    para_retSize = params["retSize"]

    ret = TEE_SUCCESS
    if not para_sessionID in RPMSESSIONS:
        ret = TEE_ERROR_RPM_SESSION
    elif not RPMSESSIONS[para_sessionID]["opened"]:
        # not opened
        ret = TEE_ERROR_RPM_SESSION
    else:
        content = RPMSESSIONS[para_sessionID]["content"][:para_size]
        ql.mem.write(para_buffer, content)
        ql.mem.write_ptr(para_retSize, 0)

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_RpmbWriteData(ql: Qiling, func_name):
    global RPMSESSIONS
    params = ql.os.resolve_fcall_params(
        {"sessionID": UINT, "buffer": POINTER, "size": UINT, "retSize": POINTER}
    )
    para_sessionID = params["sessionID"]
    para_buffer = params["buffer"]
    para_size = params["size"]
    para_retSize = params["retSize"]

    ret = TEE_SUCCESS
    if not para_sessionID in RPMSESSIONS:
        ret = TEE_ERROR_RPM_SESSION
    elif not RPMSESSIONS[para_sessionID]["opened"]:
        # not opened
        ret = TEE_ERROR_RPM_SESSION
    else:
        content = bytes(ql.mem.read(para_buffer, para_size))
        RPMSESSIONS[para_sessionID]["content"] = content
        ql.mem.write_ptr(para_retSize, 0)

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
