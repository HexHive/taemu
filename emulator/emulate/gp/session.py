from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.err import *
from .utils.param import *
from ..common import crash_notimpl
from ..custom.session_payload import get_good_response_payload


### beanpod IPC
# not fully emulated now, not actually open any session or invode any command

TEE_TIMEOUT_INFINITE = 0xFFFFFFFF

SESSIONS = {}
SESSION_NUM = 0


class Session:
    def __init__(self, session_num, target_ta):
        self.session_num = session_num
        self.target_ta = target_ta


def TEE_OpenTASession(ql: Qiling, hook_data):
    global SESSIONS, SESSION_NUM
    params = ql.os.resolve_fcall_params(
        {
            "destination": POINTER,
            "cancellationRequestTimeout": UINT,
            "paramTypes": UINT,
            "params": POINTER,
            "session": POINTER,
            "returnOrigin": POINTER,
        }
    )
    para_destination = params["destination"]
    para_cancellationRequestTimeout = params["cancellationRequestTimeout"]
    para_paramTypes = params["paramTypes"]
    para_params = params["params"]
    para_session = params["session"]
    para_returnOrigin = params["returnOrigin"]

    ql.log.info(
        f"TEE_OpenTASession: {hex(para_destination)},{para_cancellationRequestTimeout},{para_paramTypes},{hex(para_params)},{hex(para_session)},{hex(para_returnOrigin)}"
    )

    # check TEE_OpenTASession in libuTbta.so, para_cancellationRequestTimeout is not used at all
    if para_cancellationRequestTimeout == TEE_TIMEOUT_INFINITE:
        pass

    # param size must be 4
    # https://globalplatform.org/wp-content/uploads/2018/06/GPD_TEE_Internal_Core_API_Specification_v1.1.2.50_PublicReview.pdf page 63, 1015
    for i in range(4):
        current_type = TEE_PARAM_TYPE_GET(para_paramTypes, 0)
        if (
            current_type == TEE_PARAM_TYPE_VALUE_INPUT
            or current_type == TEE_PARAM_TYPE_VALUE_INOUT
        ):
            a = ql.mem.read(para_params + i * 4, 4)
            b = ql.mem.read(para_params + 4 + i * 4, 4)
            ql.log.info(f"TEE_OpenTASession: value param: {hex(a)}:{hex(b)}")

        elif (
            current_type == TEE_PARAM_TYPE_MEMREF_INPUT
            or current_type == TEE_PARAM_TYPE_MEMREF_INOUT
        ):
            buffer = ql.mem.read(para_params + i * 4, 4)
            size = ql.mem.read(para_params + 4 + i * 4, 4)
            ql.log.info(f"TEE_OpenTASession: memref param: {hex(buffer)}:{hex(size)}")

    ql.mem.write_ptr(para_session, SESSION_NUM)
    SESSIONS[SESSION_NUM] = Session(SESSION_NUM, ql.mem.read(para_destination, 0x10))
    SESSION_NUM += 1

    if para_returnOrigin != 0:
        ql.mem.write_ptr(para_returnOrigin, TEE_SUCCESS)

    # @TODO: open a session for real

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_InvokeTACommand(ql: Qiling, hook_data):
    global SESSIONS, SESSION_NUM
    params = ql.os.resolve_fcall_params(
        {
            "session": UINT,
            "cancellationRequestTimeout": UINT,
            "commandID": UINT,
            "paramTypes": UINT,
            "params": POINTER,
            "returnOrigin": POINTER,
        }
    )
    para_session = params["session"]
    para_cancellationRequestTimeout = params["cancellationRequestTimeout"]
    para_commandID = params["commandID"]
    para_paramTypes = params["paramTypes"]
    para_params = params["params"]
    para_returnOrigin = params["returnOrigin"]

    ql.log.info(
        f"TEE_InvokeTACommand: {hex(para_session)},{para_cancellationRequestTimeout},{hex(para_commandID)},{para_paramTypes},{hex(para_params)},{hex(para_returnOrigin)}"
    )

    if para_session not in SESSIONS:
        ql.log.error(f"TEE_InvokeTACommand: not valid session {hex(para_session)}")
        ql.emu_stop()

    session = SESSIONS[para_session]

    # check TEE_OpenTASession in libuTbta.so, para_cancellationRequestTimeout is not used at all
    if para_cancellationRequestTimeout == TEE_TIMEOUT_INFINITE:
        pass

    a = [0] * 4
    b = [0] * 4
    buffer = [0] * 4
    size = [0] * 4
    for i in range(4):
        current_type = TEE_PARAM_TYPE_GET(para_paramTypes, i)
        if (
            current_type == TEE_PARAM_TYPE_VALUE_INPUT
            or current_type == TEE_PARAM_TYPE_VALUE_OUTPUT
            or current_type == TEE_PARAM_TYPE_VALUE_INOUT
        ):
            a[i] = ql.mem.read_ptr(para_params + i * 8)
            b[i] = ql.mem.read_ptr(para_params + 4 + i * 8)
            ql.log.info(f"\tvalue param: {hex(a[i])}:{hex(b[i])}")

        elif (
            current_type == TEE_PARAM_TYPE_MEMREF_INPUT
            or current_type == TEE_PARAM_TYPE_MEMREF_OUTPUT
            or current_type == TEE_PARAM_TYPE_MEMREF_INOUT
        ):
            buffer[i] = ql.mem.read_ptr(para_params + i * 8)
            size[i] = ql.mem.read_ptr(para_params + 4 + i * 8)
            ql.log.info(f"\tmemref param: {hex(buffer[i])}:{hex(size[i])}")

    if para_returnOrigin != 0:
        ql.mem.write_ptr(para_returnOrigin, TEE_SUCCESS)

    # @TODO: invoke a command for real
    # params should change accordingly in this function,
    # in order to make emulation continue, we might need to manually forge value in params
    # new_params = get_good_response_payload(ql, "3d08821c33a611e6a1fa089e01c83aa2.ta", ql.arch.regs.lr)
    new_params = get_good_response_payload(
        ql, ql.arch.regs.lr, hook_data.emu.ta_name, session
    )
    if new_params is not None:
        for i in range(4):
            if type(new_params[i]) == TEE_Param_Memref:
                ql.mem.write(buffer[i], new_params[i].data)
                ql.mem.write_ptr(para_params + i * 8 + 4, new_params[i].len)
            elif type(new_params[i]) == TEE_Param_value:
                ql.mem.write_ptr(a[i], new_params[i].a)
                ql.mem.write_ptr(b[i], new_params[i].b)

        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    else:
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"TEE_InvokeTACommand unknown target TA")
            return
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BUSY)
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_CloseTASession(ql: Qiling, hook_data):
    global SESSIONS, SESSION_NUM
    params = ql.os.resolve_fcall_params({"session": UINT})
    para_session = params["session"]

    ql.log.info(f"TEE_CloseTASession: {para_session}")

    if para_session not in SESSIONS:
        ql.log.error(f"TEE_InvokeTACommand: not valid session {hex(para_session)}")
        ql.emu_stop()

    del SESSIONS[para_session]

    ql.arch.regs.arch_pc = ql.arch.regs.lr
