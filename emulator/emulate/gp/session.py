from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.err import *
from .utils.param import *
from ..common import crash_notimpl
from ..custom.session_payload import get_good_response_payload


### beanpod IPC
# not fully emulated now, not actually open any session or invode any command

TEE_TIMEOUT_INFINITE = 0xFFFFFFFF

# Samsung PROCA (Process Authenticator) TA, UUID ...0050524f4341 (ascii .PROCA).
# Knox TAs (knxgud, KEYMST, ...) open a TA-to-TA session to it in an InvokeCommand
# *prelude* to authenticate the caller. On a PROCA-stripped / custom-kernel
# device the open fails with a soft-code and the dispatcher *waives* the check
# (log-and-continue) -- which is exactly the condition the kg_unlock /
# missing-caller-binding findings need. The emulator has no PROCA peer, so it IS
# that device: model the open to the PROCA UUID as returning the documented
# "no PROCA" soft-code so the dispatcher's fall-through reaches process_cmd.
# (RE/samsung_teegris/knxgud.md: 1179648=0x120000 "does not support PROCA",
# 1114137=0x110019 "custom kernel" both proceed.) Set TAEMU_PROCA_HARD=1 to make
# the open succeed normally instead.
PROCA_SOFTPASS_CODE = 0x120000

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

    hook_data.emu.update_shm(para_params)
    hook_data.emu.update_shm(para_session)
    hook_data.emu.update_shm(para_destination)
    ql.log.info(
        f"TEE_OpenTASession: {hex(para_destination)},{para_cancellationRequestTimeout},{para_paramTypes},{hex(para_params)},{hex(para_session)},{hex(para_returnOrigin)}"
    )

    # PROCA-stripped device model: opening a session to the PROCA TA returns the
    # "does not support PROCA" soft-code, which the Knox dispatchers waive.
    import os as _os
    try:
        dest_uuid = bytes(ql.mem.read(para_destination, 0x10))
    except Exception:
        dest_uuid = b""
    if b"PROCA" in dest_uuid and "TAEMU_PROCA_HARD" not in _os.environ:
        ql.log.info(f"[proca] TEE_OpenTASession -> soft-pass {hex(PROCA_SOFTPASS_CODE)} (no PROCA peer)")
        if para_session:
            ql.mem.write_ptr(para_session, 0xFFFFFFFF)   # TEE_HANDLE_NULL
        if para_returnOrigin:
            ql.mem.write_ptr(para_returnOrigin, 2)        # TEE_ORIGIN_TEE
        ql.os.fcall.cc.setReturnValue(PROCA_SOFTPASS_CODE)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

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

    hook_data.emu.update_shm(para_session)
    hook_data.emu.update_shm(para_params)
    hook_data.emu.update_shm(para_returnOrigin)

    ql.log.info(
        f"TEE_InvokeTACommand: {hex(para_session)},{para_cancellationRequestTimeout},{hex(para_commandID)},{para_paramTypes},{hex(para_params)},{hex(para_returnOrigin)}"
    )

    synthesized = para_session not in SESSIONS
    if synthesized:
        # Unknown session: the TA invoked a TA-to-TA command without a recorded
        # OpenTASession (or with a handle we didn't model). The old code called
        # emu_stop() but fell through to SESSIONS[para_session] -> KeyError,
        # aborting the run. Synthesize a placeholder and (below) return well-
        # formed empty output so the TA proceeds instead of crashing.
        ql.log.warning(
            f"TEE_InvokeTACommand: unknown session {hex(para_session)}, synthesizing placeholder"
        )
        SESSIONS[para_session] = Session(para_session, b"")

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

    if synthesized:
        # No modelled peer for this session: hand back well-formed empty output
        # (zero-fill the OUT/INOUT memrefs to their granted length) and SUCCESS,
        # so downstream code reads valid-length data instead of crashing on an
        # uninitialized buffer/length (e.g. a HMAC key populated right after).
        for i in range(4):
            ct = TEE_PARAM_TYPE_GET(para_paramTypes, i)
            if ct in (TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_INOUT) \
                    and buffer[i] and 0 < size[i] <= 0x10000:
                try:
                    ql.mem.write(buffer[i], b"\x00" * size[i])
                except Exception:
                    pass
        ql.log.info("TEE_InvokeTACommand: synthesized session -> zero-filled OUT memrefs, SUCCESS")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    # --- STST ICCC ReadData soft-pass (duldar verify_trusted_boot gate) ---
    # The STST sibling TA (UUID ...0053545354ab) is not in the corpus.
    # duldar's verify_trusted_boot asks STST for the SVB measurement (op 9)
    # and proceeds ONLY if the returned 4-byte value == 0
    # (RE/samsung_teegris/duldar.md "Trusted-boot prelude": out==0 -> proceed,
    # RPC fail -> 0x1000A, out!=0 -> 0x1000D). The generic forge path can't
    # marshal this (off-by-one param-type consts + 8B vs real 16B param
    # stride), so model the documented "measurement matches" outcome directly:
    # zero the response memref buffer(s) and return SUCCESS. Scoped to STST so
    # the existing per-TA payloads are untouched.
    target_bytes = bytes(session.target_ta) if session.target_ta else b""
    if b"STST" in target_bytes:
        for i in range(4):
            ct = TEE_PARAM_TYPE_GET(para_paramTypes, i)
            if ct in (4, 5, 6, 7):  # any memref (emu consts 4/5/6 or GP-std 5/6/7)
                buf = ql.mem.read_ptr(para_params + i * 16)
                sz = ql.mem.read_ptr(para_params + i * 16 + 8)
                if buf and 0 < sz <= 0x2000:
                    try:
                        ql.mem.write(buf, b"\x00" * min(sz, 0x40))
                    except Exception:
                        pass
        ql.log.info("[duldar] STST ICCC ReadData soft-pass -> out=0 (SVB match)")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

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
