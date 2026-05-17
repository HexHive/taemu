"""Runtime entrypoints for initializing, invoking, and fuzzing QSEE TAs."""

import importlib
import os
from pathlib import Path
import socket
from typing import TYPE_CHECKING, List

import pwn
from qiling import Qiling
from qiling.extensions.afl import ql_afl_fuzz_custom
import unicorn
from emulate.gp.utils.err import *
from emulate.gp.utils.param import *
from emulate.mgr_cache import ql_cached_call
from emulate.params import MIN_PARAM_ADDR
from emulate.models import TA_Function
from emulate.contextmanagers import mapped_memory_ctx, stop_hooks_at
from emulate.non_gp.qsee.params import QseeCommandParams
from emulate.common import CRASH_PC, CRASH_PC_2, NOTIMPL_PC, finalize_fuzzing
from emulate.contextmanagers import _func_end_emu
from qiling.extensions.coverage import utils as cov_utils
from emulate.non_gp.qsee.models import (
    QseeInteractiveMsg,
    InteractiveCmd,
    QSEE_EXEC_REF_SLOT_SIZE,
    QSEE_EXEC_REF_TOTAL_SIZE,
    QseeSessionState,
    SetupTeardownAction,
    get_active_qsee_session_state,
)
from emulate.non_gp.qsee.utils import log_regs

if TYPE_CHECKING:
    from emulate.ta_mgr import TAEMU


def tz_app_cmd_handler(
    emu: "TAEMU",
    params: QseeCommandParams,
):
    """Wraps the command_handler to choose tz_command_handler and correctly provides the arguments."""
    command_handler_fn = emu.ta_funcs[TA_Function.CommandHandler]
    emu.log.info(
        "[command_handler:tz_app_cmd_handler] start @%#0x", command_handler_fn.start
    )

    with stop_hooks_at(
        emu.ql,
        *command_handler_fn.end,
        user_data="command_handler:tz_app_cmd_handler_end",
    ):
        params.setup(emu.ql)
        emu.ql.run(begin=command_handler_fn.start)
        ret = emu.ql.os.fcall.cc.getReturnValue()

        resp = params.read_resp(emu.ql)
        return ret, resp


QSEE_SETUP_PARAM_SIZE = 0x1000
QSEE_SETUP_PARAM_COUNT = 5
QSEE_FUZZ_RET_ADDR_OK = 0x13370

def _run_setup_or_teardown(
    self: "TAEMU",
    action: SetupTeardownAction,
    params_mem: int,
    arg4: int,
) -> int:
    setup_or_teardown_fn = self.ta_funcs[TA_Function.SetupTeardown]
    self.log.info("[setup_or_teardown] start @%#0x", setup_or_teardown_fn.start)

    with stop_hooks_at(
        self.ql,
        *setup_or_teardown_fn.end,
        user_data="setup_or_teardown",
    ):
        self.ql.os.fcall.cc.setRawParam(0, 0)
        self.ql.os.fcall.cc.setRawParam(1, action.value, argbits=16)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, arg4)

        self.ql.log.info(
            f"setup_or_teardown running at {setup_or_teardown_fn.start:#0x}"
        )
        self.ql.run(begin=setup_or_teardown_fn.start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        if ret != TEE_SUCCESS:
            self.ql.log.warning("setup_or_teardown ret != TEE_SUCCESS %#0x", ret)
        return ret


def init_qsee_session_state(self: "TAEMU") -> QseeSessionState:
    if getattr(self, "_qsee_setup_state", None) is not None:
        raise RuntimeError("QSEE setup state is already active")
    params_mem = self.ql.mem.map_anywhere(
        QSEE_SETUP_PARAM_SIZE,
        minaddr=MIN_PARAM_ADDR,
        perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
        info="qsee_state[params]",
    )
    exec_ref_mem = self.ql.mem.map_anywhere(
        QSEE_EXEC_REF_TOTAL_SIZE,
        minaddr=MIN_PARAM_ADDR,
        perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC,
        info="qsee_state[exec]",
    )
    exec_ref_next = exec_ref_mem
    self._qsee_setup_state = setup_state = QseeSessionState(
        params_mem=params_mem,
        params_size=QSEE_SETUP_PARAM_SIZE,
        exec_ref_base=exec_ref_mem,
        exec_ref_size=QSEE_EXEC_REF_TOTAL_SIZE,
        exec_ref_next=exec_ref_next,
    )
    setup_state.bind_exec_ref_slots(self.ql, self)

    ref_0 = setup_state.reserve_exec_ref_slot()
    # This address is not called, if it points to NULL
    self.ql.mem.write(ref_0, b"\x00" * QSEE_EXEC_REF_SLOT_SIZE)

    self.ql.mem.write(
        params_mem,
        pwn.flat(
            [
                pwn.p64(ref_0),  # Some form of cleanup function?
                pwn.p64(4),  # maybe type of this object?
            ]
        ),
    )
    return setup_state


def cleanup_qsee_session_state(
    self: "TAEMU", setup_state: QseeSessionState, *, clear_active: bool = True
) -> None:
    setup_state.teardown(self.ql)
    if clear_active and getattr(self, "_qsee_setup_state", None) is setup_state:
        delattr(self, "_qsee_setup_state")


def setup(self: "TAEMU") -> QseeSessionState | None:
    setup_state = get_active_qsee_session_state(self)
    if setup_state.setup_done:
        raise RuntimeError("QSEE setup already completed for the active state")
    ret = _run_setup_or_teardown(
        self, SetupTeardownAction.SETUP, setup_state.params_mem, 0x1101
    )
    if ret != TEE_SUCCESS:
        cleanup_qsee_session_state(self, setup_state)
        return None

    params: List[int] = []
    QSEE_SETUP_PARAM_COUNT = 5
    for i in range(QSEE_SETUP_PARAM_COUNT):
        params.append(
            self.ql.mem.read_ptr(setup_state.params_mem + i * self.ql.arch.pointersize)
        )
    
    setup_state.params = tuple(params)
    setup_state.setup_done = True
    cmd_handler = setup_state.params[4]

    # Quick sanity check, that params[4] was set to the cmd handler
    cmd_handler_fn = self.ta_funcs[TA_Function.CommandHandler]
    if cmd_handler != cmd_handler_fn.start:
        self.ql.log.warning(
            "setup_or_teardown cmd_handler != command_handler (%#0x != %#0x)",
            cmd_handler,
            cmd_handler_fn.start,
        )
        self.ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_STATE)
        cleanup_qsee_session_state(self, setup_state)
        return None

    return setup_state


def teardown(self: "TAEMU") -> int:
    setup_state = getattr(self, "_qsee_setup_state", None)
    if setup_state is None:
        self.ql.log.warning("teardown requested without an active setup state")
        self.ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_STATE)
        return TEE_ERROR_BAD_STATE
    if not setup_state.setup_done:
        self.ql.log.warning("teardown requested before QSEE setup completed")
        cleanup_qsee_session_state(self, setup_state)
        self.ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_STATE)
        return TEE_ERROR_BAD_STATE

    try:
        ret = _run_setup_or_teardown(
            self, SetupTeardownAction.TEARDOWN, setup_state.params_mem, 0x0
        )
    finally:
        cleanup_qsee_session_state(self, setup_state)
    return ret


@ql_cached_call
def CElfFile_invoke(self: "TAEMU"):
    elf_file_invoke_fn = self.ta_funcs[TA_Function.CElfFile_invoke]
    self.log.info("[CElfFile_invoke] start @%#0x", elf_file_invoke_fn.start)
    setup_state = get_active_qsee_session_state(self)

    with stop_hooks_at(
        self.ql, *elf_file_invoke_fn.end, user_data="CElfFile_invoke"
    ), mapped_memory_ctx(
        self.ql, 0x1000, minaddr=MIN_PARAM_ADDR, info="Celf_Invoke[param3]"
    ) as params_mem:
        sta_object_ptr = setup_state.register_named_noop(
            self.ql,
            self,
            name="sta_object",
            singleton_key="sta_object",
        )

        with pwn.context.local(arch="aarch64"):
            self.ql.mem.write(
                params_mem,
                pwn.flat(
                    [
                        pwn.p64(0),
                        pwn.p64(0),
                        pwn.p64(sta_object_ptr),
                        pwn.p64(0),  # STA Object?
                    ]
                ),
            )

        # Set memory address
        # self.ql.os.fcall.cc.setRawParam(0, 0x67)
        self.ql.os.fcall.cc.setRawParam(0, 0)
        self.ql.os.fcall.cc.setRawParam(1, 0, argbits=16)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, 0x1200, argbits=64)

        self.ql.run(begin=elf_file_invoke_fn.start)
        ret = self.ql.os.fcall.cc.getReturnValue()

        # Read the 4 params from the memory
        params: List[int] = []
        for i in range(6):
            params.append(
                self.ql.mem.read_ptr(params_mem + i * self.ql.arch.pointersize)
            )

        if ret != TEE_SUCCESS:
            self.ql.log.warning("CElfFile_invoke ret != TEE_SUCCESS %#0x", ret)
            cleanup_qsee_session_state(self, setup_state)
            return ret

        setup_teardown_address = params[4]
        setup_teardown_func = self.ta_funcs[TA_Function.SetupTeardown]
        if setup_teardown_address != setup_teardown_func.start:
            self.ql.log.warning(
                "CElfFile_invoke setup_teardown_address != setup_teardown %#0x != %#0x",
                setup_teardown_address,
                setup_teardown_func.start,
            )
            cleanup_qsee_session_state(self, setup_state)
            return TEE_ERROR_BAD_STATE
        return ret


def start_qsee_interactive(self: "TAEMU"):
    with self.just_run():
        init_qsee_session_state(self)
        ret = CElfFile_invoke(self)
        if ret != TEE_SUCCESS:
            raise Exception(f"CElfFile_invoke ret != TEE_SUCCESS {ret:#0x}")

        setup_state = setup(self)
        if setup_state is None:
            ret = self.ql.os.fcall.cc.getReturnValue()
            raise Exception(f"setup ret != TEE_SUCCESS {ret:#0x}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 1337))
    self.log.info("TA preset: %s", self.ta_path.name)
    self.log.info("Listening on port 0.0.0.0:1337")
    sock.listen()

    (client_socket, address) = sock.accept()
    self.ql.log.debug("CA connected from %s", address)

    try:
        while True:
            data = client_socket.recv(1024)
            self.ql.log.debug(f"Recv {data}")
            if len(data) == 0:
                return
            try:
                msg = QseeInteractiveMsg.from_bytes(data)
            except ValueError as e:
                self.ql.log.warning("Invalid interactive message: %s", e)
                QseeInteractiveMsg.send_DataMsg(
                    client_socket, b"error\n", str(e).encode()
                )
                continue

            self.ql.log.debug("Received message: %s", msg)

            if msg.cmd == InteractiveCmd.Exit:
                QseeInteractiveMsg.send_DataMsg(client_socket, b"ok\n")
                break

            if msg.cmd == InteractiveCmd.InvokeCommand:
                params = QseeCommandParams.from_msg(msg)
                ret, resp = tz_app_cmd_handler(self, params)
                self.ql.log.info("tz_app_cmd_handler ret: %#0x", ret)
                if ret != TEE_SUCCESS:
                    self.ql.log.warning("tz_app_cmd_handler ret != TEE_SUCCESS")
                    QseeInteractiveMsg.send_DataMsg(
                        client_socket, f"return error: {ret}".encode()
                    )
                    return ret
                QseeInteractiveMsg.send_DataMsg(client_socket, b"ok\n", resp)
                continue

            self.ql.log.warning("Unknown interactive command: %s", msg.cmd)
            QseeInteractiveMsg.send_DataMsg(client_socket, b"unknown command error\n")
    finally:
        client_socket.close()
        sock.close()
        ret = teardown(self, setup_state)
        if ret != TEE_SUCCESS:
            self.ql.log.warning("teardown ret != TEE_SUCCESS %#0x", ret)
            raise Exception(f"teardown ret != TEE_SUCCESS {ret:#0x}")

    return TEE_SUCCESS


def start_qsee_fuzz_replay(self: "TAEMU", input_file: Path, fuzz_harness: Path, rec_cov=False,):

    with self.just_run():
        init_qsee_session_state(self)
        ret = CElfFile_invoke(self)
        if ret != TEE_SUCCESS:
            self.ql.log.warning("CElfFile_invoke ret != TEE_SUCCESS %#0x", ret)
            return

        setup_state = setup(self)
        if setup_state is None:
            ret = self.ql.os.fcall.cc.getReturnValue()
            self.ql.log.warning("[////Qsee setup////] return != TEE_SUCCESS %#0x", ret)
            return

    exit_addr = [x for x in self.ta_funcs[TA_Function.CommandHandler].end]
    exit_hooks = []
    
    # import shit
    spec = importlib.util.spec_from_file_location(
        os.path.basename(fuzz_harness)[:-3],
        os.path.abspath(fuzz_harness),
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = __package__
    spec.loader.exec_module(module)
    place_input_callback = getattr(module, "place_input_callback", None)
    if place_input_callback is None:
        raise RuntimeError("place_input_callback not found in '%s' harness file", fuzz_harness)

    exit_hooks.append(
        self.ql.hook_address(
            _func_end_emu,
            QSEE_FUZZ_RET_ADDR_OK,
            user_data="TA_InvokeCommandReturn",
        )
    )
    for e in exit_addr:
        exit_hooks.append(
            self.ql.hook_address(_func_end_emu, e, user_data="TA_InvokeCommand")
        )

    try:
        input_data = open(input_file, "rb").read()
        if not place_input_callback(self.ql, input_data, -1):
            self.ql.log.warning("place_input returned -1, returning")
            return

        cov_path = self.get_cov_file_path(
            os.path.basename(input_file), os.path.dirname(fuzz_harness)
        )

        with cov_utils.collect_coverage(self.ql, "drcov", cov_path):
            self.ql.arch.regs.lr = QSEE_FUZZ_RET_ADDR_OK
            log_regs(self.ql, "[Replay pre-run]")
            self.ql.run(begin=self.ta_funcs[TA_Function.CommandHandler].start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.log.info("InvokeCommand returned: %#0x", ret)
        return

    finally:

        for e in exit_hooks:
            self.ql.hook_del(e)

        with self.just_run():
            ret = teardown(self)

        curr_params = getattr(self, "curr_params")
        if isinstance(curr_params, QseeCommandParams):
            curr_params.teardown(self.ql)
            self.curr_params = None

        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                "[////Qsee teardown////] return != TEE_SUCCESS %#0x", ret
            )


def start_qsee_fuzz(
    self: "TAEMU",
    input_file,
    fuzz_harness: Path = None,
    fuzz_replay=False,
    rec_cov=False,
):
    self.log.info(f"start fuzz args is {input_file} {fuzz_harness} {fuzz_replay}")
    if fuzz_replay:
        return start_qsee_fuzz_replay(self, input_file, fuzz_harness, rec_cov)
    
    with self.just_run():
        init_qsee_session_state(self)
        ret = CElfFile_invoke(self)
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f"CElfFile_invoke ret != TEE_SUCCESS {hex(ret)}")
            return

        setup_state = setup(self)
        if setup_state is None:
            ret = self.ql.os.fcall.cc.getReturnValue()
            self.ql.log.warning(
                f"[////Qsee setup////] return != TEE_SUCCESS {hex(ret)}"
            )
            return

    exit_addr = [x for x in self.ta_funcs[TA_Function.CommandHandler].end]
    exit_hooks = []

    self.fuzz_session = (
        None  # TODO: For now, set to None, so we are backwards compatible
    )

    if fuzz_harness is None:
        raise ValueError("fuzz_harness is required")
    # import shit
    spec = importlib.util.spec_from_file_location(
        os.path.basename(fuzz_harness)[:-3],
        os.path.abspath(fuzz_harness),
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = __package__
    spec.loader.exec_module(module)
    place_input_callback = getattr(module, "place_input_callback")

    def place_input_callback_verbose(
        ql: Qiling, input_bytes: bytes, iters: int
    ) -> bool:
        ok = place_input_callback(ql, input_bytes, iters)
        if ok:
            log_regs(ql, f"[AFL child placed input round={iters}]")
        return ok

    def crash_validation(
        ql: Qiling, result: int, input_bytes: bytes, round: int
    ) -> bool:
        ql.log.info("crash callback: %#0x %#0x", result, ql.arch.regs.arch_pc)
        if (
            ql.arch.regs.arch_pc == CRASH_PC
            or ql.arch.regs.arch_pc == CRASH_PC_2
            or ql.arch.regs.arch_pc == NOTIMPL_PC
        ):
            return True
        if result == 6:
            return True
        # if ql.arch.regs.arch_pc not in exit_addr:
        # return True
        return False

    def pivot2(ql: Qiling):
        ql.arch.regs.arch_pc = QSEE_FUZZ_RET_ADDR_OK

    # def log_unmapped_access(
    #     ql: Qiling, access: int, address: int, size: int, value: int
    # ) -> None:
    #     if access != unicorn.UC_MEM_FETCH_UNMAPPED:
    #         return
    #     ql.log.critical(
    #         "[FETCH_UNMAPPED] addr=%#0x size=%#0x value=%#0x pc=%#0x lr=%#0x sp=%#0x x0=%#0x x1=%#0x x2=%#0x x3=%#0x",
    #         address,
    #         size,
    #         value,
    #         ql.arch.regs.arch_pc,
    #         ql.arch.regs.lr,
    #         ql.arch.regs.sp,
    #         ql.arch.regs.x0,
    #         ql.arch.regs.x1,
    #         ql.arch.regs.x2,
    #         ql.arch.regs.x3,
    #     )
    # fetch_unmapped_hook = self.ql.hook_mem_unmapped(log_unmapped_access)

    def fuzz_callback_verbose(ql: Qiling) -> int:
        log_regs(ql, "[AFL fuzz-callback]")
        start_addr = self.ta_funcs[TA_Function.CommandHandler].start
        try:
            ql.arch.uc.emu_start(start_addr, 0)
        except unicorn.UcError as err:
            return err.errno
        return unicorn.UC_ERR_OK

    for e in exit_addr:
        exit_hooks += [
            self.ql.hook_address(
                callback=finalize_fuzzing,
                address=e,
                user_data="Recording suspicious inputs",
            ),
            self.ql.hook_address(
                callback=pivot2,
                address=e,
            ),
        ]

    try:
        def afl_hook(ql: Qiling):
            log_regs(ql, "[AFL hook pre-run]")
            ql_afl_fuzz_custom(
                ql,
                input_file=input_file,
                place_input_callback=place_input_callback_verbose,
                fuzzing_callback=fuzz_callback_verbose,
                exits=[QSEE_FUZZ_RET_ADDR_OK],
                validate_crash_callback=crash_validation,
                always_validate=True,
            )
        
        self.ql.hook_address(
            callback=afl_hook,
            address=self.ta_funcs[TA_Function.CommandHandler].start,
        )

        log_regs(self.ql, "[Parent pre-run]")
        self.ql.arch.regs.lr = QSEE_FUZZ_RET_ADDR_OK
        self.ql.run(begin=self.ta_funcs[TA_Function.CommandHandler].start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.log.info("InvokeCommand returned: %#0x", ret)
        return

    finally:

        for e in exit_hooks:
            self.ql.hook_del(e)

        with self.just_run():
            ret = teardown(self)

        curr_params = getattr(self, "curr_params")
        if isinstance(curr_params, QseeCommandParams):
            curr_params.teardown(self.ql)
            self.curr_params = None

        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                "[////Qsee teardown////] return != TEE_SUCCESS %#0x", ret
            )
