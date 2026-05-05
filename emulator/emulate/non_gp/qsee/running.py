"""Runtime entrypoints for initializing, invoking, and fuzzing QSEE TAs."""

from contextlib import contextmanager
from dataclasses import dataclass
import importlib
import os
from pathlib import Path
import socket
import struct
from typing import TYPE_CHECKING, Generator, List
from enum import Enum

import pwn
from qiling import Qiling
from qiling.extensions.afl import ql_afl_fuzz
from qiling.core_hooks import HookRet
import unicorn
from emulate.gp.utils.err import *
from emulate.gp.utils.param import *
from emulate import qsee_api
from colorama import Fore, Back, Style
from emulate.mgr_cache import ql_cached_call
from emulate.params import MIN_PARAM_ADDR
from emulate.non_gp.qsee.qsee_mem import get_qsee_mem_manager
from emulate.models import TA_Function, StubbedFunction
from emulate.contextmanagers import mapped_memory_ctx, stop_hooks_at
from emulate.non_gp.qsee.params import QseeCommandParams
from emulate.common import CRASH_PC, CRASH_PC_2, NOTIMPL_PC, finalize_fuzzing
from emulate.contextmanagers import _func_end_emu, stop_hooks_at
from qiling.extensions.coverage import utils as cov_utils
from emulate.non_gp.qsee.models import QseeInteractiveMsg, InteractiveCmd, SetupTeardownAction

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


def _setup_or_teardown(
    self: "TAEMU",
    action: SetupTeardownAction,
    arg4: int,
):
    setup_or_teardown_fn = self.ta_funcs[TA_Function.SetupTeardown]
    self.log.info("[setup_or_teardown] start @%#0x", setup_or_teardown_fn.start)

    with stop_hooks_at(
        self.ql,
        *setup_or_teardown_fn.end,
        user_data="setup_or_teardown",
    ), mapped_memory_ctx(
        self.ql,
        0x1000,
        minaddr=MIN_PARAM_ADDR,
        info="setup_or_teardown[param3]",
    ) as params_mem:
        exec_ref = self.ql.mem.map_anywhere(
            0x1,
            minaddr=MIN_PARAM_ADDR,
            perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC,
            info="setup_or_teardown[exec_ref]",
        )
        self.ql.mem.write(exec_ref, pwn.p64(0))

        with pwn.context.local(arch="aarch64"):
            self.ql.mem.write(
                params_mem,
                pwn.flat(
                    [
                        exec_ref,  # Some form of cleanup function?
                        pwn.p64(4),  # maybe type of this object?
                    ]
                ),
            )

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
            return ret, None
        params: List[int] = []
        for i in range(5):
            params.append(
                self.ql.mem.read_ptr(params_mem + i * self.ql.arch.pointersize)
            )
        return ret, params


@ql_cached_call
def setup(self: "TAEMU"):
    ret, params = _setup_or_teardown(self, SetupTeardownAction.SETUP, 0x1101)

    # Quick sanity check, that params[4] was set to the cmd handler
    cmd_handler = params[4]
    cmd_handler_fn = self.ta_funcs[TA_Function.CommandHandler]
    if cmd_handler != cmd_handler_fn.start:
        self.ql.log.warning(
            "setup_or_teardown cmd_handler != command_handler (%#0x != %#0x)",
            cmd_handler,
            cmd_handler_fn.start,
        )
        return TEE_ERROR_BAD_STATE
    return ret


def teardown(self: "TAEMU"):
    ret, _ = _setup_or_teardown(self, SetupTeardownAction.TEARDOWN, 0x0)
    return ret


@ql_cached_call
def CElfFile_invoke(self: 'TAEMU'):
    elf_file_invoke_fn = self.ta_funcs[TA_Function.CElfFile_invoke]
    self.log.info("[CElfFile_invoke] start @%#0x", elf_file_invoke_fn.start)

    with stop_hooks_at(
        self.ql, *elf_file_invoke_fn.end, user_data="CElfFile_invoke"
    ), mapped_memory_ctx(
        self.ql, 0x1000, minaddr=MIN_PARAM_ADDR, info="Celf_Invoke[param3]"
    ) as params_mem:
        qsee_mem = get_qsee_mem_manager(self)
        acquire_sta_object_loc = qsee_mem.new_callback(qsee_api.acquire_sta_object)

        with pwn.context.local(arch="aarch64"):
            self.ql.mem.write(
                params_mem,
                pwn.flat(
                    [
                        pwn.p64(0),
                        pwn.p64(0),
                        pwn.p64(acquire_sta_object_loc),
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
            return ret

        setup_teardown_address = params[4]
        setup_teardown_func = self.ta_funcs[TA_Function.SetupTeardown]
        if setup_teardown_address != setup_teardown_func.start:
            self.ql.log.warning(
                "CElfFile_invoke setup_teardown_address != setup_teardown %#0x != %#0x",
                setup_teardown_address,
                setup_teardown_func.start,
            )
            return TEE_ERROR_BAD_STATE
        return ret


def start_qsee_interactive(self: "TAEMU"):
    with self.just_run():
        ret = CElfFile_invoke(self)
        if ret != TEE_SUCCESS:
            raise Exception(f"CElfFile_invoke ret != TEE_SUCCESS {ret:#0x}")

        ret = setup(self)
        if ret != TEE_SUCCESS:
            raise Exception(f"setup ret != TEE_SUCCESS {ret:#0x}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 1337))
    self.log.info("TA preset: %s", self.ta_path.name)
    self.log.info("Listening on port 0.0.0.0:1337")
    sock.listen()

    (client_socket, address) = sock.accept()
    self.ql.log.debug("CA connected from %s", address)

    while True:
        data = client_socket.recv(1024)
        self.ql.log.debug(f"Recv {data}")
        if len(data) == 0:
            return
        try:
            msg = QseeInteractiveMsg.from_bytes(data)
        except ValueError as e:
            self.ql.log.warning("Invalid interactive message: %s", e)
            QseeInteractiveMsg.send_DataMsg(client_socket, b"error\n", str(e).encode())
            continue

        self.ql.log.debug("Received message: %s", msg)

        if msg.cmd == InteractiveCmd.Exit:
            QseeInteractiveMsg.send_DataMsg(client_socket, b"ok\n")
            break

        elif msg.cmd == InteractiveCmd.InvokeCommand:
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
        else:
            self.ql.log.warning("Unknown interactive command: %s", msg.cmd)
            QseeInteractiveMsg.send_DataMsg(client_socket, b"unknown command error\n")
            continue

    if teardown(self) != TEE_SUCCESS:
        self.ql.log.warning("teardown ret != TEE_SUCCESS %#0x", ret)
        raise Exception(f"teardown ret != TEE_SUCCESS {ret:#0x}")

    return TEE_SUCCESS


def start_qsee_fuzz(
    self: "TAEMU",
    input_file,
    fuzz_harness: Path = None,
    fuzz_replay=False,
    rec_cov=False,
):
    self.log.info(f"start fuzz args is {input_file} {fuzz_harness} {fuzz_replay}")
    with self.just_run(cache=True):
        ret = CElfFile_invoke(self)
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f"CElfFile_invoke ret != TEE_SUCCESS {hex(ret)}")
            return

        ret = setup(self)
        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"[////Qsee setup////] return != TEE_SUCCESS {hex(ret)}"
            )
            return

    exit_addr = [x for x in self.ta_funcs[TA_Function.CommandHandler].end]
    exit_hooks = []

    self.fuzz_session = (
        None  # TODO: For now, set to None, so we are backwards compatible
    )

    init_fuzz = None
    if fuzz_harness is None:
        # def default_place_input_callback(ql: Qiling, input: bytes, _: int):
        #     print(f"Placing input: {input}")

        #     if len(input) < 4:
        #         return False

        #     ptypes = 0
        #     command_params = [NoneParam()] * 4
        #     cmd = u32(input[:4])
        #     print(f"cmdId: {cmd}")
        #     ret, params_mem = setup_params_fuzz(
        #         ql, cmd, ptypes, command_params
        #     )  # assume the session is already set
        #     if ret != TEE_SUCCESS:
        #         return False

        #     return True
        # place_input_callback = default_place_input_callback
        raise ValueError("fuzz_harness is required")
    else:
        # import shit
        spec = importlib.util.spec_from_file_location(
            os.path.basename(fuzz_harness)[:-3],
            os.path.abspath(fuzz_harness),
        )
        module = importlib.util.module_from_spec(spec)
        module.__package__ = __package__
        spec.loader.exec_module(module)
        place_input_callback = getattr(module, "place_input_callback")
        if hasattr(module, "init_fuzz"):
            init_fuzz = getattr(module, "init_fuzz")

    def crash_validation(
        ql: Qiling, result: int, input_bytes: bytes, round: int
    ) -> bool:
        print("crash callback: ", result, hex(ql.arch.regs.arch_pc))
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
        ql.arch.regs.arch_pc = 0x13370

    def start_afl(_ql: Qiling):
        if fuzz_replay:
            return
        if self.init_fuzz:
            return
        self.log.info("[TAEMU] starting afl")
        ql_afl_fuzz(
            _ql,
            input_file=input_file,
            place_input_callback=place_input_callback,
            exits=[0x13370],
            validate_crash_callback=crash_validation,
            always_validate=True,
        )

    # self.ql.os.fcall.cc.setRawParam(0, session.session_id_mem)

    if fuzz_replay:
        self.ql._debugger = self._debugger
        for e in exit_addr:
            exit_hooks.append(
                self.ql.hook_address(_func_end_emu, e, user_data="TA_InvokeCommand")
            )

    else:
        self.ql.hook_address(
            callback=start_afl,
            address=self.ta_funcs[TA_Function.CommandHandler].start,
        )

    # set hooks for fuzzer's recording logics
    for e in exit_addr:
        self.ql.hook_address(
            callback=finalize_fuzzing,
            address=e,
            user_data="Recording suspicious inputs",
        )
        self.ql.hook_address(callback=pivot2, address=e)

    # if init_fuzz is not None:
    #     self.init_fuzz = True
    #     init_fuzz(self, sid)
    #     self.init_fuzz = False

    if fuzz_replay:
        # use data from `input_file`
        input_data = open(input_file, "rb").read()
        if not place_input_callback(self.ql, input_data, -1):
            self.ql.log.warning("place_input returned -1, returning")
            return

        # record coverage while we replay `input_file`
        cov_path = self.get_cov_file_path(
            os.path.basename(input_file), os.path.dirname(fuzz_harness)
        )

        with cov_utils.collect_coverage(self.ql, "drcov", cov_path):
            self.ql.run(begin=self.ta_funcs[TA_Function.CommandHandler].start)
    else:
        self.ql.run(begin=self.ta_funcs[TA_Function.CommandHandler].start)

    ret = self.ql.os.fcall.cc.getReturnValue()
    self.log.info("InvokeCommand returned: %#0x", ret)

    for e in exit_hooks:
        self.ql.hook_del(e)
    exit_hooks = []
    self.ql.debugger = False
    ret = teardown(self)
    if ret != TEE_SUCCESS:
        self.ql.log.warning("[////Qsee teardown////] return != TEE_SUCCESS %#0x", ret)
    return
