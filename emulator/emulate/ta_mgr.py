from dataclasses import dataclass
import functools
import os
import tempfile
import importlib

import time
import threading

from pathlib import Path

import pwn
from unicorn.arm64_const import UC_ARM64_REG_CP_REG, UC_ARM64_REG_W30, UC_ARM64_REG_X30
import hashlib

import yaml

from .mgr_cache import ql_cached_call

from . import qsee_api
# from qiling import Qiling
from .qiling_extend import QilingExtend as Qiling
from qiling.extensions.afl import ql_afl_fuzz
from qiling.extensions.coverage import utils as cov_utils
from qiling.extensions import pipe
from .redis_queue import RedisQueue
import unicorn
from pwn import *
from .gp.utils.param import TEE_Param_Memref, TEE_Param_value
import json
import socket
from hexdump import hexdump
from colorama import Fore, Back, Style
from ctypes import *
from enum import Enum
from .params import MIN_PARAM_ADDR, Param, ValueParam, MemRefParam, NoneParam, setup_params, setup_params_fuzz
from .gp.utils.err import *
from .gp.utils.param import *
from .emulator_no_loader import (
    HookData,
    fixup_got,
    mitee_setup,
    qsee_setup,
    hook_ta_dl,
    hook_ta_custom,
    teegris_32_setup, 
    optee_setup,
)
from .common import CRASH_PC, NOTIMPL_PC, CRASH_PC_2, finalize_fuzzing
from typing import Any, Callable, Optional, List, Dict
from .fuzz_record import Record, Status

def parse_msg(msg):
    f = int(msg[0])
    l = int(msg[1])
    data = msg[2 : 2 + l]
    return (f, l, data)

def pivot_df_not_hit(ql: Qiling, ta_mgr) -> None:
    ql.log.info(
        Fore.RED
        + f"double fetch location not reproduced!"
        + Style.RESET_ALL
    )
    ta_mgr.log.info(f"double fetch location not reproduced!")
    ql.stop()
    if ta_mgr.status == Status.DF_FUZZING:
        open(os.path.join(ta_mgr.df_fuzz_out, "out", "default", "DF_NOT_REPRODUCED"), "w+").write("double fetch not reproduced")

def df_validated(ql: Qiling, user_data) -> None:
    ta_mgr, input_file = user_data
    ql.log.info(
        Fore.GREEN
        + f"df validated (no crash)!"
        + Style.RESET_ALL
    )
    ta_mgr.log.info(f"df validated!")
    open(input_file + ".df", "wb+").write(open(input_file, "rb").read())
    ql.stop()

def pivot(ql: Qiling, cur) -> None:
    ql.log.info(
        Fore.BLUE
        + f"[{cur}] reach end @{ql.arch.regs.read('PC'):#0x}"
        + Style.RESET_ALL
    )
    ql.stop()

def get_n_ptype(param_type: int, n: int):
    if n >= 0 and n <= 3:
        return (param_type >> (4 * n)) & 0xF
    else:
        print("Fatal error")
        exit(-1)


class FUNCS(Enum):
    func_TEEC_InitializeContext = 0
    func_TEEC_OpenSession = 1
    func_TEEC_InvokeCommand = 2
    func_TEEC_CloseSession = 3
    func_TEEC_RegisterSharedMemory = 4
    func_TEEC_ReleaseSharedMemory = 5
    func_TEEC_FinalizeContext = 6
    func_TEEC_AllocateSharedMemory = 7

@dataclass
class Session:
    session_id_mem: int
    session_id: int
    sessionContext: int


def get_ta_uuid(ta_name):
    ta_name = ta_name.replace("-", "")
    return bytes.fromhex(ta_name)


def require_class_attr(param_name, attr_name):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, **kwargs):
            if param_name in kwargs:
                val = kwargs[param_name]

                if val != getattr(self, attr_name):
                    raise ValueError(
                        f"{param_name}={val} does not match self.{attr_name}={getattr(self, attr_name)}"
                    )
                return func(self, **kwargs)
            else:
                raise ValueError(
                    f"{param_name} not found in args or kwargs. Probably a racing bug here."
                )

        return wrapper

    return decorator


class EmuLog:

    def __init__(self, ql: Qiling):
        self._ql = ql

    def info(self, text: str, *args):
        self._ql.log.info(Fore.BLUE + text + Style.RESET_ALL, *args)


class TA_Function(Enum):
    CreateEntryPoint = "TA_CreateEntryPoint"
    OpenSessionEntryPoint = "TA_OpenSessionEntryPoint"
    InvokeCommandEntryPoint = "TA_InvokeCommandEntryPoint"
    CloseSessionEntryPoint = "TA_CloseSessionEntryPoint"
    DestroyEntryPoint = "TA_DestroyEntryPoint"
    
    CElfFile_invoke = "CElfFile_invoke"
    SetupTeardown = "setup_teardown"
    CommandHandler = "command_handler"

@dataclass
class StubbedFunction:
    name: TA_Function
    start: int
    end: List[int]
    base: int = 0

class TAEMU:

    def __init__(
        self,
        ql: Qiling,
        tee: str,
        ta_path: str,
        ta_elf: ELF,
        *,
        status: Status = None,
        record_max_items=5000,
        record_q: Optional[RedisQueue] = None,
        use_cache: bool = False,
    ):
        self.ql = ql
        self.log = EmuLog(ql)
        self.tee = tee
        self.ta_path = Path(ta_path)
        self.ta_name = self.ta_path.stem
        self.ta_elf = ta_elf
        self.ta_base = ql.mem.get_lib_base(self.ta_path.name)
        if self.tee.endswith("nongp"):
            self.taUUID = None
        else:
            self.taUUID = get_ta_uuid(self.ta_name)
        self.ta_elf.address = self.ta_base
        self.HEAP = {"allocated": {}, "freed": {}, "redzones": {}}
        self.exit_non_implemented = None
        self.curr_params = None
        self.session_counter = 0
        self.init_fuzz = False
        self.df_replay_placed = False
        self.status = status
        self.df_fuzz_out = None
        self.log.info(f"TAEMU initialized in {self.status.name} mode")

        self.use_cache = use_cache
        # Simple process management for recorder
        self._record_q = record_q
        if self.status in (Status.REPLAYING, Status.FUZZING):
            # only visiable for one thread (separate copy on the process level)
            self.curr_record_key = None
            self.curr_input = None
            self.fuzz_session = None
            self._record_meta: Dict[str, Any] = {}
            self._record_lock = threading.RLock()
            self._record_max_items = record_max_items
            self._record: List[Record] = []

        self.crash_on_not_implemented = False
        if "TAEMU_CRASH_NOTIMPL" in os.environ:
            self.crash_on_not_implemented = True

        self.sessions:List[Session] = []
        self._debugger = ql._debugger

        self.CreateEntryPoint_ret = None
        self._load_ta_info()
        self.stubbed_functions: Dict[TA_Function, StubbedFunction] = {}
        if self.tee.endswith("nongp"):
            self._assign_functions([
                TA_Function.CElfFile_invoke,
                TA_Function.SetupTeardown,
                TA_Function.CommandHandler,
            ])
            
        else:
            self._assign_functions(
                [TA_Function.InvokeCommandEntryPoint,
                 TA_Function.CreateEntryPoint,
                 TA_Function.OpenSessionEntryPoint,
                 TA_Function.CloseSessionEntryPoint,
                 TA_Function.DestroyEntryPoint,
                 ])


    def _load_ta_info(self):
        yml_path = self.ta_path.with_suffix(".yml")
        if yml_path.exists():
            with open(yml_path, "r") as f:
                yml_info = yaml.safe_load(f)
            self.ta_info = {}
            for k, v in yml_info.items():
                self.ta_info[f"{k}_start"] = v["start"]
                self.ta_info[f"{k}_end"] = v["end"]
            return
        json_path = self.ta_path.with_suffix(".json")
        with open(json_path, "r") as f:
            ta_info = json.load(f)
        self.ta_info = ta_info

    def _assign_functions(self, func_names: List[TA_Function]):
        ta_info = self.ta_info

        needed = set([f"{x.value}_end" for x in func_names] + [f"{x.value}_start" for x in func_names])
        if not needed.issubset(set(ta_info)):
            print(f"TA info error, missing keys: {needed - set(ta_info)}")
            exit(-1)
        
        base = 0
        if self.ta_elf.pie:
            base = self.ta_base
        
        for func in func_names:
            func_end = f"{func.value}_end"
            func_start = f"{func.value}_start"
            if len(ta_info[func_end]) == 0:
                print(f"TA_{func.value}_end is empty!")
                exit(-1)
            self.stubbed_functions[func] = StubbedFunction(
                name=func,
                start=ta_info[func_start] + base,
                end=[x + base for x in ta_info[func_end]],
            )
            print("Parsed function: ", func.value)

    def setup(self):
        # fix relocations and other miscellanous setup
        fixup_got(self.ql, self.ta_path, self.ta_elf, self.ta_base)
        if self.tee == "mitee":
            # handle tpidr_el0 and fix relocations
            mitee_setup(self.ql, self.ta_path, self.ta_base)
        if self.tee[:4] == "qsee":
            qsee_setup(self.ql, self.ta_path, self.ta_base)
        if self.tee == "teegris" and self.ql.arch.pointersize == 4:
            teegris_32_setup(self.ql, self.ta_path, self.ta_base)
        if self.tee == "optee":
            optee_setup(self.ql, self.ta_path, self.ta_base, self)

    def hook(self):
        # setup api hooks
        hook_ta_dl(
            self.ql,
            self.ta_path,
            self.ta_elf,
            self,
            is_mitee=self.tee == "mitee",
            is_tc=self.tee == "trustedcore",
            is_qsee=self.tee[:4] == "qsee",
            is_optee=self.tee == "optee"
        )
        hook_ta_custom(
            self.ql,
            self.ta_path,
            self.ta_elf,
            self,
        )
        self.ql.do_lib_patch()

    def start(self, *args):
        if self.status in (Status.FUZZING, Status.REPLAYING):
            print(*args)
            self.start_fuzz(
                args[0], 
                args[1], 
                fuzz_replay=(self.status == Status.REPLAYING),
            )
        elif self.status in (Status.DF_FUZZING, Status.DF_REPLAY, Status.DF_VALIDATE):
            self.df_fuzz(*args, 
                fuzz_replay=(self.status == Status.DF_REPLAY), 
                df_validate=(self.status == Status.DF_VALIDATE)
            )
        else:
            self.start_interactive()

    def hash_regs(self):
        #TODO: to discuss, cause this will generate big int, which is unfriendly to parse json file later on in other languages
        return str(int(hashlib.md5(str(self.ql.arch.regs.save()).encode()).hexdigest(),16))

    def get_shm(self, pointer, size: Optional[int] = None, is_read: bool = True):
        if self.curr_params is None:
            return None

        # self.log.info(f"[ql_get_shm] get_shm for pointer {pointer:#0x}")

        for p in self.curr_params:
            if isinstance(p, MemRefParam):
                if (
                    p.is_shared
                    and pointer >= p.shm_pybuf
                    and pointer <= p.shm_pybuf + p.size
                ):
                    if self.status in (Status.FUZZING, Status.REPLAYING) and not self.init_fuzz:
                        self.update_records(
                            key=self.curr_record_key,
                            item=Record(
                                pointer,
                                size if size is not None else None,
                                regs={
                                    "PC": self.ql.arch.regs.read("PC"),
                                    "ret_addr": self.ql.get_caller_pc(),
                                    "ret_addr_offset": self.ql.get_caller_pc() - self.ql.emu.ta_base,
                                    "is_read": is_read,
                                    "reg_hash": self.hash_regs()
                                },
                            ),
                            op=lambda a, b: a + [b],
                        )
                    return p
        return None

    def update_shm(self, pointer, size: Optional[int] = None):
        param = self.get_shm(pointer, size, is_read=True)
        if param is None:
            return
        if self.status == Status.INTERACTIVE:
            self.ql.mem.write(param.shm_pybuf, param.shm.to_bytes()[: param.size])

    def writeback_shm(self, pointer, size: Optional[int] = None):
        param = self.get_shm(pointer, size, is_read=False)
        if param is None:
            return
        if self.status == Status.INTERACTIVE:
            curr_data = self.ql.mem.read(param.shm_pybuf, param.size)
            param.shm.from_bytes(curr_data)

    @require_class_attr("key", "curr_record_key")
    def get_records(self, key):
        with self._record_lock:
            return self._record

    @require_class_attr("key", "curr_record_key")
    def set_records(self, *, key, value: List[Record]):
        with self._record_lock:
            if len(value) >= self._record_max_items:
                self.log.info(
                    f"[set_records] record cache full, truncating to {self._record_max_items} items"
                )
                value = value[: self._record_max_items]

            self._record = value
            self._record_meta["last_accessed"] = time.time()

    @require_class_attr("key", "curr_record_key")
    def update_records(
        self,
        *,
        key,
        item: Record,
        op: Callable,
    ):
        with self._record_lock:
            if self._record:
                if len(self._record) >= self._record_max_items:
                    self.log.info(
                        f"[update_records] record cache full, skipping update"
                    )
                    self._record_meta["last_accessed"] = time.time()
                    self._record_meta["full_record"] = True
                    self._record_meta["skipped_updates"] = (
                        self._record_meta["skipped_updates"]
                        if "skipped_updates" in self._record_meta
                        else 0
                    ) + 1
                    return

                self._record = op(self._record, item)
                self._record_meta["last_accessed"] = time.time()
            else:
                self.set_records(key=key, value=[item])
        self.ql.log.debug(f"[update_records] current records is {self.records_info()}")

    def records_info(self):
        with self._record_lock:
            return {
                "num_items": len(self._record),
                "key": self.curr_record_key,
                **self._record_meta,
                "details": self._record,
            }

    def save_records_to_queue(
        self, checker: Optional[Callable[[List[Record]], bool]] = None
    ):
        with self._record_lock:
            if checker is not None:
                if not checker(self._record):
                    return
            record_copy = self._record.copy()
            record_meta_copy = self._record_meta.copy()

        self.log.info(
            f"Saving records to queue: {self.curr_input}, {self.curr_record_key}"
        )
        if self._record_q:
            self._record_q.put(
                {
                    "input": self.curr_input,
                    "key": self.curr_record_key,
                    "records": record_copy,
                    "meta": record_meta_copy,
                }
            )

    def clear_records(self):
        if self.status in (Status.FUZZING, Status.REPLAYING):
            with self._record_lock:
                self._record.clear()
                self._record_meta.clear()
                self.curr_record_key = None

    def tz_app_cmd_handler(self,
        cmd: qsee_api.QseeTzCmdIdent,
        params: List[Param],
    ):
        """ Wraps the command_handler to choose tz_command_handler and correctly provides the arguments.
        """
        command_handler_fn = self.stubbed_functions[TA_Function.CommandHandler]
        self.log.info("[command_handler:tz_app_cmd_handler] start @%#0x", command_handler_fn.start)
        for e in command_handler_fn.end:
            self.ql.hook_address(pivot, e, user_data="command_handler:tz_app_cmd_handler_end")
        
        params_mem = self.ql.mem.map_anywhere(
            0x1000, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, info="command_handler[params]",
        )


        extract_resp = lambda ql, resp_mem, resp_len: None

        # pwn flat is megafucky? Idk why. Dict doesn't work, list does.
        with pwn.context.local(binary=self.ta_elf):

            if self.ta_path.name == "engmode.elf":
                req, resp_len = (
                    pwn.flat({
                    }, length=0x21c7d, 
                    #filler=string.ascii_letters.encode()
                    ),
                    0x20936
                )
            
            elif self.ta_path.name == "vaultkeeper.elf":
                req, resp_len = (
                    pwn.flat({0: pwn.p32(0)}, length=0xadf8),
                    0xae00,
                )
                def _vaultkeep_resp(ql: Qiling, resp_mem, resp_len):
                    message_loc = resp_mem + 0x5af6
                    message = ql.mem.string(message_loc)
                    resp_code = ql.mem.read_ptr(resp_mem + 1)
                    ql.log.info("vaultkeeper response: message=%s, resp_code=%#x", message, resp_code)
                extract_resp = _vaultkeep_resp


            elif self.ta_path.name == "fingerpr.elf":
                req, resp_len = (
                    pwn.flat({
                        0: pwn.p32(0x74),
                    },length=0xc5),
                    0xdef,
                )
            elif self.ta_path.name == "evautil64.elf":
                req, resp_len = (
                    pwn.flat({
                        0: pwn.p32(0),
                        4: 0xdeadbeef, # pointer to the thing?
                        12: pwn.p32(0x100), # size of the thing?
                    },length=0xabc),
                    0xdef,
                )
            elif self.ta_path.name == "featenabler.elf":
                req, resp_len = (
                    pwn.flat({
                        0: pwn.p32(0x4), # cmdid
                    },length=0xabc),
                    0x100,
                )
            
            elif self.ta_path.name == "ops.elf":
                req, resp_len = (
                    pwn.flat({
                        0: pwn.p32(0), # only command = 0x0
                    },length=0xc5, 
                    ),
                    0xdef,
                )

            elif self.ta_path.name == "mst.elf":
                req, resp_len = (
                    pwn.flat({
                        0: pwn.p32(0xa0000), # commands [0xa0001, 0xa0000]
                    },length=0xabc, 
                    ),
                    0xdef,
                )
            
            else:
                raise ValueError(f"Unknown TA: {self.ta_path.name}")

            req_len = len(req)
            req_mem = self.ql.mem.map_anywhere(req_len, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, info="command_handler[qsee_ns]")
            self.ql.mem.write(req_mem, req)

            resp_mem = self.ql.mem.map_anywhere(resp_len, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, info="command_handler[qsee_ns]")

            assert (req_len | resp_len) >> 0x20 == 0, f"req_len | resp_len is not 32bit max: {req_len | resp_len:#x}"
            payload = pwn.flat(
                {
                    0x0:{
                        0x0: params_mem + 0x100,
                        0x8: 0x24
                    },
                    # args for tz_command_handler
                    0x100: {
                        # ! (cmd len | resp len) >> 0x20 == 0 # they should be 32bit max

                        # cmd ptr
                        0x0: req_mem ,
                        # cmd len
                        0x8: req_len, # min 0x24. For engmode, has to be 0x21c7d

                        # resp ptr
                        0x10: resp_mem,
                        # resp len
                        0x18: resp_len, # min 0x8
                        
                        # arg4
                        # - arg4 should be a null byte, so we don't invoke GPAppLib_*
                        0x20: 0 # arg4
                    },
                }, filler=b"\x00")
        
            self.ql.mem.write(
                params_mem,
                payload  
            )

        self.ql.os.fcall.cc.setRawParam(1, qsee_api.QseeCmdIdent.Cmd0.value)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, 0x0001)
        
        self.ql.run(begin=command_handler_fn.start)
        ret = self.ql.os.fcall.cc.getReturnValue()
        
        extract_resp(self.ql, resp_mem, resp_len)

        return ret


    def command_handler(self,
        sid:int | None,
        cmd: qsee_api.QseeCmdIdent,
        ptypes: int,
        params: List[Param],
    ):
        command_handler_fn = self.stubbed_functions[TA_Function.CommandHandler]
        self.log.info("[command_handler] start @%#0x", command_handler_fn.start)
        for e in command_handler_fn.end:
            self.ql.hook_address(pivot, e, user_data="command_handler_end")
        
        params_mem = self.ql.mem.map_anywhere(
            0x1000, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, info="command_handler[params]"
        )

        for s in self.sessions:
            if s.session_id == sid:
                self.ql.os.fcall.cc.setRawParam(0, s.session_id_mem)
                break

        self.ql.os.fcall.cc.setRawParam(1, cmd.value)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, ptypes)
        
        self.ql.run(begin=command_handler_fn.start)
        ret = self.ql.os.fcall.cc.getReturnValue()
        return ret

    @ql_cached_call
    def setup_or_teardown(self, action: qsee_api.SetupTeardownAction):
        setup_or_teardown_fn = self.stubbed_functions[TA_Function.SetupTeardown]
        self.log.info("[setup_or_teardown] start @%#0x", setup_or_teardown_fn.start)
        for e in setup_or_teardown_fn.end:
            self.ql.hook_address(pivot, e, user_data="setup_or_teardown")

        params_mem = self.ql.mem.map_anywhere(
            0x1000, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, info="setup_or_teardown[param3]"
        )
        exec_ref = self.ql.mem.map_anywhere(0x1000, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC, info="setup_or_teardown[exec_ref]")
        self.ql.mem.write(exec_ref, pwn.p64(0))

        with pwn.context.local(arch="aarch64"):
            self.ql.mem.write(params_mem, pwn.flat([
                exec_ref, # Some form of cleanup function?
                pwn.p64(4), # maybe type of this object?
            ]))

        self.ql.os.fcall.cc.setRawParam(0, 0)
        self.ql.os.fcall.cc.setRawParam(1, action.value, argbits=16)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, 0x1101)

        self.ql.log.info(f"setup_or_teardown running at {setup_or_teardown_fn.start:#0x}")
        self.ql.run(begin=setup_or_teardown_fn.start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        if ret != TEE_SUCCESS:
            self.ql.log.warning("setup_or_teardown ret != TEE_SUCCESS %#0x", ret)
            return ret
        
        params = []
        for i in range(6):
            params.append(
                self.ql.mem.read_ptr(params_mem + i * self.ql.arch.pointersize)
            )
        cmd_handler = params[4]
        cmd_handler_fn = self.stubbed_functions[TA_Function.CommandHandler]
        if cmd_handler != cmd_handler_fn.start:
            self.ql.log.warning("setup_or_teardown cmd_handler != command_handler %#0x != %#0x", cmd_handler, cmd_handler_fn.start)
            return TEE_ERROR_BAD_STATE
        return ret

    @ql_cached_call
    def CElfFile_invoke(self):
        elf_file_invoke_fn = self.stubbed_functions[TA_Function.CElfFile_invoke]
        self.log.info("[CElfFile_invoke] start @%#0x", elf_file_invoke_fn.start)
        #CElfFile_invoke(undefined8 param_1,short param_2,long *param_3,int param_4)        

        for e in elf_file_invoke_fn.end:
            self.ql.hook_address(pivot, e, user_data="CElfFile_invoke_end")
        
        params_mem = self.ql.mem.map_anywhere(
            0x1000, minaddr=MIN_PARAM_ADDR, perms=3, info="Celf_Invoke[param3]"
        )
        exec_section = self.ql.mem.map_anywhere(0x1000, minaddr=MIN_PARAM_ADDR, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC, info="[sta_exec_section]")

        acquire_sta_object_loc = exec_section + 0x30
        with pwn.context.local(arch="aarch64"):
            self.ql.mem.write(params_mem, 
                pwn.flat([
                    pwn.p64(0),
                    pwn.p64(0),
                    pwn.p64(acquire_sta_object_loc),
                    pwn.p64(0), # STA Object? 
                ]))
            
        self.ql.hook_address(
            qsee_api.acquire_sta_object,
            acquire_sta_object_loc,
            user_data=HookData(self, "param3_acquire"),
        )

        # Set memory address
        # self.ql.os.fcall.cc.setRawParam(0, 0x67)
        self.ql.os.fcall.cc.setRawParam(0, 0)
        self.ql.os.fcall.cc.setRawParam(1, 0, argbits=16)
        self.ql.os.fcall.cc.setRawParam(2, params_mem)
        self.ql.os.fcall.cc.setRawParam(3, 0x1200, argbits=64)
        
        # # don't fail on bti, paclib
        fake_parent_ret = exec_section + 0x10
        # self.ql.uc.reg_write(UC_ARM64_REG_X30, fake_parent_ret)

        # def cp_read(crn, crm, op0, op1, op2):
        #     return self.ql.uc.reg_read(UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2))

        # def cp_write(crn, crm, op0, op1, op2, val):
        #     self.ql.uc.reg_write(UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2, val))
        
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
        setup_teardown_func = self.stubbed_functions[TA_Function.SetupTeardown]
        if setup_teardown_address != setup_teardown_func.start:
            self.ql.log.warning("CElfFile_invoke setup_teardown_address != setup_teardown %#0x != %#0x", setup_teardown_address, setup_teardown_func.start)
            return TEE_ERROR_BAD_STATE
        return ret


    def CreateEntryPoint(self):
        create_entrypoint = self.stubbed_functions[TA_Function.CreateEntryPoint]
        self.log.info(
            f"[TA_CreateEntryPoint] start @{create_entrypoint.start:#0x}"
        )
        entrypoint = create_entrypoint.start

        # stop at TA_CreateEntryPoint_end
        for e in create_entrypoint.end:
            self.ql.hook_address(pivot, e, user_data="TA_CreateEntryPoint")

        # _debugger = self.ql._debugger
        # self.ql.debugger = False
        #self.ql._debugger = self._debugger
        self.ql.run(begin=entrypoint)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.CreateEntryPoint_ret = ret
        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"[////TA_CreateEntryPoint////] return != TEE_SUCCESS {hex(ret)}"
            )
            return ret
        return ret

    def OpenSession(self):
        open_session_fn = self.stubbed_functions[TA_Function.OpenSessionEntryPoint]

        if self.CreateEntryPoint_ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"Calling OpenSession without succesfull CreateEntryPoint!"
            )
            return TEE_ERROR_BAD_STATE
        # TODO: support parameters
        session_opened = self.session_counter
        self.session_counter += 1
        session_id_mem = self.ql.mem.map_anywhere(
            0x1000, minaddr=min_addr, perms=3, info="session_id"
        )
        sessionContext = self.ql.mem.map_anywhere(
            0x1000, minaddr=min_addr, perms=3, info="session_context"
        )
        self.ql.mem.write_ptr(session_id_mem, session_opened)
        new_session = Session(session_id_mem, session_opened, sessionContext)
        self.sessions.append(new_session)

        self.log.info(
            f"[TA_OpenSessionEntryPoint] start @{open_session_fn.start:#0x}"
        )
        for e in open_session_fn.end:
            self.ql.hook_address(pivot, e, user_data="TA_OpenSessionEntryPoint")

        # ql._debugger = _debugger
        self.ql.os.fcall.cc.setRawParam(2, sessionContext)
        self.ql.run(begin=open_session_fn.start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        open_session_fn.ret = ret
        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}"
            )
            return ret, None
        return ret, new_session

    def InvokeCommand(self, sid:int, cmd, ptypes, params):
        invoke_command_fn = self.stubbed_functions[TA_Function.InvokeCommandEntryPoint]
        exit_hooks = []
        self.ql.log.debug(f"TEEC_InvokeCommand {sid} {cmd} {ptypes:#0x}")
        session = None
        for s in self.sessions:
            if sid == s.session_id:
                session = s
                break
        if session is None:
            self.ql.log.error(f"unknown session {sid}")
            return TEE_ERROR_BAD_STATE

        status, params_mem = setup_params(
            self.ql,
            session,
            cmd,
            ptypes,
            params,
            is_32bit=self.ql.arch.pointersize == 4,
        )
        if status != TEE_SUCCESS:
            return status
        self.curr_params = params

        self.log.info(
            f"[TA_InvokeCommandEntryPoint] start @{invoke_command_fn.start:#0x}"
        )
        # stop at TA_InvokeCommandEntryPoint_end
        for e in invoke_command_fn.end:
            exit_hooks.append(
                self.ql.hook_address(pivot, e, user_data="TA_InvokeCommandEntryPoint")
            )

        # run
        self.ql._debugger = self._debugger
        self.ql.run(begin=invoke_command_fn.start)
        ret = self.ql.os.fcall.cc.getReturnValue()

        params_mem_read = params_mem
        # sync output
        for i, param in enumerate(params):
            if isinstance(param, ValueParam):
                param.a = int.from_bytes(self.ql.mem.read(params_mem_read, 4), "little")
                params_mem_read += 4
                param.b = int.from_bytes(self.ql.mem.read(params_mem_read, 4), "little")
                params_mem_read += 4
                if self.ql.arch.pointersize == 4:
                    params_mem_read += 8
            elif isinstance(param, MemRefParam):
                pybuf = self.ql.mem.read_ptr(params_mem_read)
                param.buf = bytes(self.ql.mem.read(pybuf, param.size))
                self.ql.mem.unmap(pybuf, (param.size + 0xFFF) & ~0xFFF)
                params_mem_read += self.ql.arch.pointersize * 2
            elif isinstance(param, NoneParam):
                params_mem_read += self.ql.arch.pointersize * 2
            else:
                self.ql.log.error(f"unknown ptype {t}")
                return TEE_ERROR_BAD_PARAMETERS

        for e in exit_hooks:
            self.ql.hook_del(e)
            exit_hooks = []
        self.curr_params = None
        self.ql.mem.unmap(params_mem & 0xFFFFFFFFFFFFF000, 0x1000)

        return ret

    def CloseSession(self, sid):
        self.ql.log.debug(f"TA_CloseSessionEntryPoint {sid}")
        if self.tee == "t6":
            self.ql.log.warning(f"t6 CloseSessionEntryPoint not supported by emulator")
            return

        session = None
        idx = 0
        for i, s in enumerate(self.sessions):
            if sid == s.session_id:
                session = s
                idx = i
                break
        if session is None:
            self.ql.log.error(f"unknown session {sid}")
            return TEE_ERROR_BAD_STATE
        close_session_fn = self.stubbed_functions[TA_Function.CloseSessionEntryPoint]
        self.log.info(
            f"[CloseSessionEntryPoint] start @{close_session_fn.start:#0x}"
        )
        for e in close_session_fn.end:
            self.ql.hook_address(pivot, e, user_data="TA_CloseSessionEntryPoint_end")

        # self.ql._debugger = self._debugger

        self.ql.os.fcall.cc.setRawParam(0, session.sessionContext)
        self.ql.run(begin=close_session_fn.start)

        self.ql.mem.unmap(session.session_id_mem, 0x1000)
        self.ql.mem.unmap(session.sessionContext, 0x1000)
        self.sessions.pop(idx)

    def DestroyEntryPoint(self):
        destroy_entrypoint_fn = self.stubbed_functions[TA_Function.DestroyEntryPoint]
        self.log.info(
            f"[TA_DestroyEntryPoint] start @{destroy_entrypoint_fn.start:#0x}"
        )
        if self.tee == "t6":
            self.ql.log.warning(f"t6 TA_DestroyEntryPoint not supported by emulator")
            return
        for e in destroy_entrypoint_fn.end:
            self.ql.hook_address(pivot, e, user_data="TA_DestroyEntryPoint_end")

        # self.ql._debugger = self._debugger

        self.ql.run(begin=destroy_entrypoint_fn.start)

        self.CreateEntryPoint_ret = None

    def start_interactive(self):
        bufc2py = {}
        libc = CDLL("")
        # int shmget(key_t key, size_t size, int shmflg);
        shmget = libc.shmget
        shmget.restype = c_int
        shmget.argtypes = (c_int, c_size_t, c_int)
        # void* shmat(int shmid, const void *shmaddr, int shmflg);
        shmat = libc.shmat
        shmat.restype = c_void_p
        shmat.argtypes = (c_int, c_void_p, c_int)
        # int shmdt(const void *shmaddr);
        shmdt = libc.shmdt
        shmdt.restype = c_int
        shmdt.argtypes = (c_void_p,)

        if self.tee.endswith("nongp"):
            # TODO: Simple taemu context manager
            _debugger = self.ql.debugger
            self.ql.debugger = False
            ret = self.CElfFile_invoke()
            if ret != TEE_SUCCESS:
                self.ql.log.warning("CElfFile_invoke ret != TEE_SUCCESS %#0x", ret)
                return ret
            ret = self.setup_or_teardown(qsee_api.SetupTeardownAction.SETUP)
            if ret != TEE_SUCCESS:
                self.ql.log.warning("setup_or_teardown ret != TEE_SUCCESS %#0x", ret)
                return ret
            self.ql.debugger = _debugger
            
            ## Mock command_handler usage
            ret = self.tz_app_cmd_handler(qsee_api.QseeTzCmdIdent.Cmd0, [])
            return 0

        ret = self.CreateEntryPoint()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f"CreateEntryPoint ret != TEE_SUCCESS {hex(ret)}")
            return

        # block here after TA_CreateEntryPoint, now we start socket, waiting to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 1337))
        self.log.info("Listening on port 0.0.0.0:1337")
        sock.listen()

        (client_socket, address) = sock.accept()
        self.ql.log.debug(f"CA connected from {address}")

        while True:
            data = client_socket.recv(1024)
            self.ql.log.debug(f"Recv {data}")
            if len(data) == 0:
                return
            (f, l, d) = parse_msg(data)

            if (
                f == FUNCS.func_TEEC_InitializeContext.value
                and l == 5
                and d == b"start"
            ):
                self.ql.log.debug(f"TEEC_InitializeContext")
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_OpenSession.value and l == 0x10:
                uuid = (
                    p32(u32(d[:4]), endian="big")
                    + p16(u16(d[4:6]), endian="big")
                    + p16(u16(d[6:8]), endian="big")
                    + d[8:]
                ).hex()
                self.ql.log.debug(f"TEEC_OpenSession from uuid {uuid}")
                if "-" in self.ta_path:
                    if uuid != self.ta_path.replace("-", "").split("/")[-1][:-3] and uuid != self.ta_path.replace("-", "").split("/")[-1][:-3].lower():
                        self.ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        return
                else:
                    if uuid != self.ta_path.split("/")[-1][:-3] and uuid != self.ta_path.split("/")[-1][:-3].lower():
                        self.ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        exit(-1)
                ret, new_session = self.OpenSession()
                if ret != TEE_SUCCESS:
                    self.ql.log.warning(
                        f"[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}"
                    )
                    return
                client_socket.send(b"ok" + p32(new_session.session_id))
            elif (f == FUNCS.func_TEEC_RegisterSharedMemory.value or f == FUNCS.func_TEEC_AllocateSharedMemory.value) and l == 16:
                shm_key = u32(d[:4])
                size = u32(d[4:8])
                buf = u64(d[8:])
                func_name = "TEEC_RegisterSharedMemory" if f == FUNCS.func_TEEC_RegisterSharedMemory.value else "TEEC_AllocateSharedMemory"
                self.ql.log.info(
                    f"{func_name} {shm_key:#0x} {buf:#0x} {size:#0x}"
                )

                class SHM(Structure):
                    _fields_ = [
                        ("msg", c_byte * size),
                    ]

                    @classmethod
                    def from_key(cls, key):
                        shm_id = shmget(key, sizeof(SHM), 0o666)
                        if shm_id < 0:
                            return
                        ptr = shmat(shm_id, 0, 0)
                        if ptr:
                            ptr = cast(ptr, POINTER(SHM))
                            return ptr.contents

                    def to_bytes(self):
                        return bytes(self.msg)

                    def from_bytes(self, data):
                        memmove(addressof(self.msg), bytes(data), len(data))

                    def __del__(self):
                        ptr = cast(addressof(self), c_void_p)
                        shmdt(ptr)

                shm = SHM.from_key(shm_key)
                bufc2py[buf] = (size, shm)

                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_InvokeCommand.value and l == 108:
                sid = u32(d[:4])
                cmd = u32(d[4:8])
                ptypes = u32(d[8:12])
                self.ql.log.debug(f"TEEC_InvokeCommand {sid} {cmd} {ptypes:#0x}")

                command_params: List['Param'] = []
                params = d[12:]
                pcnt = 0
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        a = u32(params[pcnt * 24 : pcnt * 24 + 4])
                        b = u32(params[pcnt * 24 + 4 : pcnt * 24 + 8])
                        command_params.append(ValueParam(a, b))
                        self.ql.log.debug(f"value p {a} {b}")
                    # tmp mem
                    elif t >= 5 and t <= 7:
                        buf = u64(params[pcnt * 24 : pcnt * 24 + 8])
                        size = u64(params[pcnt * 24 + 8 : pcnt * 24 + 16])
                        self.ql.log.debug(f"mem p {buf:#0x} {size:#0x}")
                        if buf not in bufc2py:
                            self.ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                            sock.close()
                            return
                        (shm_size, shm) = bufc2py[buf]
                        if size > shm_size:
                            self.ql.log.error(
                                f"size larger than shm: {size:#0x} v.s. {shm_size}"
                            )
                            sock.close()
                            return
                        # get shared content
                        self.ql.log.debug(f"SHM IN content: {shm.to_bytes()}")
                        # shared memory
                        memref = MemRefParam(shm.to_bytes(), size)
                        memref.is_shared = True
                        memref.shm = shm
                        command_params.append(memref)
                    elif t == 0:
                        command_params.append(NoneParam())
                    else:
                        self.ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        return
                    pcnt += 1

                ret = self.InvokeCommand(sid, cmd, ptypes, command_params)
                self.ql.log.info(f"InvokeCommand returned: {hex(ret)}")

                # sync shm
                pcnt = 0
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        # @TODO: send back a and b
                        self.ql.log.debug("value type output not implemneted")
                    elif t >= 5 and t <= 7:
                        # copy back memory to shm
                        memref = command_params[pcnt]
                        buf = u64(params[pcnt * 24 : pcnt * 24 + 8])
                        size = u64(params[pcnt * 24 + 8 : pcnt * 24 + 16])
                        (shm_size, shm) = bufc2py[buf]
                        data = bytes(memref.buf)
                        self.ql.log.debug(f"buf: {buf:#0x}, size: {size:#0x}")
                        data = data.ljust(shm_size, b"\x00")
                        shm.msg = (c_byte * shm_size)(*data)
                        self.ql.log.debug(f"SHM OUT content: {shm.to_bytes()}")
                    elif t == 0:
                        pass
                    else:
                        self.ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        return
                    pcnt += 1

                client_socket.send(b"ok" + p32(ret))
            elif f == FUNCS.func_TEEC_ReleaseSharedMemory.value and l == 8:
                buf = u64(d)
                self.ql.log.debug(f"func_TEEC_ReleaseSharedMemory: {buf:#0x}")
                if buf not in bufc2py:
                    self.ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                    sock.close()
                    return
                (shm_size, shm) = bufc2py[buf]
                del shm
                del bufc2py[buf]
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_CloseSession.value and l == 4:
                sid = u32(d)
                self.ql.log.debug(f"func_TEEC_CloseSession: {sid}")

                self.CloseSession(sid)

                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_FinalizeContext.value and l == 4 and d == b"quit":
                self.ql.log.debug(f"func_TEEC_FinalizeContext")
                break
            else:
                self.ql.log.error(f"Recved unknown msg {f, l, d}")
                sock.close()
                return
        self.DestroyEntryPoint()

    def get_cov_file_path(self, input_name: str, harness_dir: str) -> str:
        cov_dir = None
        if harness_dir is None:
            # we don't have a harness and thus don't have a dir where the
            # cov file should go. We use a tmpdir instead!
            tmp_dir = tempfile.TemporaryDirectory(prefix="ta-gp-").name
            out_dir = os.path.join(tmp_dir.name, "out")
        else:
            out_dir = os.path.join(harness_dir, "out")
        cov_dir = os.path.join(out_dir, "cov")
        os.makedirs(cov_dir, exist_ok=True)
        cov_path = os.path.join(cov_dir, f"{input_name}.cov")
        return cov_path

    def start_fuzz(
        self, input_file, fuzz_harness=None, fuzz_replay=False, rec_cov=False
    ):
        self.log.info(f"start fuzz args is {input_file} {fuzz_harness} {fuzz_replay}")
        ret = self.CreateEntryPoint()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f"CreateEntryPoint ret != TEE_SUCCESS {hex(ret)}")
            return

        ret, new_session = self.OpenSession()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}"
            )
            return

        exit_addr = []
        exit_hooks = []
        sid = new_session.session_id
        cmd = 0
        ptypes = 0
        command_params = [NoneParam()] * 4
        # ret = self.InvokeCommand(sid, cmd, ptypes, command_params)

        for e in self.TA_InvokeCommandEntryPoint_end:
            exit_addr.append(e)
        self.ql.log.debug(f"TEEC_InvokeCommand {sid} {cmd} {ptypes:#0x}")
        session = None
        for s in self.sessions:
            if sid == s.session_id:
                session = s
                break
        if session is None:
            self.ql.log.error(f"unknown session {sid}")
            return TEE_ERROR_BAD_STATE

        self.fuzz_session = session

        def default_place_input_callback(ql: Qiling, input: bytes, _: int):
            print(f"Placing input: {input}")

            if len(input) < 4:
                return False

            ptypes = 0
            command_params = [NoneParam()] * 4
            cmd = u32(input[:4])
            print(f"cmdId: {cmd}")
            ret, params_mem = setup_params_fuzz(
                ql, cmd, ptypes, command_params
            )  # assume the session is already set
            if ret != TEE_SUCCESS:
                return False

            return True

        init_fuzz = None
        if fuzz_harness is None:
            place_input_callback = default_place_input_callback
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
            if ql.arch.regs.arch_pc == CRASH_PC or ql.arch.regs.arch_pc == CRASH_PC_2 or ql.arch.regs.arch_pc == NOTIMPL_PC:
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
            self.log.info(f"[TAEMU] starting afl")
            ql_afl_fuzz(
                _ql,
                input_file=input_file,
                place_input_callback=place_input_callback,
                exits=[0x13370],
                validate_crash_callback=crash_validation,
                always_validate=True,
            )

        self.ql.os.fcall.cc.setRawParam(0, session.session_id_mem)

        if fuzz_replay:
            self.ql._debugger = self._debugger
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        pivot, e, user_data="TA_InvokeCommandEntryPoint"
                    )
                )

        else:
            self.ql.hook_address(
                callback=start_afl,
                address=self.TA_InvokeCommandEntryPoint_start,
            )

        # set hooks for fuzzer's recording logics
        for e in exit_addr:
            self.ql.hook_address(
                callback=finalize_fuzzing,
                address=e,
                user_data="Recording suspicious inputs",
            )
            self.ql.hook_address(
                callback=pivot2,
                address=e
            )
        
        if init_fuzz is not None:
            self.init_fuzz = True
            init_fuzz(self, sid)
            self.init_fuzz = False

        if fuzz_replay:
            # use data from `input_file`
            input_data = open(input_file, "rb").read()
            if not place_input_callback(self.ql, input_data, -1):
                print(f"place_input returned -1, returning")
                return

            # record coverage while we replay `input_file`
            cov_path = self.get_cov_file_path(
                os.path.basename(input_file), os.path.dirname(fuzz_harness)
            )

            with cov_utils.collect_coverage(self.ql, "drcov", cov_path):
                self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
        else:
            self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.log.info(f"InvokeCommand returned: {hex(ret)}")

        for e in exit_hooks:
            self.ql.hook_del(e)
        exit_hooks = []
        self.ql.debugger = False
        self.CloseSession(sid)

        self.DestroyEntryPoint()
        return

    def df_fuzz(
        self, input_file, fuzz_harness, df_seed, df_reg_hash, fuzz_replay=False, df_validate=False
    ):
        # df_seed: seed which triggered the double fetch 
        # df_addr: shm address
        # df_size: size of double fetched data

        if df_validate: assert not fuzz_replay, "fuzz_replay can not be set for df_validate!"
        if fuzz_replay: assert not df_validate, "df_validate can not be set for fuzz_replay"

        self.df_fuzz_out = os.path.join(os.path.dirname(fuzz_harness), "df_fuzz", f"{os.path.basename(df_seed)}_{df_reg_hash}")

        meta_path = df_seed + ".meta"
        if not os.path.exists(meta_path):
            print(f'double fetch seed meta does not exist')
            return

        df_meta = json.load(open(meta_path)) 

        df_records = []

        if df_reg_hash is not None:
           for r in df_meta['records']:
                if str(r["regs"]["reg_hash"]) == str(df_reg_hash):
                    if r not in df_records:
                        df_records.append(r)

        if len(df_records) > 1:
            # unicorn has an issue where the registers in a read callback stay the same for a basic block
            # this leads to duplicate reg_hashes
            # but since they're all in the same basic block we can just fuzz starting from there
            print(f'multiple df record candidates: {df_records}, merging ranges')
            ranges= []
            for df_record in df_records:
                addr = df_record["addr"]
                size = df_record["size"]
                found = False
                for i, rangee in enumerate(ranges):
                    if rangee[0] == addr + size:
                        ranges[i] = (addr, rangee[1])
                        found = True
                        break
                    if rangee[1] == addr:
                        ranges[i] = (rangee[0], addr+size)
                        found = True
                        break
                if not found:
                    ranges.append((addr, addr+size))
            if len(ranges) == 1:
                df_records[0]["addr"] = ranges[0][0]
                df_records[0]["size"] = ranges[0][1] - ranges[0][0]
                self.log.info(f"merged range: {ranges[0]}")
            else:
                self.log.info(f"non overlapping ranges in multiple df candidates {ranges}")
                return

        if len(df_records) == 0:
            print(f'no df record candidates from {df_meta["records"]}')
            return

        df_record = df_records[0]

        if not df_record["regs"]["is_read"]:
            print(f'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print(f'!!!!! THERE IS NO POINT IN FUZZING A WRITE TO SHARED MEMORY !!!!!!!')
            print(f'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print(f'"-.-')
            self.log.info(f"trying to fuzz write double fetch!! -> returning")
            return
        if df_record["size"] == 0:
            print(f'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print(f'!!!!! THERE IS NO POINT IN FUZZING 0 SIZE FETCH             !!!!!!!')
            print(f'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print(f'"-.-')
            self.log.info(f"trying to fuzz 0-sized double fetch!! -> returning")
            #return

        self.log.info(f"df fuzz args is {input_file} {fuzz_harness} {fuzz_replay} {df_validate}")
        self.log.info(f"    df@{hex(df_record['regs']['PC'])}->{hex(df_record['addr'])}:{df_record['size']} from {df_seed}")
        
        ret = self.CreateEntryPoint()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f"CreateEntryPoint ret != TEE_SUCCESS {hex(ret)}")
            return

        ret, new_session = self.OpenSession()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(
                f"[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}"
            )
            return

        exit_addr = []
        exit_hooks = []
        df_hook = None
        sid = new_session.session_id
        cmd = 0
        ptypes = 0

        for e in self.TA_InvokeCommandEntryPoint_end:
            exit_addr.append(e)
        self.ql.log.debug(f"TEEC_InvokeCommand {sid} {cmd} {ptypes:#0x}")
        session = None
        for s in self.sessions:
            if sid == s.session_id:
                session = s
                break
        if session is None:
            self.ql.log.error(f"unknown session {sid}")
            return TEE_ERROR_BAD_STATE

        self.fuzz_session = session
        init_fuzz = None
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
            if ql.arch.regs.arch_pc == CRASH_PC or ql.arch.regs.arch_pc == CRASH_PC_2 or ql.arch.regs.arch_pc == NOTIMPL_PC:
                return True
            if result == 6:
                return True
            # if ql.arch.regs.arch_pc not in exit_addr:
            # return True
            return False
        
        def df_write(ql: Qiling, df_data):
            df_size = df_record['size']
            if df_size is None:
                ql.mem.write(df_record['addr'], df_data)
            else:
                if len(df_data) < df_size:
                    df_data = df_data + (df_size-len(df_data))*b"\x00"
                ql.mem.write(df_record['addr'], df_data[:df_size])

        
        def place_df_replay(ql: Qiling):
            if self.df_replay_placed:
                return
            ql.log.debug(f"place_df_replay {ql.arch.regs.save()}")
            if self.init_fuzz:
                return
            ql.log.debug(f"hashes: {self.hash_regs()} {df_record['regs']['reg_hash']}")
            if self.hash_regs() != df_record['regs']['reg_hash']:
                return
            for e in exit_hooks:
                self.ql.hook_del(e) 
            exit_hooks.clear()
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        pivot, e, user_data="TA_InvokeCommandEntryPoint"
                    )
                ) 
            #self.ql.hook_del(df_hook)
            self.log.info(f"placing double fetch data")
            df_data = open(input_file, "rb").read()
            df_write(ql, df_data) 
            self.df_replay_placed = True

        def place_df_fuzz(ql: Qiling, input: bytes, _:int): 
            df_write(ql, input)

        def start_afl(_ql: Qiling):
            if fuzz_replay:
                return
            if df_validate:
                return
            #if self.init_fuzz:
            #    return
            print(self.hash_regs(), df_record['regs']['reg_hash'])
            if self.hash_regs() != df_record['regs']['reg_hash']:
                return
            self.log.info(f"[TAEMU] starting afl")
            for e in exit_hooks:
                self.ql.hook_del(e)
            exit_hooks.clear()
            self.ql.hook_del(df_hook)
            ql_afl_fuzz(
                _ql,
                input_file=input_file,
                place_input_callback=place_df_fuzz,
                exits=exit_addr,
                validate_crash_callback=crash_validation,
                always_validate=True,
            )

        if fuzz_replay:
            self.ql._debugger = self._debugger
            df_hook = self.ql.hook_address_front(
                callback=place_df_replay,
                address=df_record['regs']['PC']
            ) 
        elif df_validate: 
            pass
        else: #fuzzing
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        pivot, e, user_data="TA_InvokeCommandEntryPoint"
                    )
                )
            df_hook = self.ql.hook_address_front(
                callback=start_afl,
                address=df_record['regs']['PC']
            )
        
        if init_fuzz is not None:
            if fuzz_replay or df_validate:
                for e in exit_addr:
                    exit_hooks.append(
                        self.ql.hook_address(
                            pivot, e, user_data=self
                        )
                    )
            self.init_fuzz = True
            init_fuzz(self, sid)
            self.init_fuzz = False
            if fuzz_replay:
                for e in exit_hooks:
                    self.ql.hook_del(e) 
                exit_hooks = []
                for e in exit_addr:
                    exit_hooks.append(
                        self.ql.hook_address(
                            pivot_df_not_hit, e, user_data=self
                        )
                    )       
        else:
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        pivot_df_not_hit, e, user_data=self
                    )
                )
        

        df_seed_data = open(df_seed, "rb").read()

        if not place_input_callback(self.ql, df_seed_data, -1):
            print("place_input_callback failed in setup for df fuzz..")
            exit(-1)

        if fuzz_replay:
            df_fuzz_dir = os.path.dirname(input_file)[:os.path.dirname(input_file).find("/out/")]
            cov_path = self.get_cov_file_path(
                os.path.basename(input_file), df_fuzz_dir
            )

            with cov_utils.collect_coverage(self.ql, "drcov", cov_path):
                self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
        elif df_validate:
            # check if df fuzz data placed in beginning also triggers the crash
            for e in exit_hooks:
                self.ql.hook_del(e) 
            exit_hooks = []
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        df_validated, e, user_data=(self,input_file)
                    )
                ) 
            self.log.info(f"placing double fetch data")
            df_data = open(input_file, "rb").read()
            df_write(self.ql, df_data) 
            self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
        else: #fuzzing
            for e in exit_hooks:
                self.ql.hook_del(e) 
            for e in exit_addr:
                exit_hooks.append(
                    self.ql.hook_address(
                        pivot_df_not_hit, e, user_data=self
                    )
                )
            self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.log.info(f"InvokeCommand returned: {hex(ret)}")

        for e in exit_hooks:
            self.ql.hook_del(e)
        exit_hooks = []
        self.ql.debugger = False
        self.CloseSession(sid)

        self.DestroyEntryPoint()
        return 

    def __enter__(self):
        self.setup()
        self.hook()
        self.ql.emu = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("[TAEMU] Context manager cleanup...")
        self.clear_records()
        print("[TAEMU] queue cleared")
        self.ql.stop()
        print("[TAEMU] emulator stopped")
        return False
