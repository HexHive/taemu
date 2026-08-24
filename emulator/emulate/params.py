import abc
from typing import List
from qiling import Qiling

from . import gp_api
from .gp.utils.param import TEE_Param_Memref, TEE_Param_value
import json
import socket
import hashlib
from ctypes import *
from .gp.utils.err import *
from .fuzz_record import Record, Status

min_addr = 0xBBBBB000
MIN_PARAM_ADDR = 0xBBBBB000

class Param(abc.ABC):
    pass

class ValueParam(Param):
    def __init__(self, a: int, b: int):
        self.a = a
        self.b = b


class MemRefParam(Param):
    def __init__(self, buf: bytes, size: int):
        self.buf = buf
        self.size = size
        self.is_shared = True 
        self.shm = None
        self.shm_pybuf = None

    def __str__(self):
        return f"MemRefParam(size={self.size}, is_shared={self.is_shared}, shm={self.shm}, shm_pybuf={self.shm_pybuf})"


def shared_read_callback(
    ql: Qiling, access: int, address: int, size: int, value: int, user_data
):
    # refetch data from the shared memory
    memref = user_data
    # TODO make more efficient
    if ql.emu.status == Status.INTERACTIVE:
        assert memref.shm is not None
        ql.mem.write(memref.shm_pybuf, memref.shm.to_bytes())
    ql.log.debug(f'shared mem read {hex(address)} pc:{hex(ql.arch.regs.arch_pc)} size: {size}')
    ql.log.debug(f'shared mem read regs: {ql.arch.regs.save()}')
    if ql.emu.status in (Status.FUZZING, Status.REPLAYING) and not ql.emu.init_fuzz:
        ql.emu.update_records(
            key=ql.emu.curr_record_key,
            item=Record(
                address,
                size,
                regs={
                    "PC": ql.arch.regs.read("PC"),
                    "ret_addr": ql.get_caller_pc(),
                    "ret_addr_offset": ql.get_caller_pc() - ql.emu.ta_base,
                    "is_read": True,
                    "reg_hash": ql.emu.hash_regs()
                },
            ),
            op=lambda a, b: a + [b],
        )


def shared_write_callback(
    ql: Qiling, access: int, address: int, size: int, value: int, user_data
):
    # write data back to memory
    memref = user_data
    # TODO make this more efficient
    if ql.emu.status == Status.INTERACTIVE:
        assert memref.shm is not None
        curr_data = ql.mem.read(memref.shm_pybuf, memref.size)
        memref.shm.from_bytes(curr_data)
    if ql.emu.status in (Status.FUZZING, Status.REPLAYING) and not ql.emu.init_fuzz:
        ql.emu.update_records(
            key=ql.emu.curr_record_key,
            item=Record(
                address,
                size,
                regs={
                    "PC": ql.arch.regs.read("PC"),
                    "ret_addr": ql.get_caller_pc(),
                    "ret_addr_offset": ql.get_caller_pc() - ql.emu.ta_base,
                    "is_read": False,
                    "reg_hash": ql.emu.hash_regs()
                },
            ),
            op=lambda a, b: a + [b],
        )
    


class NoneParam(Param):
    def __init__(self):
        pass


def setup_fuzz(ql: Qiling, cmd, ptypes, params:List[Param], input):
    # TODO: Why do we hash input, why not params directly?
    ql.emu.curr_input = input
    seed_id = f"run:id:{hashlib.md5(input).hexdigest()}"
    ql.emu.curr_record_key = seed_id
    ql.emu.curr_params = params 
    setup_params_fuzz(ql, cmd, ptypes, params)

def setup_params_fuzz(ql: Qiling, cmd, ptypes, params:List[Param]):
    return setup_params(
        ql, ql.emu.fuzz_session, cmd, ptypes, params, is_32bit=ql.arch.pointersize == 4
    )


def setup_params(ql: Qiling, session: 'Session', cmd, ptypes, params:List[Param], is_32bit=False):
    if session is not None:
        ql.os.fcall.cc.setRawParam(0, session.session_id_mem)
    ql.os.fcall.cc.setRawParam(1, cmd)
    ql.os.fcall.cc.setRawParam(2, ptypes)
    params_mem = ql.mem.map_anywhere(
        0x1000, minaddr=min_addr, perms=3, info="TEE_Params"
    )
    ql.os.fcall.cc.setRawParam(3, params_mem)

    assert len(params) == 4
    params_mem_write = params_mem
    for i, param in enumerate(params):
        if isinstance(param, ValueParam):
            a = param.a
            b = param.b
            ql.log.debug(f"value p {a} {b}")

            ql.mem.write(params_mem_write, a.to_bytes(4, "little"))
            params_mem_write += 4
            ql.mem.write(params_mem_write, b.to_bytes(4, "little"))
            params_mem_write += 4
            if not is_32bit:
                params_mem_write += 8
        # tmp mem
        elif isinstance(param, MemRefParam):
            buf = param.buf
            size = param.size
            ql.log.debug(f"mem p {size:#0x}")
            pybuf = ql.mem.map_anywhere(
                size, minaddr=min_addr, perms=3, info=f"shared_memory_{i}"
            )
            if param.is_shared:
                param.shm_pybuf = pybuf
                ql.mem.write(pybuf, buf[:size])
                if not ql.emu.init_fuzz:
                    ql.hook_mem_write(
                        shared_write_callback,
                        user_data=param,
                        begin=pybuf,
                        end=pybuf + size,
                    )
                    ql.hook_mem_read(
                        shared_read_callback, user_data=param, begin=pybuf, end=pybuf + size
                    )
            else:
                ql.mem.write(pybuf, buf[:size])
            ql.mem.write_ptr(params_mem_write, pybuf)
            params_mem_write += ql.arch.pointersize
            ql.mem.write_ptr(params_mem_write, size)
            params_mem_write += ql.arch.pointersize
        elif isinstance(param, NoneParam):
            params_mem_write += ql.arch.pointersize * 2
        else:
            ql.log.error(f"unknown ptype {param}")
            return TEE_ERROR_BAD_PARAMETERS, params_mem
    return TEE_SUCCESS, params_mem
