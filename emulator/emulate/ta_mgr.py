from qiling import Qiling
import importlib
from qiling.extensions.afl import ql_afl_fuzz
from qiling.extensions import pipe
import unicorn
from pwn import *
from . import gp_api
from .gp.utils.param import TEE_Param_Memref, TEE_Param_value
import json
import socket
from ctypes import *
from enum import Enum
from .params import *
from .gp.utils.err import *
from .gp.utils.param import *
from .emulator_no_loader import fixup_got, mitee_setup, hook_ta_dl, hook_ta_custom
from .common import CRASH_PC, NOTIMPL_PC


def parse_msg(msg):
    f = int(msg[0])
    l = int(msg[1])
    data = msg[2:2+l]
    return (f, l, data)

def pivot(ql: Qiling, cur) -> None:
    ql.log.info(f"[////{cur}////] reach end @{ql.arch.regs.read('PC'):#0x}")
    ql.stop()

def get_n_ptype(param_type: int, n: int):
    if n >= 0 and n <= 3:
        return (param_type >> (4 * n)) & 0xf
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



class Session():
    def __init__(self, session_id_mem, session_id, sessionContext):
        self.session_id_mem = session_id_mem
        self.session_id = session_id
        self.sessionContext = sessionContext

def get_ta_uuid(ta_name):
    ta_name = ta_name.replace('-', '')
    return bytes.fromhex(ta_name)

class TAEMU():
    
    def __init__(self, ql: Qiling, tee: str, ta_path: str, ta_elf: ELF):
        self.ql = ql
        self.tee = tee
        self.ta_path = ta_path
        self.ta_elf = ta_elf
        self.ta_base = ql.mem.get_lib_base(ta_path.split("/")[-1])
        self.taUUID = get_ta_uuid(ta_path.split("/")[-1][:-3])
        self.ta_elf.address = self.ta_base
        self.HEAP = {"allocated": {}, "freed": {}, "redzones": {}}
        self.exit_non_implemented = None
        self.curr_params = None
        self.session_counter = 0
        self.crash_on_not_implemented = False
        if "TAEMU_CRASH_NOTIMPL" in os.environ:
            self.crash_on_not_implemented = True
        self.sessions = []
        self._debugger = ql._debugger 

        f = open(f"{self.ta_path[:-3]}.json", 'r')
        ta_info = json.load(f)
        self.ta_info = ta_info
        
        if all(i in ta_info for i in ["TA_InvokeCommandEntryPoint_start", "TA_InvokeCommandEntryPoint_end", "TA_CreateEntryPoint_start", "TA_CreateEntryPoint_end", "TA_OpenSessionEntryPoint_start", "TA_OpenSessionEntryPoint_end", "TA_CloseSessionEntryPoint_start", "TA_CloseSessionEntryPoint_end", "TA_DestroyEntryPoint_start", "TA_DestroyEntryPoint_end"]):
            self.TA_CreateEntryPoint_start = ta_info["TA_CreateEntryPoint_start"]
            self.TA_CreateEntryPoint_end = ta_info["TA_CreateEntryPoint_end"]
            self.TA_OpenSessionEntryPoint_start = ta_info["TA_OpenSessionEntryPoint_start"]
            self.TA_OpenSessionEntryPoint_end = ta_info["TA_OpenSessionEntryPoint_end"]
            self.TA_InvokeCommandEntryPoint_start = ta_info["TA_InvokeCommandEntryPoint_start"]
            self.TA_InvokeCommandEntryPoint_end = ta_info["TA_InvokeCommandEntryPoint_end"]
            self.TA_CloseSessionEntryPoint_start = ta_info['TA_CloseSessionEntryPoint_start']
            self.TA_CloseSessionEntryPoint_end = ta_info['TA_CloseSessionEntryPoint_end']
            self.TA_DestroyEntryPoint_start = ta_info['TA_DestroyEntryPoint_start']
            self.TA_DestroyEntryPoint_end = ta_info['TA_DestroyEntryPoint_end']
        else:
            print(f"TA info error")
            exit(-1)

        if len(self.TA_CloseSessionEntryPoint_end) == 0 or len(self.TA_DestroyEntryPoint_end) == 0 or len(self.TA_InvokeCommandEntryPoint_end) == 0 or len(self.TA_OpenSessionEntryPoint_end) == 0 or len(self.TA_CreateEntryPoint_end) == 0:
            print(f"one or more TA_*_end entries is empty!")
            exit(-1)

        if self.ta_elf.pie:
            self.TA_CreateEntryPoint_start = self.TA_CreateEntryPoint_start + self.ta_base
            self.TA_CreateEntryPoint_end = [end + self.ta_base for end in self.TA_CreateEntryPoint_end] 
            self.TA_OpenSessionEntryPoint_start = self.TA_OpenSessionEntryPoint_start + self.ta_base
            self.TA_OpenSessionEntryPoint_end = [end + self.ta_base for end in self.TA_OpenSessionEntryPoint_end]
            self.TA_InvokeCommandEntryPoint_start = self.TA_InvokeCommandEntryPoint_start + self.ta_base
            self.TA_InvokeCommandEntryPoint_end = [end + self.ta_base for end in self.TA_InvokeCommandEntryPoint_end ]
            self.TA_CloseSessionEntryPoint_start = self.TA_CloseSessionEntryPoint_start + self.ta_base
            self.TA_CloseSessionEntryPoint_end = [end + self.ta_base for end in self.TA_CloseSessionEntryPoint_end]
            self.TA_DestroyEntryPoint_start = self.TA_DestroyEntryPoint_start + self.ta_base
            self.TA_DestroyEntryPoint_end = [end + self.ta_base for end in self.TA_DestroyEntryPoint_end]
        
        f.close() 

    def setup(self):
        # fix relocations and other miscellanous setup
        fixup_got(self.ql, self.ta_path, self.ta_elf, self.ta_base)
        if self.tee == "mitee":
            # handle tpidr_el0 and fix relocations
            mitee_setup(self.ql, self.ta_path, self.ta_base)

    def hook(self):
        # setup api hooks
        hook_ta_dl(self.ql, self.ta_path, self.ta_elf, self, is_mitee=self.tee=="mitee")
        hook_ta_custom(self.ql, self.ta_path, self.ta_elf, self)
        self.ql.do_lib_patch()

    def get_shm(self, pointer):
        if self.curr_params is None:
            return None
        for p in self.curr_params:
            if isinstance(p, MemRefParam):
                if p.is_shared and pointer >= p.shm_pybuf and pointer <= p.shm_pybuf + p.size:
                    return p
        return None

    def update_shm(self, pointer):
        param = self.get_shm(pointer)
        if param is None:
            return
        self.ql.mem.write(param.shm_pybuf, param.shm.to_bytes()) 
    
    def writeback_shm(self, pointer):
        param = self.get_shm(pointer)
        if param is None:
            return
        curr_data = self.ql.mem.read(param.shm_pybuf, param.size)
        param.shm.from_bytes(curr_data) 

    def CreateEntryPoint(self):
        self.ql.log.info(f"[////TA_CreateEntryPoint////] start @{self.TA_CreateEntryPoint_start:#0x}")
        entrypoint = self.TA_CreateEntryPoint_start

        # stop at TA_CreateEntryPoint_end
        for e in self.TA_CreateEntryPoint_end:
            self.ql.hook_address(pivot, e, user_data="TA_CreateEntryPoint")

        #_debugger = self.ql._debugger
        self.ql.debugger = False
        self.ql.run(begin=entrypoint)

        ret = self.ql.os.fcall.cc.getReturnValue()
        self.CreateEntryPoint_ret = ret
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f'[////TA_CreateEntryPoint////] return != TEE_SUCCESS {hex(ret)}')
            return ret
        return ret

    def OpenSession(self):
        if self.CreateEntryPoint_ret != TEE_SUCCESS:
            self.ql.log.warning(f'Calling OpenSession without succesfull CreateEntryPoint!')
            return TEE_ERROR_BAD_STATE 
        #TODO: support parameters
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

        self.ql.log.info(f"[////TA_OpenSessionEntryPoint////] start @{self.TA_OpenSessionEntryPoint_start:#0x}")
        for e in self.TA_OpenSessionEntryPoint_end:
            self.ql.hook_address(pivot, e, user_data="TA_OpenSessionEntryPoint")

        #ql._debugger = _debugger
        self.ql.os.fcall.cc.setRawParam(2, sessionContext)
        self.ql.run(begin=self.TA_OpenSessionEntryPoint_start)
        
        ret = self.ql.os.fcall.cc.getReturnValue()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f'[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}')
            return ret, None
        return ret, new_session

    def InvokeCommand(self, sid, cmd, ptypes, params):
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

          
        status, params_mem = setup_params(self.ql, session, cmd, ptypes, params, is_32bit=self.tee=="beanpod")
        if status != TEE_SUCCESS:
            return status
        self.curr_params = params

        self.ql.log.info(f"[////TA_InvokeCommandEntryPoint////] start @{self.TA_InvokeCommandEntryPoint_start:#0x}")
        # stop at TA_InvokeCommandEntryPoint_end
        for e in self.TA_InvokeCommandEntryPoint_end:
            exit_hooks.append(self.ql.hook_address(pivot, e, user_data="TA_InvokeCommandEntryPoint"))

        # run
        self.ql._debugger = self._debugger
        self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
        ret = self.ql.os.fcall.cc.getReturnValue()

        params_mem_read = params_mem
        # sync output
        for i, param in enumerate(params):
            if isinstance(param, ValueParam):
                param.a = int.from_bytes(self.ql.mem.read(params_mem_read, 4), "little")
                params_mem_read += 4
                param.b = int.from_bytes(self.ql.mem.read(params_mem_read, 4), "little")
                params_mem_read += 4
                if self.tee != "beanpod":
                    # 32 bit
                    params_mem_read += 8
            elif isinstance(param, MemRefParam):
                pybuf = self.ql.mem.read_ptr(params_mem_read)
                param.buf = self.ql.mem.read(pybuf, param.size)
                self.ql.mem.unmap(pybuf, (param.size + 0xFFF) & ~0xFFF )
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
        self.ql.mem.unmap(params_mem & 0xfffffffffffff000, 0x1000)

        return ret

    def CloseSession(self, sid):
        self.ql.log.debug(f"TA_CloseSessionEntryPoint {sid}")
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
        self.ql.log.info(f"[////CloseSessionEntryPoint////] start @{self.TA_CloseSessionEntryPoint_start:#0x}")
        for e in self.TA_CloseSessionEntryPoint_end:
            self.ql.hook_address(pivot, e, user_data="TA_CloseSessionEntryPoint_end")

        #self.ql._debugger = self._debugger

        self.ql.os.fcall.cc.setRawParam(0, session.sessionContext)
        self.ql.run(begin=self.TA_CloseSessionEntryPoint_start) 

        self.ql.mem.unmap(session.session_id_mem, 0x1000)
        self.ql.mem.unmap(session.sessionContext, 0x1000)
        self.sessions.pop(idx)

    def DestroyEntryPoint(self):
        self.ql.log.info(f"[////TA_DestroyEntryPoint////] start @{self.TA_DestroyEntryPoint_start:#0x}")
        for e in self.TA_DestroyEntryPoint_end:
            self.ql.hook_address(pivot, e, user_data="TA_CloseSessionEntryPoint_end")

        #self.ql._debugger = self._debugger

        self.ql.run(begin=self.TA_DestroyEntryPoint_start)

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

        ret = self.CreateEntryPoint()
        if( ret != TEE_SUCCESS ):
            self.ql.log.warning(f'CreateEntryPoint ret != TEE_SUCCESS {hex(ret)}')
            return
        
        # block here after TA_CreateEntryPoint, now we start socket, waiting to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 1337))
        sock.listen()

        (client_socket, address) = sock.accept()
        self.ql.log.debug(f"CA connected from {address}") 

        while True:
            data = client_socket.recv(1024)
            self.ql.log.debug(f"Recv {data}")
            if len(data) == 0:
                return
            (f, l, d) = parse_msg(data)

            if f == FUNCS.func_TEEC_InitializeContext.value and l == 5 and d == b'start':
                self.ql.log.debug(f"TEEC_InitializeContext")
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_OpenSession.value and l == 0x10:
                uuid = (p32(u32(d[:4]), endian='big') + p16(u16(d[4:6]), endian='big') + p16(u16(d[6:8]), endian='big') + d[8:]).hex()
                self.ql.log.debug(f"TEEC_OpenSession from uuid {uuid}")
                if "-" in self.ta_path:
                    if (uuid != self.ta_path.replace("-","").split("/")[-1][:-3]):
                        self.ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        return
                else:
                    if (uuid != self.ta_path.split("/")[-1][:-3]):
                        self.ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        exit(-1)
                ret, new_session = self.OpenSession()
                if ret != TEE_SUCCESS:
                    self.ql.log.warning(f'[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}')
                    return 
                client_socket.send(b"ok" + p32(new_session.session_id))
            elif f == FUNCS.func_TEEC_RegisterSharedMemory.value and l == 16:
                shm_key = u32(d[:4])
                size = u32(d[4:8])
                buf = u64(d[8:])
                self.ql.log.info(f"TEEC_RegisterSharedMemory {shm_key:#0x} {buf:#0x} {size:#0x}")

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
                
                command_params = []
                params = d[12:]
                pcnt = 0
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        a = u32(params[pcnt*24:pcnt*24+4])
                        b = u32(params[pcnt*24+4:pcnt*24+8])
                        command_params.append(ValueParam(a,b))
                        self.ql.log.debug(f"value p {a} {b}")
                    # tmp mem
                    elif t >= 5 and t <= 7:
                        buf = u64(params[pcnt*24:pcnt*24+8])
                        size = u64(params[pcnt*24+8:pcnt*24+16])
                        self.ql.log.debug(f"mem p {buf:#0x} {size:#0x}")
                        if buf not in bufc2py:
                            self.ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                            sock.close()
                            return 
                        (shm_size, shm) = bufc2py[buf]
                        if size > shm_size:
                            self.ql.log.error(f"size larger than shm: {size:#0x} v.s. {shm_size}")
                            sock.close()
                            return 
                        # get shared content
                        self.ql.log.debug(f"SHM IN content: {shm.to_bytes()}")
                        if self.tee == "mitee" or self.tee == "teegris":
                            # shared memory
                            memref = MemRefParam(shm.to_bytes(), size)
                            memref.is_shared = True
                            memref.shm = shm
                            command_params.append(memref)
                        else:
                            command_params.append(MemRefParam(shm.to_bytes(), size))
                    elif t == 0:
                        command_params.append(NoneParam())
                    else:
                        self.ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        return
                    pcnt += 1

                ret = self.InvokeCommand(sid, cmd, ptypes, command_params) 
                self.ql.log.info(f'InvokeCommand returned: {hex(ret)}')

                # sync shm
                pcnt = 0
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        #@TODO: send back a and b
                        self.ql.log.debug("value type output not implemneted")
                    elif t >= 5 and t <= 7:
                        # copy back memory to shm
                        memref = command_params[pcnt]
                        buf = u64(params[pcnt*24:pcnt*24+8])
                        size = u64(params[pcnt*24+8:pcnt*24+16])
                        (shm_size, shm) = bufc2py[buf]
                        data = bytes(memref.buf)
                        self.ql.log.debug(f"buf: {buf:#0x}, size: {size:#0x}")
                        data = data.ljust(shm_size, b'\x00')
                        shm.msg = (c_byte * shm_size)(*data)
                        self.ql.log.debug(f"SHM OUT content: {shm.to_bytes()}")
                    elif t == 0:
                        pass
                    else:
                        self.ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        return
                    pcnt += 1

                client_socket.send(b"ok"+p32(ret))
            elif f == FUNCS.func_TEEC_ReleaseSharedMemory.value and l == 8:
                buf = u64(d)
                self.ql.log.debug(f"func_TEEC_ReleaseSharedMemory: {buf:#0x}")
                if buf not in bufc2py:
                    self.ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                    sock.close()
                    return
                (shm_size, shm) = bufc2py[buf]
                del(shm)
                del bufc2py[buf]
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_CloseSession.value and l == 4:
                sid = u32(d)
                self.ql.log.debug(f"func_TEEC_CloseSession: {sid}")

                self.CloseSession(sid)

                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_FinalizeContext.value and l == 4 and d == b'quit':
                self.ql.log.debug(f"func_TEEC_FinalizeContext")
                break
            else:
                self.ql.log.error(f"Recved unknown msg {f, l, d}")
                sock.close()
                return
        self.DestroyEntryPoint()

    def start_fuzz(self, input_file, fuzz_harness=None, fuzz_replay=False):

        ret = self.CreateEntryPoint()
        if( ret != TEE_SUCCESS ):
            self.ql.log.warning(f'CreateEntryPoint ret != TEE_SUCCESS {hex(ret)}')
            return

        ret, new_session = self.OpenSession()
        if ret != TEE_SUCCESS:
            self.ql.log.warning(f'[////TA_OpenSessionEntryPoint////] return != TEE_SUCCESS {hex(ret)}')
            return

        exit_addr = []
        exit_hooks = []
        sid = new_session.session_id
        cmd = 0
        ptypes = 0
        command_params = [ NoneParam() ] * 4
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

        def default_place_input_callback(ql: Qiling, input: bytes, _: int):
            print(f"Placing input: {input}")

            if len(input) < 4:
                return False

            ptypes = 0
            command_params = [ NoneParam() ] * 4
            cmd = u32(input[:4])
            print(f"cmdId: {cmd}")
            ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params) # assume the session is already set
            if ret != TEE_SUCCESS:
                return False

            return True

        if fuzz_harness is None:
            place_input_callback = default_place_input_callback
        else:
            # import shit
            spec = importlib.util.spec_from_file_location(os.path.basename(fuzz_harness)[:-3], os.path.abspath(fuzz_harness))
            module = importlib.util.module_from_spec(spec)
            module.__package__ = __package__
            spec.loader.exec_module(module)
            place_input_callback = getattr(module, "place_input_callback")
            if hasattr(module, "init_fuzz"):
                init_fuzz = getattr(module, "init_fuzz")
                init_fuzz(self, session)

        def crash_validation(ql: Qiling, result: int, input_bytes: bytes, round: int) -> bool:
            print("crash callback: ", result)
            if ql.arch.regs.arch_pc == CRASH_PC or ql.arch.regs.arch_pc == NOTIMPL_PC: 
                return True
            if result == 6:
                return True
            #if ql.arch.regs.arch_pc not in exit_addr:
                #return True
            return False

        def start_afl(_ql: Qiling):
            print("starting afl")
            ql_afl_fuzz(_ql, input_file=input_file, place_input_callback=place_input_callback, exits=exit_hooks, validate_crash_callback=crash_validation, always_validate=True)
        
        self.ql.os.fcall.cc.setRawParam(0, session.session_id_mem)

        if fuzz_replay:
            self.ql._debugger = self._debugger
            place_input_callback(self.ql, open(input_file, 'rb').read(), -1)
            for e in exit_addr:
                exit_hooks.append(self.ql.hook_address(pivot, e, user_data="TA_InvokeCommandEntryPoint"))
        else:
            self.ql.hook_address(callback=start_afl, address=self.TA_InvokeCommandEntryPoint_start)


        self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
        ret = self.ql.os.fcall.cc.getReturnValue()
        self.ql.log.info(f'InvokeCommand returned: {hex(ret)}')

        for e in exit_hooks:
            self.ql.hook_del(e)
        exit_hooks = []
        self.ql.debugger = False
        self.CloseSession(sid)

        self.DestroyEntryPoint()
        return
