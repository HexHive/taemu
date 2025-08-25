from qiling import Qiling
from pwn import *
from . import gp_api
from .gp.utils.param import TEE_Param_Memref, TEE_Param_value
import json
import socket
from ctypes import *
from enum import Enum

TA_NAME = ""

class FUNCS(Enum):
    func_TEEC_InitializeContext = 0
    func_TEEC_OpenSession = 1
    func_TEEC_InvokeCommand = 2
    func_TEEC_CloseSession = 3
    func_TEEC_RegisterSharedMemory = 4
    func_TEEC_ReleaseSharedMemory = 5
    func_TEEC_FinalizeContext = 6

def parse_msg(msg):
    f = int(msg[0])
    l = int(msg[1])
    data = msg[2:2+l]
    return (f, l, data)

def pivot(ql: Qiling, cur) -> None:
    ql.log.info(f"[////{cur}////] reach end @{ql.arch.regs.read('PC'):#0x}")
    
    ql.stop()
    # ql.arch.regs.write("PC", ret_addr)


def get_n_ptype(param_type: int, n: int):
    if n >= 0 and n <= 3:
        return (param_type >> (4 * n)) & 0xf
    else:
        print("Fatal error")
        exit(-1)

min_addr = 0xbbbbb000

def start(ql: Qiling, ta_name: str, tee: str):
    global TA_NAME

    bufc2py = {}

    TA_NAME = ta_name

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

    try:
        f = open(f"{ta_name[:-3]}.json", 'r')
        ta_elf = ELF(ta_name, checksec=True)
        ta_info = json.load(f)
        if all(i in ta_info for i in ["TA_InvokeCommandEntryPoint_start", "TA_InvokeCommandEntryPoint_end", "TA_CreateEntryPoint_start", "TA_CreateEntryPoint_end", "TA_OpenSessionEntryPoint_start", "TA_OpenSessionEntryPoint_end", "TA_CloseSessionEntryPoint_start", "TA_CloseSessionEntryPoint_end", "TA_DestroyEntryPoint_start", "TA_DestroyEntryPoint_end"]):
            TA_CreateEntryPoint_start = ta_info["TA_CreateEntryPoint_start"]
            TA_CreateEntryPoint_end = ta_info["TA_CreateEntryPoint_end"]
            TA_OpenSessionEntryPoint_start = ta_info["TA_OpenSessionEntryPoint_start"]
            TA_OpenSessionEntryPoint_end = ta_info["TA_OpenSessionEntryPoint_end"]
            TA_InvokeCommandEntryPoint_start = ta_info["TA_InvokeCommandEntryPoint_start"]
            TA_InvokeCommandEntryPoint_end = ta_info["TA_InvokeCommandEntryPoint_end"]
            TA_CloseSessionEntryPoint_start = ta_info['TA_CloseSessionEntryPoint_start']
            TA_CloseSessionEntryPoint_end = ta_info['TA_CloseSessionEntryPoint_end']
            TA_DestroyEntryPoint_start = ta_info['TA_DestroyEntryPoint_start']
            TA_DestroyEntryPoint_end = ta_info['TA_DestroyEntryPoint_end']
        else:
            print(f"TA info error")
            exit(-1)

        if len(TA_CloseSessionEntryPoint_end) == 0 or len(TA_DestroyEntryPoint_end) == 0 or len(TA_InvokeCommandEntryPoint_end) == 0 or len(TA_OpenSessionEntryPoint_end) == 0 or len(TA_CreateEntryPoint_end) == 0:
            print(f"one or more TA_*_end entries is empty!")
            exit(-1)

        if ta_elf.pie:
            ta_base = ql.mem.get_lib_base(ta_name.split("/")[-1])
            TA_CreateEntryPoint_start = TA_CreateEntryPoint_start + ta_base
            TA_CreateEntryPoint_end = [end + ta_base for end in TA_CreateEntryPoint_end] 
            TA_OpenSessionEntryPoint_start = TA_OpenSessionEntryPoint_start + ta_base
            TA_OpenSessionEntryPoint_end = [end + ta_base for end in TA_OpenSessionEntryPoint_end]
            TA_InvokeCommandEntryPoint_start = TA_InvokeCommandEntryPoint_start + ta_base
            TA_InvokeCommandEntryPoint_end = [end + ta_base for end in TA_InvokeCommandEntryPoint_end ]
            TA_CloseSessionEntryPoint_start = TA_CloseSessionEntryPoint_start + ta_base
            TA_CloseSessionEntryPoint_end = [end + ta_base for end in TA_CloseSessionEntryPoint_end]
            TA_DestroyEntryPoint_start = TA_DestroyEntryPoint_start + ta_base
            TA_DestroyEntryPoint_end = [end + ta_base for end in TA_DestroyEntryPoint_end]
        
        f.close()

        ql.log.info(f"[////TA_CreateEntryPoint////] start @{TA_CreateEntryPoint_start:#0x}")
        # TA_CreateEntryPoint_start
        entrypoint = TA_CreateEntryPoint_start

        # stop at TA_CreateEntryPoint_end
        for e in TA_CreateEntryPoint_end:
            ql.hook_address(pivot, e, user_data="TA_CreateEntryPoint")

        _debugger = ql._debugger
        #ql.debugger = False
        # run
        ql.run(begin=entrypoint)

        # block here after TA_CreateEntryPoint, now we start socket, waiting to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 1337))
        sock.listen()

        (client_socket, address) = sock.accept()
        ql.log.debug(f"CA connected from {address}")

        exit_hooks = []

        session_opened = 0

        sessionContext = ql.mem.map_anywhere(
                    0x1000, minaddr=min_addr, perms=3, info="session_context"
                )

        while True:
            data = client_socket.recv(1024)
            ql.log.debug(f"Recv {data}")
            if len(data) == 0:
                return
            (f, l, d) = parse_msg(data)

            if f == FUNCS.func_TEEC_InitializeContext.value and l == 5 and d == b'start':
                ql.log.debug(f"TEEC_InitializeContext")
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_OpenSession.value and l == 0x10:
                uuid = (p32(u32(d[:4]), endian='big') + p16(u16(d[4:6]), endian='big') + p16(u16(d[6:8]), endian='big') + d[8:]).hex()
                ql.log.debug(f"TEEC_OpenSession from uuid {uuid}")
                if "-" in ta_name:
                    if (uuid != ta_name.replace("-","").split("/")[-1][:-3]):
                        ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        exit(-1)
                else:
                    if (uuid != ta_name.split("/")[-1][:-3]):
                        ql.log.error(f"Inconsistent TA name!")
                        sock.close()
                        exit(-1)
                if (session_opened != 0):
                    ql.log.error(f"Open session with one TA mutiple times not supported")
                    sock.close()
                    exit(-1)
                session_opened = 1
                # setup params of InvokeCommand
                session_id_mem = ql.mem.map_anywhere(
                    0x1000, minaddr=min_addr, perms=3, info="session_id"
                )
                ql.mem.write_ptr(session_id_mem, session_opened)
                client_socket.send(b"ok" + p32(session_opened))

                ql.log.info(f"[////TA_OpenSessionEntryPoint////] start @{TA_OpenSessionEntryPoint_start:#0x}")
                # stop at TA_OpenSessionEntryPoint_end
                for e in TA_OpenSessionEntryPoint_end:
                    ql.hook_address(pivot, e, user_data="TA_OpenSessionEntryPoint")

                #ql._debugger = _debugger
                ql.os.fcall.cc.setRawParam(2, sessionContext)
                ql.run(begin=TA_OpenSessionEntryPoint_start)

            elif f == FUNCS.func_TEEC_RegisterSharedMemory.value and l == 16:
                shm_key = u32(d[:4])
                size = u32(d[4:8])
                buf = u64(d[8:])
                ql.log.info(f"TEEC_RegisterSharedMemory {shm_key:#0x} {buf:#0x} {size:#0x}")

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

                    def __del__(self):
                        ptr = cast(addressof(self), c_void_p)
                        shmdt(ptr)
               
                shm = SHM.from_key(shm_key)

                pybuf = ql.mem.map_anywhere(
                    size, minaddr=min_addr, perms=3, info=f"shared_memory_{shm_key}"
                )

                bufc2py[buf] = (size, shm, pybuf)

                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_InvokeCommand.value and l == 108:
                sid = u32(d[:4])
                cmd = u32(d[4:8])
                ptypes = u32(d[8:12])
                pcnt = 0
                ql.log.debug(f"TEEC_InvokeCommand {sid} {cmd} {ptypes:#0x}")
                if sid != session_opened:
                    ql.log.error(f"unknown session {sid}")
                    sock.close()
                    exit(-1)

                ql.os.fcall.cc.setRawParam(0, session_id_mem)
                ql.os.fcall.cc.setRawParam(1, cmd)
                ql.os.fcall.cc.setRawParam(2, ptypes)
                #ql.arch.regs.r0 = session_id_mem
                #ql.arch.regs.r1 = cmd
                #ql.arch.regs.r2 = ptypes
                # setup TEE_Params
                params_mem = ql.mem.map_anywhere(
                    0x1000, minaddr=min_addr, perms=3, info="TEE_Params"
                )  
                #ql.arch.regs.r3 = params_mem  
                ql.os.fcall.cc.setRawParam(3, params_mem)

                params = d[12:]
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        a = u32(params[pcnt*24:pcnt*24+4])
                        b = u32(params[pcnt*24+4:pcnt*24+8])
                        ql.log.debug(f"value p {a} {b}")

                        ql.mem.write(params_mem, a.to_bytes(4, "little"))
                        params_mem += 4
                        ql.mem.write(params_mem, b.to_bytes(4, "little"))
                        params_mem += 4
                        if tee != "beanpod":
                            # 32 bit
                            params_mem += 8
                    # tmp mem
                    elif t >= 5 and t <= 7:
                        buf = u64(params[pcnt*24:pcnt*24+8])
                        size = u64(params[pcnt*24+8:pcnt*24+16])
                        ql.log.debug(f"mem p {buf:#0x} {size:#0x}")
                        if buf not in bufc2py:
                            ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                            sock.close()
                            exit(-1)
                        print(bufc2py)
                        (shm_size, shm, pybuf) = bufc2py[buf]
                        if size > shm_size:
                            ql.log.error(f"size larger than shm: {size:#0x} v.s. {shm_size}")
                            sock.close()
                            exit(-1)
                        # get shared content
                        ql.log.debug(f"SHM IN content: {shm.to_bytes()}")
                        ql.mem.write(pybuf, shm.to_bytes())
                        ql.mem.write_ptr(params_mem, pybuf)
                        params_mem += ql.arch.pointersize
                        ql.mem.write_ptr(params_mem, size)
                        params_mem += ql.arch.pointersize 
                    elif t == 0:
                        pass
                    else:
                        ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        exit(-1)
                    pcnt += 1
                
                ql.log.info(f"[////TA_InvokeCommandEntryPoint////] start @{TA_InvokeCommandEntryPoint_start:#0x}")
                # stop at TA_InvokeCommandEntryPoint_end
                for e in TA_InvokeCommandEntryPoint_end:
                    exit_hooks.append(ql.hook_address(pivot, e, user_data="TA_InvokeCommandEntryPoint"))

                # run
                ql._debugger = _debugger
                ql.run(begin=TA_InvokeCommandEntryPoint_start)
                ret = ql.os.fcall.cc.getReturnValue()

                # sync shm
                pcnt = 0
                while pcnt < 4:
                    t = get_n_ptype(ptypes, pcnt)
                    # value type
                    if t >= 1 and t <= 3:
                        #@TODO: send back a and b
                        ql.log.debug("value type output not implemneted")
                    elif t >= 5 and t <= 7:
                        # copy back memory to shm
                        buf = u64(params[pcnt*24:pcnt*24+8])
                        size = u64(params[pcnt*24+8:pcnt*24+16])
                        (shm_size, shm, pybuf) = bufc2py[buf]
                        data = bytes(ql.mem.read(pybuf, size))
                        ql.log.debug(f"buf: {buf:#0x}, size: {size:#0x}")
                        data = data.ljust(shm_size, b'\x00')
                        shm.msg = (c_byte * shm_size)(*data)
                        ql.log.debug(f"SHM OUT content: {shm.to_bytes()}")
                    elif t == 0:
                        pass
                    else:
                        ql.log.error(f"unknown ptype {t}")
                        sock.close()
                        exit(-1)
                    pcnt += 1
                for e in exit_hooks:
                    ql.hook_del(e)
                exit_hooks = []
                ql.mem.unmap(params_mem & 0xfffff000, 0x1000)

                client_socket.send(b"ok"+p32(ret))
            elif f == FUNCS.func_TEEC_ReleaseSharedMemory.value and l == 8:
                buf = u64(d)
                ql.log.debug(f"func_TEEC_ReleaseSharedMemory: {buf:#0x}")
                if buf not in bufc2py:
                    ql.log.error(f"unknown buf {buf:#0x} in {bufc2py}")
                    sock.close()
                    exit(-1)
                (shm_size, shm, pybuf) = bufc2py[buf]
                ql.mem.unmap(pybuf, shm_size)
                del(shm)
                del bufc2py[buf]
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_CloseSession.value and l == 4:
                sid = u32(d)
                ql.log.debug(f"func_TEEC_CloseSession: {sid}")
                if sid != session_opened:
                    ql.log.error(f"unknown session id {sid}")
                    sock.close()
                    exit(-1)
                session_opened = 0

                ql.log.info(f"[////TA_CloseSessionEntryPoint////] start @{TA_CloseSessionEntryPoint_start:#0x}")
                client_socket.send(b"ok")
            elif f == FUNCS.func_TEEC_FinalizeContext.value and l == 4 and d == b'quit':
                ql.log.debug(f"func_TEEC_FinalizeContext")
                break
            else:
                ql.log.error(f"Recved unknown msg {f, l, d}")
                sock.close()
                exit(-1)

        ql.log.info(f"[////TA_DestroyEntryPoint////] start @{TA_DestroyEntryPoint_start:#0x}")

    except FileNotFoundError:
        print(f"unknown TA: {ta_name}")
        exit(-1)
    # except Exception as e:
    #     print(e)
    sock.close()
    


def exit_handler(ql: Qiling, ret_addr):
    # just a graceful return from the main function
    ql.log.info(f"hit return point at {hex(ret_addr)}, exiting")
    ql.emu_stop()


