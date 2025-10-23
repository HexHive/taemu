from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .data import *
import os
from .object import filepaths2tranobjs, handle2obj
from ...common import NOTIMPL_PC

PERSISTENT_OBJECT_MEM = 0xAA00000

# not defined in gp???
TEE_OBJECT_ID_MAX_LEN = 0x100

TEE_HANDLE_NULL = 0

# every handler corresponse to one object
# one can open two handlers for one object, they might have different flags
handler2perobj = {}
handler_cnt = 1

FILE_PREFIX = "./emulate/files/"


def memory_alignment_round_up(addr, roundup):
    return addr - (addr % roundup) + roundup


class perObject:
    def __init__(
        self, flag, storageID, objectID, handler, iscreated, para_attributes, ql: Qiling
    ) -> None:
        self.para_attributes = para_attributes
        self.connected_trans_obj = None
        if self.para_attributes != 0x0:
            for handle, obj in handle2obj.items():
                if handle == self.para_attributes:
                    self.connected_trans_obj = obj
                    self.connected_trans_obj.persistent = True
            if self.connected_trans_obj is None:
                ql.log.warning(
                    f"connected object {hex(self.para_attributes)} not found!!"
                )
                ql.emu_stop()
        self.flag = flag
        if objectID.endswith(b"\x00") and all(b < 128 and b > 0x20 for b in objectID):
            self.objectID = objectID[:-1].decode("ascii")
        elif all(b < 128 and b > 0x20 for b in objectID):
            self.objectID = objectID.decode("ascii")
        else:
            self.objectID = objectID.hex()
        self.storageID = storageID
        self.file_name = f"{FILE_PREFIX}{self.storageID}/{self.objectID}"
        if self.file_name in filepaths2tranobjs:
            self.connected_trans_obj = filepaths2tranobjs[self.file_name]
        if self.connected_trans_obj is not None:
            filepaths2tranobjs[self.file_name] = self.connected_trans_obj
        ql.log.info(f"\tfile name: {self.file_name}")
        if self.connected_trans_obj is None:
            if not iscreated and not os.path.exists(self.file_name):
                self.file = None
                return
            else:
                if not os.path.exists(f"{FILE_PREFIX}{self.storageID}"):
                    os.mkdir(f"{FILE_PREFIX}{self.storageID}")
                if not os.path.exists(self.file_name):
                    open(self.file_name, "w")
                if flag & TEE_DATA_FLAG_ACCESS_WRITE != 0:
                    self.file = open(self.file_name, "rb+")
                else:
                    self.file = open(self.file_name, "rb+")
                ql.log.info(f"\topen file at {FILE_PREFIX+self.objectID}")
        self.handler = handler

    def write(self, data, ql: Qiling):
        ql.log.info(f"\twrite to object: {data.hex()[:8]}{len(data)}")
        if self.connected_trans_obj is not None:
            ql.log.warning(
                f"write on persistent object with connected transient object not implemented!!"
            )
            ql.arch.regs.arch_pc = NOTIMPL_PC
            ql.emu_stop()
        self.file.write(data)
        # open(self.file_name, 'wb').write(data)

    def read(self, size, ql: Qiling):
        if self.connected_trans_obj is not None:
            ql.log.warning(
                f"read on persistent object with connected transient object not implemented!!"
            )
            ql.arch.regs.arch_pc = NOTIMPL_PC
            ql.emu_stop()
        return self.file.read(size)
        return open(self.file_name, "rb").read(size)

    def seek(self, offset, whence):
        self.file.seek(offset, whence)

    def file_size(self, ql: Qiling):
        return os.path.getsize(self.file_name)

    def file_close(self, ql: Qiling):
        if self.connected_trans_obj is None:
            # no connected transient object
            self.file.close()

    def file_close_and_delete(self, ql: Qiling):
        if self.connected_trans_obj is not None:
            ql.log.warning(
                f"close_delete on persistent object with connected transient object not implemented!!"
            )
            ql.arch.regs.arch_pc = NOTIMPL_PC
            ql.emu_stop()
        self.file.close()
        os.remove(self.file_name)
