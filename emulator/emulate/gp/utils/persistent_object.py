from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .data import *
import os

PERSISTENT_OBJECT_MEM = 0xaa00000

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
    def __init__(self, flag, storageID, objectID, handler, iscreated, ql:Qiling) -> None:
        self.flag = flag
        self.objectID = objectID.decode('utf-8')
        self.storageID = storageID
        self.file_name = f"{FILE_PREFIX}{self.storageID}/{self.objectID}"
        ql.log.info(f"\tfile name: {self.file_name}")
        if not iscreated and not os.path.exists(self.file_name):
            self.file = None
            return
        else:      
            if not os.path.exists(f"{FILE_PREFIX}{self.storageID}"): os.mkdir(f"{FILE_PREFIX}{self.storageID}")
            if flag & TEE_DATA_FLAG_ACCESS_WRITE != 0:
                self.file = open(self.file_name, 'wb')
            else:
                self.file = open(self.file_name, 'rb')
            ql.log.info(f"\topen file at {FILE_PREFIX+self.objectID}")
        self.handler = handler

    def write(self, data, ql:Qiling):
        ql.log.info(f"\twrite to object: {data.hex()[:8]}{len(data)}")
        self.file.write(data)

    def read(self, size, ql:Qiling):
        return self.file.read(size)
    
    def file_size(self, ql:Qiling):
        return os.path.getsize(self.file_name)
    
    def file_close(self, ql:Qiling):
        self.file.close()

    def file_close_and_delete(self, ql:Qiling):
        self.file.close()
        os.remove(self.file_name)
