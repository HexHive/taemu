from qiling import Qiling
import os
from .object import filepaths2tranobjs, handle2obj
from ...common import NOTIMPL_PC
from ...determinism import MEM_STORE_ENABLED

PERSISTENT_OBJECT_MEM = 0xAA00000

# not defined in gp???
TEE_OBJECT_ID_MAX_LEN = 0x100

TEE_HANDLE_NULL = 0

# every handler corresponse to one object
# one can open two handlers for one object, they might have different flags
handler2perobj = {}
handler_cnt = 1

FILE_PREFIX = "./emulate/files/"

# --- persistent-store backend ------------------------------------------------
# Default: real files under FILE_PREFIX (interactive runs want cross-session
# persistence). Under TAEMU_DETERMINISM / TAEMU_MEM_STORE the store is held in
# process memory instead, so (a) it never pollutes the working tree, and (b) the
# AFL fork server resets it for free every iteration via copy-on-write -- no
# cross-iteration accumulation, fully reproducible. See emulate/determinism.py.
MEM_STORE = {}  # full-path str -> bytearray (live contents)


class _MemFile:
    """Minimal rb+-like handle over a bytearray that lives in MEM_STORE, so
    writes persist across opens within the process (until fork/reset)."""

    def __init__(self, store, name):
        self._store = store
        self._name = name
        store.setdefault(name, bytearray())
        self.pos = 0

    def _buf(self):
        return self._store[self._name]

    def write(self, data):
        b = self._buf()
        end = self.pos + len(data)
        if end > len(b):
            b.extend(b"\x00" * (end - len(b)))
        b[self.pos:end] = data
        self.pos = end

    def read(self, n=-1):
        b = self._buf()
        if n is None or n < 0:
            n = len(b) - self.pos
        out = bytes(b[self.pos:self.pos + n])
        self.pos += len(out)
        return out

    def seek(self, offset, whence=0):
        b = self._buf()
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = len(b) + offset
        return self.pos

    def tell(self):
        return self.pos

    def close(self):
        pass


def _store_exists(name):
    if MEM_STORE_ENABLED:
        return name in MEM_STORE
    return os.path.exists(name)


def _store_open(name):
    """Open (creating if absent) and return an rb+-style handle positioned at 0.
    Mirrors the original open(...,'rb+') semantics: existing content preserved,
    no truncation on create (parity with prior on-disk behavior)."""
    if MEM_STORE_ENABLED:
        return _MemFile(MEM_STORE, name)
    d = os.path.dirname(name)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(name):
        open(name, "w").close()
    return open(name, "rb+")


def _store_remove(name):
    if MEM_STORE_ENABLED:
        MEM_STORE.pop(name, None)
        return
    os.remove(name)


def _store_size(name):
    if MEM_STORE_ENABLED:
        return len(MEM_STORE.get(name, b""))
    return os.path.getsize(name)


def store_listdir(storage_id):
    """Object names (basenames) in a storage, matching os.listdir semantics.
    Exported (no leading underscore) for the enumerator in persistent_objects."""
    if MEM_STORE_ENABLED:
        prefix = f"{FILE_PREFIX}{storage_id}/"
        return sorted(k[len(prefix):] for k in MEM_STORE if k.startswith(prefix))
    try:
        return sorted(os.listdir(f"{FILE_PREFIX}{storage_id}"))
    except OSError:
        return []


def store_reset():
    """Clear the in-memory store (single-process replay determinism; the fork
    server resets it automatically for parallel fuzzing)."""
    if MEM_STORE_ENABLED:
        MEM_STORE.clear()


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
        self.objectID = self.objectID.replace("/", "-") 
        self.storageID = storageID
        self.file_name = f"{FILE_PREFIX}{self.storageID}/{self.objectID}"
        if self.file_name in filepaths2tranobjs:
            self.connected_trans_obj = filepaths2tranobjs[self.file_name]
        if self.connected_trans_obj is not None:
            filepaths2tranobjs[self.file_name] = self.connected_trans_obj
        ql.log.info(f"\tfile name: {self.file_name}")
        if self.connected_trans_obj is None:
            if not iscreated and not _store_exists(self.file_name):
                self.file = None
                return
            else:
                # backend picks real file vs in-memory (see _store_open)
                self.file = _store_open(self.file_name)
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

    def file_size(self, ql:Qiling):
        return _store_size(self.file_name)
    
    def file_close(self, ql:Qiling):
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
        _store_remove(self.file_name)
