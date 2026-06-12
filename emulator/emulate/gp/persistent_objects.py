from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER

from .utils.data import *
from .utils.persistent_object import *
from .utils.err import *

from .transient_objects import handle2obj
from ..common import crash, crash_notimpl
import unicorn
import os


def TEE_CreatePersistentObject(ql: Qiling, hook_data):
    global handler_cnt
    params = ql.os.resolve_fcall_params(
        {
            "storageID": UINT,
            "objectID": POINTER,
            "objectIDLen": UINT,
            "flags": UINT,
            "attributes": POINTER,
            "initialData": POINTER,
            "initialDataLen": UINT,
            "object": POINTER,
        }
    )
    para_storageID = params["storageID"]
    para_objectID = params["objectID"]
    para_objectIDLen = params["objectIDLen"]
    para_flags = params["flags"]
    para_attributes = params["attributes"]
    para_initialData = params["initialData"]
    para_initialDataLen = params["initialDataLen"]
    para_object = params["object"]

    hook_data.emu.update_shm(para_objectID)
    hook_data.emu.update_shm(para_attributes)
    hook_data.emu.update_shm(para_initialData)

    ql.log.info(f"TEE_CreatePersistentObject: ")
    if para_storageID == TEE_STORAGE_PRIVATE or MITEE_FILE_STORAGE:

        if para_objectIDLen > TEE_OBJECT_ID_MAX_LEN:
            ql.log.error(f"TEE_CreatePersistentObject: objectID too long {hex(para_objectIDLen)}")
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
        try:
            objectID = bytes(ql.mem.read(para_objectID, para_objectIDLen))
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, hook_data.func_name)
            return
        ql.log.info(f"\tobjectID: {objectID}")

        # open a handler
        obj = perObject(
            para_flags, para_storageID, objectID, handler_cnt, True, para_attributes, ql
        )
        handler_cnt += 1
        handler2perobj[obj.handler] = obj

        if para_initialDataLen != 0:
            data = ql.mem.read(para_initialData, para_initialDataLen)
            obj.write(data, ql)

        ql.log.info(f"\tobject handler: {obj.handler}")
        try:
            ql.mem.write_ptr(para_object, obj.handler)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, hook_data.func_name)
            return
        ret = TEE_SUCCESS
    else:
        ret = TEE_ERROR_ITEM_NOT_FOUND

    hook_data.emu.writeback_shm(para_object)
    ql.log.info(f"\tret {hex(ret)}")
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_OpenPersistentObject(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    global handler_cnt
    params = ql.os.resolve_fcall_params(
        {
            "storageID": UINT,
            "objectID": POINTER,
            "objectIDLen": UINT,
            "flags": UINT,
            "object": POINTER,
        }
    )
    para_storageID = params["storageID"]
    para_objectID = params["objectID"]
    para_objectIDLen = params["objectIDLen"]
    para_flags = params["flags"]
    para_object = params["object"]

    ql.log.info(f"TEE_OpenPersistentObject: ")

    hook_data.emu.update_shm(para_objectID, para_objectIDLen)
    objectID = bytes(ql.mem.read(para_objectID, para_objectIDLen))
    ql.log.info(f"\tobjectID {objectID}")

    # open a handler
    obj = perObject(para_flags, para_storageID, objectID, handler_cnt, False, 0x0, ql)
    if obj.file == None:
        ret = TEE_ERROR_ITEM_NOT_FOUND
        # fail, fill object with TEE_HANDLE_NULL.
        try:
            ql.mem.write_ptr(para_object, TEE_HANDLE_NULL)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, func_name)
            return
    else:
        handler_cnt += 1
        handler2perobj[obj.handler] = obj
        ret = TEE_SUCCESS
        try:
            ql.mem.write_ptr(para_object, obj.handler)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, func_name)
            return
        ql.log.info(f"\tobject handler: {obj.handler}")

    hook_data.emu.writeback_shm(para_object)
    ql.log.info(f"\tret {hex(ret)}")
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_WriteObjectData(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params(
        {"object": UINT, "buffer": POINTER, "size": UINT}
    )
    para_object = params["object"]
    para_buffer = params["buffer"]
    para_size = params["size"]

    hook_data.emu.update_shm(para_object)
    hook_data.emu.update_shm(para_buffer, para_size)
    ql.log.info(f"{func_name}: object handler {para_object}")

    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not a valid object handle")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    obj = handler2perobj[para_object]
    if obj.flag & TEE_DATA_FLAG_ACCESS_WRITE == 0:
        ql.log.error(f"{func_name}: {para_object} not opened for write (flag {hex(obj.flag)})")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_CONFLICT)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    
    # atomic?
    try:
        data = bytes(ql.mem.read(para_buffer, para_size))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    obj.write(data, ql)

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_SeekObjectData(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params(
        {"object": UINT, "offset": UINT, "whence": UINT}
    )
    para_object = params["object"]
    offset = params["offset"]
    whence = params["whence"]

    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not a valid object handle")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    hook_data.emu.update_shm(para_object)
    # whence maps 1:1 to Python file.seek (SET=0, CUR=1, END=2). perObject.seek
    # already does the real seek -- previously only offset==0/whence==0 was
    # accepted and anything else emu_stop()ed, which broke any TA that reads a
    # record at a non-zero position.
    obj = handler2perobj[para_object]
    try:
        obj.seek(offset, whence)
    except Exception as e:
        ql.log.warning(f"TEE_SeekObjectData: seek({offset},{whence}) failed: {e}")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_CloseObject(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT})
    para_object = params["object"]

    # currently this can only close persistent obj
    ql.log.info(f"{func_name}: object handler {para_object}")

    if para_object == TEE_HANDLE_NULL:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    if para_object not in handler2perobj:
        if para_object in handle2obj:
            obj = handle2obj[para_object]
            for attr in obj.attrs:
                del attr
            del handle2obj[para_object]  # delete from dict
            del obj  # delete object
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return

        ql.log.error(
            f"{func_name}: {para_object} not in {handler2perobj} or {handle2obj}"
        )
        ql.emu_stop()
    obj = handler2perobj[para_object]
    obj.file_close(ql)
    # storage is persistent, we only remove the handler, don't free or unmap anything
    del handler2perobj[para_object]
    del obj

    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_CloseAndDeletePersistentObject1(ql: Qiling, hook_data):
    TEE_CloseAndDeletePersistentObject(ql, hook_data)


def TEE_CloseAndDeletePersistentObject(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT})
    para_object = params["object"]

    # currently this can only close persistent obj
    ql.log.info(f"{func_name}: object handler {para_object}")
    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not a valid object handle")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    obj = handler2perobj[para_object]
    obj.file_close_and_delete(ql)
    del handler2perobj[para_object]
    del obj

    # success path must report TEE_SUCCESS; otherwise the stale return reg (the
    # object handle) is read by the TA as a failure (e.g. teessu clear_ssu_data
    # logged "Failed to delete object" while the file *was* deleted).
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_ReadObjectData(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params(
        {"object": UINT, "buffer": POINTER, "size": UINT, "count": POINTER}
    )
    para_object = params["object"]
    para_buffer = params["buffer"]
    para_size = params["size"]
    para_count = params["count"]

    ql.log.info(f"{func_name}: object handler {para_object}, size {para_size:#0x}")

    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not a valid object handle")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    obj = handler2perobj[para_object]

    # atomic?
    data = obj.read(para_size, ql)
    try:
        ql.mem.write(para_buffer, data)
        ql.mem.write(para_count, len(data).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, func_name)
        return
    hook_data.emu.writeback_shm(para_buffer, para_count)
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GetObjectInfo1(ql: Qiling, hook_data):
    TEE_GetObjectInfo(ql, hook_data)


def TEE_GetObjectInfo(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT, "objectInfo": POINTER})
    para_object = params["object"]
    para_objectInfo = params["objectInfo"]

    ql.log.info(f"{func_name}: object handler {para_object}")
    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not a valid object handle")
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    obj = handler2perobj[para_object]

    #     typedef struct {
    # 2231 uint32_t objectType;
    # 2232 uint32_t objectSize;
    # 2233 uint32_t maxObjectSize;
    # 2234 uint32_t objectUsage;
    # 2235 uint32_t dataSize;
    # 2236 uint32_t dataPosition;
    # 2237 uint32_t handleFlags;
    # 2238 } TEE_ObjectInfo;

    # @TODO: more info need to fill
    try:
        ql.mem.write_ptr(para_objectInfo + 16, obj.file_size(ql))
        ql.mem.write_ptr(para_objectInfo + 20, obj.file.tell())
        ql.mem.write_ptr(para_objectInfo + 24, obj.flag)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return

    hook_data.emu.writeback_shm(para_objectInfo)
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# --- persistent-object enumerator (TEE_*PersistentObjectEnumerator) ---------
# Lets a TA list the objects in a storage. Backed by the same flat file store as
# perObject (FILE_PREFIX/<storageID>/<objectID>). 4 corpus TAs import these.
_enumerators = {}
_enum_cnt = 0x40000

def TEE_AllocatePersistentObjectEnumerator(ql: Qiling, hook_data):
    global _enum_cnt
    p = ql.os.resolve_fcall_params({"enumerator": POINTER})
    h = _enum_cnt
    _enum_cnt += 1
    _enumerators[h] = {"items": [], "idx": 0}
    try:
        ql.mem.write_ptr(p["enumerator"], h)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_FreePersistentObjectEnumerator(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"enumerator": UINT})
    _enumerators.pop(p["enumerator"], None)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_ResetPersistentObjectEnumerator(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"enumerator": UINT})
    e = _enumerators.get(p["enumerator"])
    if e is not None:
        e["idx"] = 0
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_StartPersistentObjectEnumerator(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"enumerator": UINT, "storageID": UINT})
    e = _enumerators.get(p["enumerator"])
    if e is None:
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_BAD_PARAMETERS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    # store_listdir picks the on-disk or in-memory backend (determinism mode)
    e["items"] = store_listdir(p['storageID'])
    e["idx"] = 0
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS if e["items"] else TEE_ERROR_ITEM_NOT_FOUND)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_GetNextPersistentObject(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
        {"enumerator": UINT, "objectInfo": POINTER, "objectID": POINTER, "objectIDLen": POINTER}
    )
    e = _enumerators.get(p["enumerator"])
    if e is None or e["idx"] >= len(e["items"]):
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_ITEM_NOT_FOUND)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    name = e["items"][e["idx"]]
    e["idx"] += 1
    idb = name.encode("latin-1", "replace")
    try:
        if p["objectID"]:
            ql.mem.write(p["objectID"], idb)
        if p["objectIDLen"]:
            ql.mem.write_ptr(p["objectIDLen"], len(idb))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"TEE_GetNextPersistentObject -> {name!r}")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
