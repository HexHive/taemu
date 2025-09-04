from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER

from .utils.data import *
from .utils.persistent_object import *
from .utils.err import *

from .transient_objects import handle2obj
from ..common import crash, crash_notimpl
import unicorn


def TEE_CreatePersistentObject(ql:Qiling, hook_data):
    global handler_cnt
    params = ql.os.resolve_fcall_params({'storageID': UINT, 'objectID': POINTER, 'objectIDLen': UINT,
                                        'flags': UINT, 'attributes': POINTER, 'initialData': POINTER, 'initialDataLen': UINT, "object": POINTER})
    para_storageID = params['storageID']
    para_objectID = params['objectID']
    para_objectIDLen = params['objectIDLen']
    para_flags = params['flags']
    para_attributes = params['attributes']
    para_initialData = params['initialData']
    para_initialDataLen = params['initialDataLen']
    para_object = params['object']

    ql.log.info(f'TEE_CreatePersistentObject: ')
    if para_storageID == TEE_STORAGE_PRIVATE or MITEE_FILE_STORAGE:

        if para_objectIDLen > TEE_OBJECT_ID_MAX_LEN:
            ql.log.error(f"TEE_CreatePersistentObject: objectID too long {hex(para_objectIDLen)}")
            ql.emu_stop()
        try:
            objectID = bytes(ql.mem.read(para_objectID, para_objectIDLen))
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, hook_data.func_name)
            return
        ql.log.info(f"\tobjectID: {objectID}")

        # open a handler
        obj = perObject(para_flags, para_storageID, objectID, handler_cnt, True, ql)
        handler_cnt += 1
        handler2perobj[obj.handler] = obj

        if para_attributes != 0:
            ql.log.error("Not implemented yet. Need refaction, as in, perObj and tranObj are both Obj")
            ql.emu_stop()

        if para_initialDataLen != 0:
            data = ql.mem.read(para_initialData, para_initialDataLen)
            obj.write(data, para_initialDataLen, ql)

        ql.log.info(f"\tobject handler: {obj.handler}") 
        try:
            ql.mem.write_ptr(para_object, obj.handler) 
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, hook_data.func_name)
            return
        ret = TEE_SUCCESS
    else:
        ret = TEE_ERROR_ITEM_NOT_FOUND
    
    ql.log.info(f'\tret {hex(ret)}')
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



def TEE_OpenPersistentObject(ql:Qiling, hook_data):
    func_name = hook_data.func_name 
    global handler_cnt
    params = ql.os.resolve_fcall_params({'storageID': UINT, 'objectID': POINTER, 'objectIDLen': UINT,
                                         'flags': UINT, "object": POINTER})
    para_storageID = params['storageID']
    para_objectID = params['objectID']
    para_objectIDLen = params['objectIDLen']
    para_flags = params['flags']
    para_object = params['object']

    ql.log.info(f'TEE_OpenPersistentObject: ')

    objectID = bytes(ql.mem.read(para_objectID, para_objectIDLen))
    ql.log.info(f"\tobjectID {objectID}")

    # open a handler
    obj = perObject(para_flags, para_storageID, objectID, handler_cnt, False, ql)
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

    ql.log.info(f'\tret {hex(ret)}')
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



def TEE_WriteObjectData(ql:Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'object': UINT, 'buffer': POINTER, 'size': UINT})
    para_object = params['object']
    para_buffer = params['buffer']
    para_size = params['size']
    
    ql.log.info(f'{func_name}: object handler {para_object}')

    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not in {handler2perobj}")
        ql.emu_stop()

    obj = handler2perobj[para_object]
    if obj.flag & TEE_DATA_FLAG_ACCESS_WRITE == 0:
        ql.log.error(f"{func_name}: {para_object} flag {obj.flags} error")
        ql.emu_stop()
    
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
    params = ql.os.resolve_fcall_params({'object': UINT, 'offset': UINT, 'whence': UINT})
    para_object = params['object']
    offset = params['offset']
    whence = params['whence']

    if offset == 0 and whence == 0:
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else: 
        ql.log.warning(f'TEE_SeekObjectData not properly implemetned')
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f'TEE_SeekObjectDat')
            return
        ql.emu_stop()


def TEE_CloseObject(ql:Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT})
    para_object = params['object']

    # currently this can only close persistent obj
    ql.log.info(f'{func_name}: object handler {para_object}')

    if para_object == TEE_HANDLE_NULL:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return 

    if para_object not in handler2perobj:

        if para_object in handle2obj:
            obj = handle2obj[para_object]
            for attr in obj.attrs:
                del(attr)
            del(handle2obj[para_object])    # delete from dict
            del(obj)    # delete object
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return

        ql.log.error(f"{func_name}: {para_object} not in {handler2perobj} or {handle2obj}")
        ql.emu_stop()
    obj = handler2perobj[para_object]
    obj.file_close(ql)
    # storage is persistent, we only remove the handler, don't free or unmap anything
    del(handler2perobj[para_object])
    del(obj)
    
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_CloseAndDeletePersistentObject1(ql: Qiling, hook_data):
    TEE_CloseAndDeletePersistentObject(ql, hook_data)

def TEE_CloseAndDeletePersistentObject(ql:Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT})
    para_object = params['object']

    # currently this can only close persistent obj
    ql.log.info(f'{func_name}: object handler {para_object}')
    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not in {handler2perobj}")
        ql.emu_stop()
    obj = handler2perobj[para_object]
    obj.file_close_and_delete(ql)
    del(handler2perobj[para_object])
    del(obj)
    
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_ReadObjectData(ql:Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'object': UINT, 'buffer': POINTER, 'size': UINT, "count": POINTER})
    para_object = params['object']
    para_buffer = params['buffer']
    para_size = params['size']
    para_count = params['count']

    ql.log.info(f'{func_name}: object handler {para_object}, size {para_size:#0x}')

    obj = handler2perobj[para_object]
    
    # atomic?
    data = obj.read(para_size, ql)
    try:
        ql.mem.write(para_buffer, data)
        ql.mem.write(para_count, len(data).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, func_name)
        return

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GetObjectInfo(ql:Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"object": UINT, "objectInfo": POINTER})
    para_object = params['object']
    para_objectInfo = params['objectInfo']

    ql.log.info(f'{func_name}: object handler {para_object}')
    if para_object not in handler2perobj:
        ql.log.error(f"{func_name}: {para_object} not in {handler2perobj}")
        ql.emu_stop()
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

    ql.arch.regs.arch_pc = ql.arch.regs.lr


    
