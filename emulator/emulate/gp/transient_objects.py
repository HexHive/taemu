from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from pwn import *
from .utils.err import *
from .utils.object import *
from .utils.attribute import *
from ..common import crash, crash_notimpl
import unicorn

def TEE_AllocateTransientObject(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'objectType': UINT, 'maxObjectSize': UINT, 'object': POINTER})
    objectType = params['objectType']
    maxObjectSize = params['maxObjectSize']
    para_object = params['object']
    ql.log.info("TEE_AllocateTransientObject: ")
    if objectType == ObjectTypes.TEE_TYPE_RSA_KEYPAIR.value: #TEE_TYPE_RSA_KEYPAIR
        new_obj = RSA_KEYPAIR_Obj(maxObjectSize, ql)
        handle2obj[new_obj.handle] = new_obj
        try:
            ql.mem.write_ptr(para_object, new_obj.handle)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, func_name)
            return
        ql.log.info(f'\tallocated {ObjectTypes.TEE_TYPE_RSA_KEYPAIR.name} with {hex(maxObjectSize)} bytes at {hex(new_obj.handle)}, stored at {hex(para_object)}')
        # @TODO: error return value
        ql.os.fcall.cc.setReturnValue(0)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif objectType == ObjectTypes.TEE_TYPE_AES.value:
        new_obj = AES_Obj(maxObjectSize, ql)
        handle2obj[new_obj.handle] = new_obj
        try:
            ql.mem.write_ptr(para_object, new_obj.handle)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, func_name)
            return 
        ql.log.info(f'\tallocated {ObjectTypes.TEE_TYPE_AES.name} with {hex(maxObjectSize)} bytes at {hex(new_obj.handle)}, stored at {hex(para_object)}')
        # @TODO: error return value
        ql.os.fcall.cc.setReturnValue(0)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    else:
        ql.log.error(f'TEE_AllocateTransientObject unknown object type!! {hex(objectType)}')
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f'TEE_AllocateTransientObject unknown object type!! {hex(objectType)}')
            return
        ql.emu_stop()


def TEE_GenerateKey(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'object': POINTER, 'keySize': UINT, 'params': POINTER, 'paramCount': UINT})
    para_object = params['object']
    para_keySize = params['keySize']
    para_params = params['params']
    para_paramCount = params['paramCount']

    ql.log.info(f'TEE_GenerateKey: ')
    if para_object not in handle2obj:
        ql.log.error(f'TEE_GenerateKey: called with {hex(para_object)} not in {handle2obj}')
        ql.emu_stop()
    obj = handle2obj[para_object]
    ret = obj.generateKey(para_keySize, para_params, para_paramCount, ql)
    ql.log.info(f"\treturn {hex(ret)}")
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



def TEE_PopulateTransientObject(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name 
    params = ql.os.resolve_fcall_params({'object': POINTER, 'attrs': POINTER, 'attrCount': UINT})
    para_object = params['object']
    para_attrs = params['attrs']
    para_attrCount = params['attrCount']

    ql.log.info(f'TEE_PopulateTransientObject: ')
    if para_object not in handle2obj:
        ql.log.error(f'TEE_PopulateTransientObject: called with {hex(para_object)} not in {handle2obj}')
        ql.emu_stop()
    obj = handle2obj[para_object]

    # if object is initialized, the caller should first call TEE_ResetTransientObject before using TEE_PopulateTransientObject
    if obj.initialized:
        ql.log.error(f'TEE_PopulateTransientObject: object {hex(para_object)} already initialized!!')
        ql.emu_stop()

    ret = obj.populate(para_attrs, para_attrCount, ql)
    ql.log.info(f"\treturn {hex(ret)}")
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_ResetTransientObject(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'object': POINTER})
    para_object = params['object']
    ql.log.info(f'TEE_ResetTransientObject: ')
    if para_object not in handle2obj:
        ql.log.error(f'TEE_ResetTransientObject: called with {hex(para_object)} not in {handle2obj}')
        crash(ql, func_name)
        return
    obj = handle2obj[para_object]
    # @TODO: In any case, the function resets the key usage of the container to 0xFFFFFFFFF
    for attr in obj.attrs:
        del(attr)
    obj.initialized = False
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_FreeTransientObject(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'object': POINTER})
    para_object = params['object']
    if para_object not in handle2obj:
        ql.log.error(f'TEE_FreeTransientObject: called with {hex(para_object)} not in {handle2obj}')
        crash(ql, func_name)
        return
    obj = handle2obj[para_object]
    for attr in obj.attrs:
        del(attr)
    del(handle2obj[para_object])    # delete from dict
    del(obj)    # delete object
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_InitRefAttribute(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'attr': POINTER, "attributeID": UINT, "buffer": POINTER, "length": UINT})
    para_attr = params['attr']
    para_attributeID = params['attributeID']
    para_buffer = params['buffer']
    para_length = params['length']

    ql.log.info(f'TEE_InitRefAttribute: attributeID {hex(para_attributeID)}')
    if (para_attributeID >> 29) & 0x1 != 0:
        ql.log.error(f'TEE_InitRefAttribute: attributeID {hex(para_attributeID)} not consistent')
        ql.emu_stop() 

    try:
        ql.mem.write(para_attr, p32(para_attributeID))
        ql.mem.write_ptr(para_attr + 4, para_buffer)
        ql.mem.write_ptr(para_attr + ql.arch.pointersize, para_length)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_InitValueAttribute(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'attr': POINTER, "attributeID": UINT, "a": POINTER, "b": length})
    para_attr = params['attr']
    para_attributeID = params['attributeID']
    para_a = params['a']
    para_b = params['b']

    ql.log.info(f'TEE_InitValueAttribute: attributeID {hex(para_attributeID)}')
    if (para_attributeID >> 29) & 0x1 != 1:
        ql.log.error(f'TEE_InitRefAttribute: attributeID {hex(para_attributeID)} not consistent')
        ql.emu_stop() 

    try:
        ql.mem.write(para_attr, p32(para_attributeID))
        ql.mem.write_ptr(para_attr + 4, para_a, 4)
        ql.mem.write(para_attr + 8, para_b, 4)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_CopyObjectAttributes1(ql:Qiling, hook_data):
    emu = hook_data.emu
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'destObject': UINT, "srcObject": UINT})
    para_destObject = params['destObject']
    para_srcObject = params['srcObject']

    ql.log.debug(f'TEE_CopyObjectAttributes1: dest {hex(para_destObject)}, src {hex(para_srcObject)}, {handle2obj}')

    if para_destObject not in handle2obj:
        ql.log.error(f'TEE_CopyObjectAttributes1: called with {hex(para_destObject)} not in {handle2obj}')
        ql.emu_stop()
    destObj = handle2obj[para_destObject]

    if para_srcObject not in handle2obj:
        ql.log.error(f'TEE_CopyObjectAttributes1: called with {hex(para_srcObject)} not in {handle2obj}')
        ql.emu_stop()
    srcObj = handle2obj[para_srcObject]

    ret = destObj.copy_from(srcObj, ql)
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    
    

