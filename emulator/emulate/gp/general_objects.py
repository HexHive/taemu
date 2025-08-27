from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.object import *
from .utils.attribute import *
from .utils.err import *
from pwn import *


def TEE_GetObjectBufferAttribute(ql:Qiling, hook_data):
    params = ql.os.resolve_fcall_params({'object': UINT, 'attributeID': UINT, 'buffer': POINTER, 'size': POINTER})
    para_object = params['object']
    para_attributeID = params['attributeID']
    para_buffer = params['buffer']
    para_size = params['size']  

    ql.log.info(f"TEE_GetObjectBufferAttribute")
    ql.log.debug(f"TEE_GetObjectBufferAttribute: current {handle2obj}, with para_object {para_object}:{hex(para_object)}")

    if para_object not in handle2obj:
        ql.log.error(f'TEE_GetObjectBufferAttribute: called with {hex(para_object)} not in {handle2obj}')
        ql.emu_stop()
    obj = handle2obj[para_object]

    if obj.initialized == False:
        ql.log.error(f'TEE_GetObjectBufferAttribute: obj {hex(para_object)} not initialized')
        ql.emu_stop()

    if (para_attributeID >> 29) & 0x1 != 0:
        ql.log.error(f'TEE_GetObjectBufferAttribute: not a buffer attribute')
        ql.emu_stop()

    # @TODO: If Bit [28] of attributeID is set to 0, denoting a protected attribute, and the object usage does not contain the TEE_USAGE_EXTRACTABLE flag.
    # if (para_attributeID >> 28) & 0x1 == 0:
    #     ql.log.error(f'TEE_GetObjectBufferAttribute: not a buffer attribute')
    #     ql.emu_stop()

    
    if para_attributeID not in obj.attrs:
        ret = TEE_ERROR_ITEM_NOT_FOUND
    else:
        ql.log.debug(f"\tattr.attributeID: {hex(para_attributeID)}")
        (buffer, size) = obj.attrs[para_attributeID]
        data = bytes(ql.mem.read(buffer, size))
        ql.log.info(f"\tdata: {data}")
        ql.mem.write(para_buffer, data)
        ql.mem.write_ptr(para_size, size)
        ret = TEE_SUCCESS

    ql.log.info(f"\treturn {hex(ret)}")
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
