from .utils.crypto import *
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.err import *
from .utils.object import *
from ..common import crash, crash_notimpl
import unicorn

OPERATION_ID = 0
id2opration = {}

def TEE_AllocateOperation(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': POINTER, "algorithm": UINT, "mode": UINT, "maxKeySize": UINT})
    param_operation = params['operation']
    param_algorithm = params['algorithm']
    param_mode = params['mode']
    param_maxKeySize = params['maxKeySize']

    ql.log.info(f"TEE_AllocateOperation: ")

    try:
        ret = TEE_SUCCESS
        if param_algorithm == TEE_ALG_SHA256 and param_mode == TEE_MODE_DIGEST:
            ql.log.info(f"\tTEE_ALG_SHA256")
            op = Digest_Operation(OPERATION_ID, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1      
        elif param_algorithm == TEE_ALG_MD5 and param_mode == TEE_MODE_DIGEST:
            ql.log.info(f"\tTEE_ALG_MD5")
            op = MD5_Operation(OPERATION_ID, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1      
        elif param_algorithm == TEE_ALG_RSAES_PKCS1_V1_5:
            ql.log.info(f"\tTEE_ALG_RSAES_PKCS1_V1_5")
            op = RSAES_PKCS1_V1_5_Operation(OPERATION_ID, param_mode, param_maxKeySize, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1
        elif param_algorithm == TEE_ALG_AES_ECB_NOPAD:
            ql.log.info(f"\tTEE_ALG_AES_ECB_NOPAD")
            op = AES_ECB_NOPAD_Operation(OPERATION_ID, param_mode, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1
        elif param_algorithm == TEE_ALG_AES_CBC_NOPAD:
            ql.log.info(f"\tTEE_ALG_AES_CBC_NOPAD")
            op = AES_CBC_NOPAD_Operation(OPERATION_ID, param_mode, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1
        elif param_algorithm == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
            ql.log.info(f"\tTEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256")
            op = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256_Operation(OPERATION_ID, param_mode, param_maxKeySize, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1
        elif param_algorithm == TEEGRIS_LOG_ENC:
            ql.log.info(f"\tTEEGRIS custom log encryption (noop)")
            op = TEEGRIS_LOG_ENC_Operation(OPERATION_ID, param_mode, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1 
        elif param_algorithm == TEE_ALG_HMAC_SHA256:
            ql.log.info(f'\tTEE_ALG_HMAC_SHA256')
            op = TEE_ALG_HMAC_SHA256_Operation(OPERATION_ID, param_mode, ql)
            id2opration[OPERATION_ID] = op
            ql.mem.write_ptr(param_operation, OPERATION_ID)
            OPERATION_ID += 1
        else:
            ql.log.info(f"\t mode {hex(param_mode)} or algo {hex(param_algorithm)} not valid")
            ret = TEE_ERROR_NOT_SUPPORTED
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_DigestUpdate(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, "chunk": POINTER, "chunkSize": UINT})
    param_operation = params['operation']
    param_chunk = params['chunk']
    param_chunkSize = params['chunkSize']

    ql.log.info(f"TEE_DigestUpdate: {hex(param_chunk)} {hex(param_chunkSize)}")

    try:
        if param_operation not in id2opration:
            ql.log.error(f"TEE_DigestUpdate: Operation {hex(param_operation)} not in {id2opration}")
            ql.emu_stop()
        
        op = id2opration[param_operation]
        data = ql.mem.read(param_chunk, param_chunkSize)
        if type(op) == Digest_Operation:
            op.digest_update(data)
        elif type(op) == MD5_Operation:
            op.digest_update(data)
        else: 
            ql.log.error(f"TEE_DigestUpdate: op is not a Digest_Operation {type(op)}")
            ql.emu_stop()

    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_DigestDoFinal(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, "chunk": POINTER, "chunkLen": UINT, "hash": POINTER, "hashLen": POINTER})
    param_operation = params['operation']
    param_chunk = params['chunk']
    param_chunkLen = params['chunkLen']
    param_hash = params['hash']
    param_hashLen = params['hashLen']

    ql.log.info(f"TEE_DigestDoFinal: ")

    try:
        if param_operation not in id2opration:
            ql.log.error(f"TEE_DigestDoFinal: Operation {hex(param_operation)} not in {id2opration}")
            ql.emu_stop()
        
        op = id2opration[param_operation]
        data = ql.mem.read(param_chunk, param_chunkLen)
        if type(op) == Digest_Operation:
            hash = op.finalize(data, param_hashLen, ql)
        elif type(op) == MD5_Operation:
            hash = op.finalize(data, param_hashLen, ql)
        else:
            ql.log.error(f"TEE_DigestDoFinal: op is not a Digest_Operation")
            ql.emu_stop()

        if hash:    
            ql.mem.write(param_hash, hash)
            ret = TEE_SUCCESS
        else:
            ret = TEE_ERROR_SHORT_BUFFER
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



def TEE_FreeOperation(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT})
    param_operation = params['operation']

    ql.log.info(f"TEE_FreeOperation: ")

    if param_operation not in id2opration:
        ql.log.error(f"TEE_FreeOperation: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()
    
    op = id2opration[param_operation]
    del(id2opration[param_operation])
    del(op)

    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_SetOperationKey(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'key': UINT})
    param_operation = params['operation']
    param_key = params['key']

    ql.log.info(f"TEE_SetOperationKey: ")

    try:
        if param_operation not in id2opration:
            ql.log.error(f"TEE_SetOperationKey: Operation {hex(param_operation)} not in {id2opration}")
            ql.emu_stop()
        
        if param_key not in handle2obj:
            ql.log.error(f'TEE_SetOperationKey: called with {hex(param_key)} not in {handle2obj}')
            ql.emu_stop()

        op = id2opration[param_operation]
        key = handle2obj[param_key]

        if type(op) == RSAES_PKCS1_V1_5_Operation:
            if op.initialized:
                ql.log.error(f'TEE_SetOperationKey: op is not an un-initialized operation type of TEE_ALG_RSAES_PKCS1_V1_5')
                ql.emu_stop()

            if type(key) != RSA_KEYPAIR_Obj or not key.initialized:
                ql.log.error(f'TEE_SetOperationKey: key is not a initialized object type of TEE_TYPE_RSA_KEYPAIR')
                ql.emu_stop()

            op.initialize(key.rsa_param, ql)

            ql.log.info(f"\top initialized")
            ql.log.info(f"\tn: {op.key.n}")
            ql.log.info(f"\td: {op.key.d}")
            ql.log.info(f"\te: {op.key.e}")

        elif type(op) == AES_ECB_NOPAD_Operation or type(op) == AES_CBC_NOPAD_Operation:
            if op.initialized:
                ql.log.error(f'TEE_SetOperationKey: op is not an un-initialized operation type {type(op)}')
                ql.emu_stop()

            if type(key) != AES_Obj or not key.initialized:
                ql.log.error(f'TEE_SetOperationKey: key is not a initialized object type of TEE_TYPE_AES')
                ql.emu_stop()

            op.initialize(key.key, ql)

            ql.log.info(f"\t{type(op)} op initialized")
            ql.log.info(f"\tkey: {op.key}")   

        elif type(op) == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256_Operation:
            op.initialize(key.rsa_param, ql)
            ql.log.info("\tALG_RSAES_PKCS1_OAEP_MGF1_SHA256 initialized with new keys, passing...")

        elif type(op) == TEEGRIS_LOG_ENC_Operation:
            op.initialize(key.key, ql)

        elif type(op) == TEE_ALG_HMAC_SHA256_Operation:
            op.initialize(key.key, ql)

        else:
            ql.log.error(f'TEE_SetOperationKey: unknown op type')
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(f'TEE_SetOperationKey: unknown op type {op}')
                return 
            ql.emu_stop()
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_AsymmetricDecrypt(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'params': POINTER, 'paramCount': UINT, 'srcData': POINTER, 'srcLen': UINT, "destData": POINTER, 'destLen': UINT})
    param_operation = params['operation']
    param_params = params['params']
    param_paramCount = params['paramCount']
    param_srcData = params['srcData']
    param_srcLen = params['srcLen']
    param_destData = params['destData']
    param_destLen = params['destLen']

    ql.log.info(f"TEE_AsymmetricDecrypt: ")

    if param_operation not in id2opration:
        ql.log.error(f"TEE_AsymmetricDecrypt: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()
    op = id2opration[param_operation]
    if not op.initialized or op.mode != TEE_MODE_DECRYPT:
        ql.log.error(f"TEE_AsymmetricDecrypt: op mode error or not initialized")
        ql.emu_stop()
    
    # @TODO: support params for TEE_ALG_RSAES_PKCS1_OAEP_MGF1_XXX
    if param_paramCount != 0:
        ql.log.error(f"TEE_AsymmetricDecrypt: only supported no params")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"TEE_AsymmetricDecrypt: only supported no params")
            return
        ql.emu_stop()

    try:
        ct = ql.mem.read(param_srcData, param_srcLen)
        pt = op.decrypt(ct, ql)
        if len(pt) == 0:
            ql.log.info("\tdecrypt error")
            ret = TEE_ERROR_CIPHERTEXT_INVALID
        else:
            ql.mem.write(param_destData, pt)
            ql.mem.write_ptr(param_destLen, len(pt))
            ret = TEE_SUCCESS
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr  
    

def TEE_CipherInit(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'IV': POINTER, 'IVLen': UINT})
    param_operation = params['operation']
    param_iv = params['IV']
    param_ivLen = params['IVLen']
    
    if param_operation not in id2opration:
        ql.log.error(f"TEE_CipherInit: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()

    op = id2opration[param_operation]

    try: 
        if type(op) == AES_ECB_NOPAD_Operation or type(op) == AES_CBC_NOPAD_Operation:
            if op.initialized and not op.active:
                op.activate(bytes(ql.mem.read(param_iv, param_ivLen)))
            else:
                ql.log.error(f"TEE_CipherInit: {type(op)} not initialized or already activated")
                ql.emu_stop()

            ql.log.info(f"TEE_CipherInit: {type(op)} op cypher init, iv: {op.iv}")

        elif type(op) == TEEGRIS_LOG_ENC_Operation:
            if op.initialized and not op.active:
                op.activate(bytes(ql.mem.read(param_iv, param_ivLen)))
            else:
                ql.log.error(f"TEE_CipherInit: {type(op)} not initialized or already activated")
                ql.emu_stop()
            ql.log.info(f"TEE_CipherInit: {type(op)} op cypher init, iv: {op.iv}")

        else:
            ql.log.error(f"TEE_CipherInit: unknown op type")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"TEE_CipherInit: unknown op type")
                return
            ql.emu_stop()
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr

 
    
def TEE_CipherDoFinal(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'srcData': POINTER, 'srcLen': UINT, 'dstData': POINTER, 'dstLen': POINTER})
    param_operation = params['operation']
    param_src = params['srcData']
    param_srcLen = params['srcLen']
    param_dst = params['dstData']
    param_dstLen = params['dstLen']
    
    if param_operation not in id2opration:
        ql.log.error(f"TEE_CipherDoFinal: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()

    op = id2opration[param_operation]

    ql.log.info(f"TEE_CipherDoFinal")

    try: 
        if type(op) == AES_ECB_NOPAD_Operation or type(op) == AES_CBC_NOPAD_Operation:
            if op.active:
                srcContent = bytes(ql.mem.read(param_src, param_srcLen))
                if op.mode == TEE_MODE_DECRYPT:
                    ql.log.info(f"\tct ({param_srcLen:#0x}): {srcContent}")
                elif op.mode == TEE_MODE_ENCRYPT:
                    ql.log.info(f"\tpt ({param_srcLen:#0x}): {srcContent}")
                dstContent = op.finalize(srcContent)
                ql.mem.write(param_dst, dstContent)
                ql.mem.write_ptr(param_dstLen, len(dstContent))
                if op.mode == TEE_MODE_DECRYPT:
                    ql.log.info(f"\tpt ({len(dstContent):#0x}): {dstContent}")
                elif op.mode == TEE_MODE_ENCRYPT:
                    ql.log.info(f"\tpt ({len(dstContent):#0x}): {dstContent}")
            else:
                ql.log.error(f"TEE_CipherDoFinal: {type(op)} not activated")
                ql.emu_stop()

        elif type(op) == TEEGRIS_LOG_ENC_Operation:
            if op.active:
                srcContent = bytes(ql.mem.read(param_src, param_srcLen)) 
                op.finalize(srcContent)
                dstContent = op.finalize(srcContent)
                ql.mem.write(param_dst, dstContent)
                ql.mem.write_ptr(param_dstLen, len(dstContent)) 
        else:
            ql.log.error(f"TEE_CipherDoFinal: unknown op type")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"TEE_CipherDoFinal: unknown op type")
                return
            ql.emu_stop()
    
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_MACInit(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'iv': POINTER, 'ivLen': POINTER})
    param_operation = params['operation']
    iv = params['iv']
    ivLen = params['ivLen']

    if param_operation not in id2opration:
        ql.log.error(f"TEE_CipherDoFinal: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()

    op = id2opration[param_operation]

    ql.log.info(f"TEE_MACInit")

    try:
        if type(op) == TEE_ALG_HMAC_SHA256_Operation:
            if op.initialized:
                op.activate()
            else:
               ql.log.error(f"TEE_CipherDoFinal: {type(op)} not activated")
               ql.emu_stop() 
        else:
            ql.log.error(f"TEE_CipherDoFinal: unknown op type")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"TEE_CipherDoFinal: unknown op type")
                return
            ql.emu_stop() 
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_MACComputeFinal(ql:Qiling, hook_data):
    global OPERATION_ID, id2opration
    params = ql.os.resolve_fcall_params({'operation': UINT, 'message': POINTER, 'messageLen': POINTER, 'mac': POINTER, 'macLen': POINTER})
    param_operation = params['operation']
    message = params['message']
    messageLen = params['messageLen']
    mac = params['mac']
    macLen = params['macLen']

    if param_operation not in id2opration:
        ql.log.error(f"TEE_CipherDoFinal: Operation {hex(param_operation)} not in {id2opration}")
        ql.emu_stop()

    op = id2opration[param_operation]

    ql.log.info(f"TEE_MACComputeFinal")

    try:
        if type(op) == TEE_ALG_HMAC_SHA256_Operation:
            if op.activated:
                result = op.compute(ql.mem.read(message, messageLen))
                ql.mem.write(mac, result)
                ql.mem.write(macLen, len(result).to_bytes(ql.arch.pointersize, "little"))
            else:
               ql.log.error(f"TEE_CipherDoFinal: {type(op)} not activated")
               ql.emu_stop() 
        else:
            ql.log.error(f"TEE_CipherDoFinal: unknown op type")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"TEE_CipherDoFinal: unknown op type")
                return
            ql.emu_stop() 
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

    