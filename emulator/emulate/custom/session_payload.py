from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from ..gp.utils.param import TEE_Param_Memref
from ..gp.utils.err import *
from ..gp.utils.string import *
from Crypto.Random import get_random_bytes
from unicorn import UC_PROT_READ, UC_PROT_WRITE

def get_good_response_payload(ql: Qiling, lr, ta_name, session):
    #TODO: flawed logic do it target oriented (TODO)
    if ta_name == "3d08821c33a611e6a1fa089e01c83aa2.ta":
        ql.log.info(f"get good payload at: {lr:#0x}")
        if lr == 0xAAB4:
            # lr = 0xAAB4, bypass check at 0xAC68
            p1_data = p32(64) + b"A" * 64
            tee_params = [None, TEE_Param_Memref(p1_data, 0x44), None, None]
            return tee_params
        else:
            print(f"unknown lr: {lr:#0x}")
            return None
    elif ta_name == "14498ace2a8f11e880c8509a4c146f4c.ta":
        ql.log.info(f"get good payload at: {lr:#0x}")
        if lr == 0x10A14:
            # lr = 0xAAB4, bypass check at 0xAC68
            p1_data = p32(64) + b"A" * 64
            tee_params = [None, TEE_Param_Memref(p1_data, 0x44), None, None]
            return tee_params
        elif lr == 0x10634:
            p1_data = b"x" * 0x20
            tee_params = [None, TEE_Param_Memref(p1_data, 0x20), None, None]
            return tee_params
        elif lr == 0x10C38:
            p1_data = b"y" * 0x20  # forge hmac
            tee_params = [None, TEE_Param_Memref(p1_data, 0x20), None, None]
            return tee_params
        elif lr == 0x10EBC:
            p1_data = p32(64) + b"B" * 64  # forge sign
            tee_params = [None, TEE_Param_Memref(p1_data, 0x44), None, None]
            return tee_params
        else:
            print(f"unknown lr: {lr:#0x}")
            exit(-1)
    elif ta_name == "08010203000000000000000000000000.ta":
        ql.log.info(f"get good payload at: {lr:#0x}")
        if lr == 0xe19c:
            tee_params = [None, TEE_Param_Memref(b'\x01'*0x40, 0x40), None, None]
            return tee_params
        elif lr == 0xdf90:
            p1_data = p32(64) + b"B" * 64  # forge sign
            tee_params = [None, TEE_Param_Memref(p1_data, 0x44), None, None]
            return tee_params
        else:
            print(f"unknown lr: {lr:#0x}")
            return None
    else:

        print(f"unknown TA: {session.target_ta}")
        return None