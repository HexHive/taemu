from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA  # provided by pycryptodome
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Util.number import size
from Crypto.Util.number import bytes_to_long
from qiling import Qiling

#  6.10.1 List of Algorithm Identifiers
TEE_ALG_AES_ECB_NOPAD   =   0x10000010
TEE_ALG_AES_CBC_NOPAD   =   0x10000110
TEE_ALG_SHA256          =   0x50000004
TEE_ALG_RSAES_PKCS1_V1_5    =   0x60000130
TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 = 0x60410230
TEEGRIS_LOG_ENC = 0xf0100003



# 6.1.1 Possible TEE_OperationMode Values
TEE_MODE_ENCRYPT    = 0x00000000
TEE_MODE_DECRYPT    = 0x00000001
TEE_MODE_DIGEST     = 0x00000005 


class Operation():
    def __init__(self, operaitonID, ql) -> None:
        self.operationID = operaitonID
        self.ql = ql


class Digest_Operation(Operation):
    def __init__(self, operationID, ql) -> None:
        super().__init__(operationID, ql)
        self.h = SHA256.new()

    def digest_update(self, data):
        self.h.update(data)

    def finalize(self, data, hash_len, ql:Qiling):
        self.h.update(data)
        hash = self.h.digest()

        if len(hash) > hash_len:
            ql.log.info(f"\tfinalize: len of hash {hex(len(hash))}, len of res buffer {hex(hash_len)}")
            return None

        self.h = SHA256.new()
        return hash

class AES_ECB_NOPAD_Operation(Operation):
    def __init__(self, operationID, mode, ql) -> None:
        super().__init__(operationID, ql)
        self.initialized = False
        self.key = None
        self.cypher = None
        self.iv = None
        self.active = False
        self.mode = mode
    
    def initialize(self, key, ql):
        self.key = key
        self.initialized = True

    def activate(self, iv):
        self.iv = iv
        # no iv for ECB mode  
        self.cypher = AES.new(self.key, AES.MODE_ECB)
        self.active = True

    def finalize(self, src):
        if self.mode == TEE_MODE_DECRYPT:
            self.active = False
            l = len(src)
            if l % 0x10 == 0:
                pad_l = l
            else:
                pad_l = l - (l % 0x10) + 0x10
            pad_src = src.ljust(pad_l, b'\x00')
            return self.cypher.decrypt(pad_src)[:l]
        elif self.mode == TEE_MODE_ENCRYPT:
            self.active = False
            l = len(src)
            if l % 0x10 == 0:
                pad_l = l
            else:
                pad_l = l - (l % 0x10) + 0x10
            pad_src = src.ljust(pad_l, b'\x00')
            return self.cypher.encrypt(pad_src)[:l]
        else:
            self.ql.log.error(f"mode {self.mode} for AES_ECB_NOPAD_Operation not implemented")
            self.ql.emu_stop()


class AES_CBC_NOPAD_Operation(Operation):
    def __init__(self, operationID, mode, ql) -> None:
        super().__init__(operationID, ql)
        self.initialized = False
        self.key = None
        self.cypher = None
        self.iv = None
        self.active = False
        self.mode = mode
    
    def initialize(self, key, ql):
        self.key = key
        self.initialized = True

    def activate(self, iv):
        self.iv = iv
        self.cypher = AES.new(self.key, AES.MODE_CBC, iv = iv)
        self.active = True

    def finalize(self, src):
        if self.mode == TEE_MODE_DECRYPT:
            self.active = False
            l = len(src)
            if l % 0x10 == 0:
                pad_l = l
            else:
                pad_l = l - (l % 0x10) + 0x10
            pad_src = src.ljust(pad_l, b'\x00')
            return self.cypher.decrypt(pad_src)[:l]
        elif self.mode == TEE_MODE_ENCRYPT:
            self.active = False
            l = len(src)
            if l % 0x10 == 0:
                pad_l = l
            else:
                pad_l = l - (l % 0x10) + 0x10
            pad_src = src.ljust(pad_l, b'\x00')
            return self.cypher.encrypt(pad_src)[:l]
        else:
            self.ql.log.error(f"mode {self.mode} for AES_CBC_NOPAD_Operation not implemented")
            self.ql.emu_stop()
    
class RSAES_PKCS1_V1_5_Operation(Operation):
    def __init__(self, operationID, mode, keySize, ql) -> None:
        super().__init__(operationID, ql)
        self.keySize = keySize
        self.mode = mode
        self.key = None
        self.cypher = None
        self.initialized = False

    def initialize(self, params, ql):
        n = bytes_to_long(params['n'])
        d = bytes_to_long(params['d'])
        e = bytes_to_long(params['e'])
        self.key = RSA.construct((n, e, d))
        self.cypher = PKCS1_v1_5.new(self.key)
        self.initialized = True

    def decrypt(self, ct, ql:Qiling):
        ct = bytes(ct)
        ql.log.info(f"\tct: {ct}, len: {len(ct):#0x}")
        pt = self.cypher.decrypt(ct, None)
        ql.log.info(f"\tpt: {pt}, len: {len(pt):#0x}")
        return pt

class TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256_Operation(Operation):
    def __init__(self, operationID, mode, keySize, ql) -> None:
        super().__init__(operationID, ql)
        self.keySize = keySize
        self.mode = mode
        self.key = None
        self.cypher = None
        self.initialized = False 

    def initialize(self, params, ql):
        #TODO
        self.initialized = True

    def decrypt(self, ct, ql: Qiling):
        return b""

class TEEGRIS_LOG_ENC_Operation(Operation):
    def __init__(self, operationID, mode, ql) -> None:
        super().__init__(operationID, ql)
        self.mode = mode
        self.key = None
        self.cypher = None
        self.initialized = False 
        self.active = False

    def activate(self, iv):
        self.iv = iv
        self.active = True

    def finalize(self, src):
        return src

    def initialize(self, key, ql):
        self.initialized = True
        self.key = key
    

