from enum import Enum
import os
from qiling import Qiling
from Crypto.PublicKey import RSA  # provided by pycryptodome
from Crypto.Util.number import size
from .err import *
from .attribute import *

OBJECT_MEM = 0x690000


class ObjectTypes(Enum):
    TEE_TYPE_RSA_KEYPAIR = 0xA1000030
    TEE_TYPE_DATA = 0xA00000BF
    TEE_TYPE_AES = 0xA0000010
    TEE_TYPE_HMAC_SHA256 = 0xA0000004


handle2obj = {}
filepaths2tranobjs = {}


class Object:
    # @TODO: meaning of size, does it both include key size and attr size??
    def __init__(self, size, ql: Qiling) -> None:
        global OBJECT_MEM
        self.handle = ql.mem.map_anywhere(
            size, minaddr=OBJECT_MEM, perms=0, info="TransientObject"
        )
        OBJECT_MEM += size - (size % 0x1000) + 0x1000
        self.maxSize = size
        self.initialized = False
        self.persistent = (
            False  # track if this object is connected to a persistent object
        )
        self.attrs = {}

    def parse_params(self, params, paramCount, ql: Qiling):
        res = []
        current_param = params
        for _ in range(paramCount):
            attributeID = ql.mem.read_ptr(current_param, 4)
            current_param += 4
            if (attributeID >> 29) & 0x1 == 0:  # ref
                buffer = ql.mem.read_ptr(current_param)
                current_param += ql.arch.pointersize
                length = ql.mem.read_ptr(current_param)
                current_param += ql.arch.pointersize
                attr = TEE_Ref_Attribute(attributeID, buffer, length, ql)
            else:  # value
                a = ql.mem.read_ptr(current_param, 4)
                current_param += 4
                b = ql.mem.read_ptr(current_param, 4)
                current_param += 4
                if ql.arch.pointersize == 8:
                    # not sure about this
                    current_param += 8
                attr = TEE_Value_Attribute(attributeID, a, b)
            res.append(attr)
            current_param += 4  # alignment
        return res


class AES_Obj(Object):

    def __init__(self, size, ql: Qiling) -> None:
        super().__init__(size, ql)
        self.obj_type = ObjectTypes.TEE_TYPE_AES
        self.key = None

    def populate(self, attrs, attrsCount, ql: Qiling) -> int:
        # The values of all attributes are copied into the object so that the attrs array and all the memory buffers it points to may be freed after this routine returns without affecting the object. Page 136. 2553

        if attrsCount * 12 > self.maxSize:
            ql.log.error(
                f"populate: attributes array too large: {hex(attrsCount * 0xc)} > {self.maxSize}"
            )
            ql.emu_stop()

        parsed_attrs = self.parse_params(attrs, attrsCount, ql)

        if len(parsed_attrs) != 1 or type(parsed_attrs[0]) != TEE_Ref_Attribute:
            ql.log.error(f"populate: attrs error in AES_Obj")
            ql.emu_stop()

        self.key = bytes(ql.mem.read(parsed_attrs[0].buffer, parsed_attrs[0].length))
        # ret = self.retrieve_rsa_params(parsed_attrs, ql)

        # if ret != TEE_SUCCESS:
        #     return ret

        self.initialized = True
        return TEE_SUCCESS


class SHA256HMAC_Obj(Object):

    class __AttributeTypes__(Enum):
        TEE_ATTR_SECRET_VALUE = 0xC0000000

    def __init__(self, size, ql):
        super().__init__(size, ql)
        self.obj_type = ObjectTypes.TEE_TYPE_HMAC_SHA256
        self.key = None

    def populate(self, attrs, attrsCount, ql: Qiling) -> int:
        # The values of all attributes are copied into the object so that the attrs array and all the memory buffers it points to may be freed after this routine returns without affecting the object. Page 136. 2553

        if attrsCount * 12 > self.maxSize:
            ql.log.error(
                f"populate: attributes array too large: {hex(attrsCount * 0xc)} > {self.maxSize}"
            )
            ql.emu_stop()

        parsed_attrs = self.parse_params(attrs, attrsCount, ql)

        if len(parsed_attrs) != 1 or type(parsed_attrs[0]) != TEE_Ref_Attribute:
            ql.log.error(f"populate: attrs error in AES_Obj")
            ql.emu_stop()

        self.key = bytes(ql.mem.read(parsed_attrs[0].buffer, parsed_attrs[0].length))
        # ret = self.retrieve_rsa_params(parsed_attrs, ql)

        # if ret != TEE_SUCCESS:
        #     return ret

        self.initialized = True
        return TEE_SUCCESS

    def generateKey(self, keySize, params, paramCount, ql: Qiling) -> int:
        key_buffer = ql.mem.map_anywhere(
            0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
        )
        key = 32 * b"A"  # TEE_TYPE_HMAC_SHA256 allows keys up to 512 bits, but 256 bits is common

        ql.mem.write(key_buffer, key)
        self.attrs[self.__AttributeTypes__.TEE_ATTR_SECRET_VALUE.value] = (
            key_buffer,
            32,
        )
        self.key = key

        return TEE_SUCCESS


class RSA_KEYPAIR_Obj(Object):

    class __AttributeTypes__(Enum):
        ###  attrs for object type TEE_TYPE_RSA_KEYPAIR
        TEE_ATTR_RSA_MODULUS = 0xD0000130
        TEE_ATTR_RSA_PUBLIC_EXPONENT = 0xD0000230
        TEE_ATTR_RSA_PRIVATE_EXPONENT = 0xC0000330

        TEE_ATTR_RSA_PRIME1 = 0xC0000430  # p
        TEE_ATTR_RSA_PRIME2 = 0xC0000530  # q
        TEE_ATTR_RSA_EXPONENT1 = 0xC0000630  # dp
        TEE_ATTR_RSA_EXPONENT2 = 0xC0000730  # dq
        TEE_ATTR_RSA_COEFFICIENT = 0xC0000830  # iq

    def __init__(self, size, ql: Qiling) -> None:
        super().__init__(size, ql)
        self.obj_type = ObjectTypes.TEE_TYPE_RSA_KEYPAIR
        self.supported_keySize = [256, 512, 768, 1024, 1536, 2048]
        self.rsa_param = {}
        self.rsa_optional_param = {}
        self.key = None

    def retrieve_rsa_params(self, parsed_attrs, ql) -> int:
        for attr in parsed_attrs:
            if type(attr) == TEE_Value_Attribute:
                ql.log.info(f"\tTEE_Value_Attribute not supoorted for RSA_KEYPAIR_Obj")
                return TEE_ERROR_BAD_PARAMETERS
            else:

                if (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_MODULUS.value
                ):
                    self.rsa_param["n"] = ql.mem.read(attr.buffer, attr.length)
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_PUBLIC_EXPONENT.value
                ):
                    self.rsa_param["e"] = ql.mem.read(attr.buffer, attr.length)
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_PRIVATE_EXPONENT.value
                ):
                    self.rsa_param["d"] = ql.mem.read(attr.buffer, attr.length)
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_PRIME1.value
                ):
                    self.rsa_optional_param["p"] = ql.mem.read(attr.buffer, attr.length)
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_PRIME2.value
                ):
                    self.rsa_optional_param["q"] = ql.mem.read(attr.buffer, attr.length)
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_EXPONENT1.value
                ):
                    self.rsa_optional_param["dp"] = ql.mem.read(
                        attr.buffer, attr.length
                    )
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_EXPONENT2.value
                ):
                    self.rsa_optional_param["dq"] = ql.mem.read(
                        attr.buffer, attr.length
                    )
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                elif (
                    attr.attributeID
                    == self.__AttributeTypes__.TEE_ATTR_RSA_COEFFICIENT.value
                ):
                    self.rsa_optional_param["iq"] = ql.mem.read(
                        attr.buffer, attr.length
                    )
                    self.attrs[attr.attributeID] = (attr.buffer, attr.length)
                else:
                    ql.log.info(
                        f"\tretrieve_rsa_params: attr {hex(attr.attributeID)} not supoorted"
                    )
                    return TEE_ERROR_BAD_PARAMETERS

        # if any of these are provided, all of these should be provided
        if bool(self.rsa_optional_param):
            if any(
                [p not in self.rsa_optional_param for p in ["p", "q", "dp", "dq", "iq"]]
            ):
                ql.log.info(
                    f"\tretrieve_rsa_params: p, q, dp, dq, iq should all be provided if one is provided."
                )
                return TEE_ERROR_BAD_PARAMETERS

        return TEE_SUCCESS

    def generateKey(self, keySize, params, paramCount, ql: Qiling) -> int:
        ql.log.info(f"\tRSA_KEYPAIR_Obj: generateKey {keySize} {params} {paramCount}")

        parsed_attrs = self.parse_params(params, paramCount, ql)
        if keySize in self.supported_keySize:
            # @TODO: generate key according to parsed_attrs
            self.keySize = keySize
            ret = self.retrieve_rsa_params(parsed_attrs, ql)
            if ret != TEE_SUCCESS:
                return ret

            if not self.rsa_param:
                ql.log.info(
                    f"\tgenerateKey: params not specified, using default (e=65537)"
                )
                n_buffer = ql.mem.map_anywhere(
                    0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
                )
                d_buffer = ql.mem.map_anywhere(
                    0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
                )
                e_buffer = ql.mem.map_anywhere(
                    0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
                )
                p_buffer = ql.mem.map_anywhere(
                    0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
                )
                q_buffer = ql.mem.map_anywhere(
                    0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="TEE_Ref_Attribute"
                )
                self.key = RSA.generate(keySize, e=65537)
                n_size = d_size = self.keySize // 8
                e_size = 3
                p_size = size(self.key.p) // 8
                q_size = size(self.key.q) // 8
                ql.mem.write(n_buffer, self.key.n.to_bytes(n_size, "big"))
                ql.mem.write(d_buffer, self.key.d.to_bytes(d_size, "big"))
                ql.mem.write(e_buffer, self.key.e.to_bytes(e_size, "big"))
                ql.mem.write(p_buffer, self.key.p.to_bytes(p_size, "big"))
                ql.mem.write(q_buffer, self.key.q.to_bytes(q_size, "big"))

                self.rsa_param["n"] = self.key.n
                self.attrs[self.__AttributeTypes__.TEE_ATTR_RSA_MODULUS.value] = (
                    n_buffer,
                    n_size,
                )

                self.rsa_param["e"] = self.key.e
                self.attrs[
                    self.__AttributeTypes__.TEE_ATTR_RSA_PUBLIC_EXPONENT.value
                ] = (e_buffer, e_size)

                self.rsa_param["d"] = self.key.d
                self.attrs[
                    self.__AttributeTypes__.TEE_ATTR_RSA_PRIVATE_EXPONENT.value
                ] = (d_buffer, d_size)

                self.rsa_param["p"] = self.key.p
                self.attrs[self.__AttributeTypes__.TEE_ATTR_RSA_PRIME1.value] = (
                    p_buffer,
                    p_size,
                )

                self.rsa_param["q"] = self.key.q
                self.attrs[self.__AttributeTypes__.TEE_ATTR_RSA_PRIME2.value] = (
                    q_buffer,
                    q_size,
                )

                # @TODO: init iq, dp etc.

            else:
                rsa_tuple = (
                    self.rsa_param["n"],
                    self.rsa_param["e"],
                    self.rsa_param["d"],
                )
                if bool(self.rsa_optional_param):
                    rsa_tuple += (
                        self.rsa_param["p"],
                        self.rsa_param["q"],
                        self.rsa_param["dp"],
                        self.rsa_param["dq"],
                        self.rsa_param["iq"],
                    )
                ql.log.info(f"\tgenerateKey: rsa params {rsa_tuple}")
                try:
                    self.key = RSA.construct(rsa_tuple, consistency_check=True)
                except ValueError:
                    ql.log.info(f"\tgenerateKey: rsa params not valid")
                    return TEE_ERROR_BAD_PARAMETERS

            self.initialized = True
            ql.log.debug(f"\tparsed_attrs: {parsed_attrs}")
            return TEE_SUCCESS
        else:
            return TEE_ERROR_BAD_PARAMETERS

    def populate(self, attrs, attrsCount, ql: Qiling) -> int:
        # The values of all attributes are copied into the object so that the attrs array and all the memory buffers it points to may be freed after this routine returns without affecting the object. Page 136. 2553

        if attrsCount * 12 > self.maxSize:
            ql.log.error(
                f"populate: attributes array too large: {hex(attrsCount * 0xc)} > {self.maxSize}"
            )
            ql.emu_stop()

        parsed_attrs = self.parse_params(attrs, attrsCount, ql)
        ret = self.retrieve_rsa_params(parsed_attrs, ql)
        if ret != TEE_SUCCESS:
            return ret

        self.initialized = True
        return TEE_SUCCESS

    def copy_from(self, src, ql) -> int:
        if type(src) != type(self):
            ql.log.error(
                f"copy_from: cannot copy from type {hex(src.obj_type)} to type {hex(self.obj_type)}"
            )
            ql.emu_stop()

        if src.initialized == False or self.initialized == True:
            ql.log.error(
                f"copy_from: can only copy from an initialized obj from an unintialized obj"
            )
            ql.emu_stop()

        self.attrs = src.attrs.copy()
        self.rsa_param = src.rsa_param.copy()
        self.rsa_optional_param = src.rsa_optional_param.copy()
        self.initialized = True

        return TEE_SUCCESS
