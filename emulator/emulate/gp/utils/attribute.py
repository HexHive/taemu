from qiling import Qiling

ATTRIBUTE_MEM = 0x770000


class TEE_Attribute:
    def __init__(self, attributeID, ql: Qiling) -> None:
        self.attributeID = attributeID


class TEE_Ref_Attribute(TEE_Attribute):
    def __init__(self, attributeID, buffer, length, ql: Qiling) -> None:
        super().__init__(attributeID, ql)
        self.buffer = buffer
        self.length = length

    def __str__(self):
        return f"TEE_Ref_Attribute: attributeID: {self.attributeID:#0x}, buffer: {self.buffer:#0x}, len: {self.length:#0x}"


class TEE_Value_Attribute(TEE_Attribute):
    def __init__(self, attributeID, a, b, ql: Qiling) -> None:
        super().__init__(attributeID, ql)
        self.a = a
        self.b = b

    def __str__(self):
        return f"TEE_Value_Attribute: attributeID: {self.attributeID:#0x}, a: {self.a:#0x}, b: {self.b:#0x}"


ptr2bignum = {}
