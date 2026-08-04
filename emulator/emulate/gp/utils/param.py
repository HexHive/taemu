TEE_PARAM_TYPE_NONE = 0
TEE_PARAM_TYPE_VALUE_INPUT = 1
TEE_PARAM_TYPE_VALUE_OUTPUT = 2
TEE_PARAM_TYPE_VALUE_INOUT = 3
TEE_PARAM_TYPE_MEMREF_INPUT = 4
TEE_PARAM_TYPE_MEMREF_OUTPUT = 5
TEE_PARAM_TYPE_MEMREF_INOUT = 6

TEE_MEMORY_ACCESS_READ = 0x00000001
TEE_MEMORY_ACCESS_WRITE = 0x00000002
TEE_MEMORY_ACCESS_ANY_OWNER = 0x00000004


def TEE_PARAM_TYPE_GET(param_types: int, idx: int) -> int:
    return ((param_types) >> ((idx) * 4)) & 0xF


def TEE_PARAM_TYPES(t0: int, t1: int, t2: int, t3: int) -> int:
    return (t0) | ((t1) << 4) | ((t2) << 8) | ((t3) << 12)


class TEE_Param:
    def __init__(self) -> None:
        pass


class TEE_Param_Memref(TEE_Param):
    def __init__(self, data: bytes, length: int) -> None:
        super().__init__()
        self.data = data
        self.len = length
        self.ptr = None


class TEE_Param_value(TEE_Param):
    def __init__(self, a: int, b: int) -> None:
        super().__init__()
        self.a = a
        self.b = b
