"""Marshalling for the OP-TEE syscall ABI structures.

`struct utee_params` and `struct utee_attribute` mirror optee_os
`lib/libutee/include/utee_types.h`. These are the structures exchanged between
the TA's libutee and the kernel across the `svc` boundary, so the emulator
(playing the kernel) reads/writes them here.
"""

from qiling import Qiling
from ..gp.utils.attribute import TEE_Ref_Attribute, TEE_Value_Attribute

TEE_NUM_PARAMS = 4

# struct utee_params { uint64_t types; uint64_t vals[TEE_NUM_PARAMS * 2]; }
UTEE_PARAMS_SIZE = 8 + 8 * 2 * TEE_NUM_PARAMS  # 72

# struct utee_attribute { uint64_t a; uint64_t b; uint32_t attribute_id; uint32_t pad; }
UTEE_ATTRIBUTE_SIZE = 24

# TEE_Param types (one nibble per param in `types`)
TEE_PARAM_TYPE_NONE = 0
TEE_PARAM_TYPE_VALUE_INPUT = 1
TEE_PARAM_TYPE_VALUE_OUTPUT = 2
TEE_PARAM_TYPE_VALUE_INOUT = 3
TEE_PARAM_TYPE_MEMREF_INPUT = 5
TEE_PARAM_TYPE_MEMREF_OUTPUT = 6
TEE_PARAM_TYPE_MEMREF_INOUT = 7

# bit 29 of an attribute id => value attribute (else memory reference)
TEE_ATTR_FLAG_VALUE = 1 << 29


def param_type(types: int, n: int) -> int:
    return (types >> (4 * n)) & 0xF


def is_value_type(t: int) -> bool:
    return 1 <= t <= 3


def is_memref_type(t: int) -> bool:
    return 5 <= t <= 7


def write_utee_params(ql: Qiling, ptr: int, types: int, vals):
    """vals: iterable of 2*TEE_NUM_PARAMS u64 values."""
    ql.mem.write(ptr, int(types).to_bytes(8, "little"))
    off = 8
    for v in vals:
        ql.mem.write(ptr + off, int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
        off += 8


def read_utee_params(ql: Qiling, ptr: int):
    """Returns (types, [vals...]) read back from a struct utee_params."""
    types = int.from_bytes(ql.mem.read(ptr, 8), "little")
    vals = []
    off = 8
    for _ in range(2 * TEE_NUM_PARAMS):
        vals.append(int.from_bytes(ql.mem.read(ptr + off, 8), "little"))
        off += 8
    return types, vals


def read_utee_attributes(ql: Qiling, ptr: int, count: int):
    """Translate a struct utee_attribute[count] into attribute objects that the
    existing gp/ object & key logic understands."""
    attrs = []
    cur = ptr
    for _ in range(count):
        a = int.from_bytes(ql.mem.read(cur, 8), "little")
        b = int.from_bytes(ql.mem.read(cur + 8, 8), "little")
        attribute_id = int.from_bytes(ql.mem.read(cur + 16, 4), "little")
        cur += UTEE_ATTRIBUTE_SIZE
        if attribute_id & TEE_ATTR_FLAG_VALUE:
            attrs.append(TEE_Value_Attribute(attribute_id, a & 0xFFFFFFFF,
                                             b & 0xFFFFFFFF, ql))
        else:
            attrs.append(TEE_Ref_Attribute(attribute_id, a, b, ql))
    return attrs
