from .utils.crypto import *
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER, INT
from .utils.err import *
from .utils.object import *
from .utils.bigint import *


def TEE_BigIntInit(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'buf': POINTER, 'len': POINTER})
    buf = params['buf']
    length = params['len']
    ql.log.info(f"{func_name}: buf:{hex(buf)}, length:{hex(length)}")
    if buf in BIGINTS:
        ql.log.critical(f"double initialization of bigint! {hex(buf)}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return
    BIGINTS[buf] = BigInt(buf, length, ql)

    #ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntConvertFromOctetString(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'buffer': POINTER, 'bufferLen': POINTER, 'sign': INT})
    dest = params['dest']
    buffer = params['buffer']
    bufferLen = params['bufferLen']
    sign = params['sign']
    ql.log.info(f"{func_name}: {ql.mem.read(buffer, bufferLen)} => {hex(dest)}")
    if dest not in BIGINTS:
        ql.log.critical(f"bigint dest buffer not initialized! {hex(dest)}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return
    bigIntObj = BIGINTS[dest]
    hex_str = ql.mem.read(buffer, bufferLen).decode()
    if len(hex_str)/2 > bigIntObj.size*4:
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    try:
        nr = int.from_bytes(bytes.fromhex(hex_str), "big")
        if sign < 0:
            nr = -nr
        nr_bytes = nr.to_bytes(bigIntObj.size*4, "little", signed=True)
        ql.mem.write(dest, nr_bytes)
    except:
        ql.log.info(f"{func_name}: unable to convert hex string")

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

def TEE_BigIntConvertToOctetString(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({
        'buffer': POINTER,
        'bufferLen': POINTER,
        'bigInt': POINTER
    })

    buffer = params['buffer']
    bufferLen_ptr = params['bufferLen']
    bigInt_ptr = params['bigInt']

    if bigInt_ptr not in BIGINTS:
        ql.log.critical(f"{func_name}: bigint src not initialized! {hex(bigInt_ptr)}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return

    bigIntObj = BIGINTS[bigInt_ptr]

    # Read BigInt internal representation
    raw_bytes = ql.mem.read(bigInt_ptr, bigIntObj.size * 4)
    nr = int.from_bytes(raw_bytes, "little", signed=True)

    abs_nr = abs(nr)
    octets = abs_nr.to_bytes((abs_nr.bit_length() + 7) // 8, "big") or b"\x00"

    # Read current bufferLen
    buf_len = ql.mem.read_ptr(bufferLen_ptr)

    if buf_len < len(octets):
        # Update required size
        ql.mem.write_ptr(bufferLen_ptr, len(octets))
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_SHORT_BUFFER)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    # Write octets to buffer
    ql.mem.write(buffer, octets)

    # Update bufferLen with actual size
    ql.mem.write_ptr(bufferLen_ptr, len(octets))

    ql.log.info(f"{func_name}: {nr} => {octets.hex()} (len={len(octets)})")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntConvertFromS32(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'shortVal': INT})
    dest = params['dest']
    shortVal = params['shortVal']
    if dest not in BIGINTS:
        ql.log.critical(f"bigint dest buffer not initialized! {hex(dest)}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return 
    bigIntObj = BIGINTS[dest]
    shortVal_bytes = shortVal.to_bytes(bigIntObj.size*4, "little", signed=True)
    ql.mem.write(dest, shortVal_bytes)

    ql.os.fcall.cc.setReturnValue(dest)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

def TEE_BigIntAdd(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]

    # Ensure all operands are initialized
    dest_obj = _require_bigint(dest)
    if dest_obj is None:
        _panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    v1, obj1 = _read_bigint(ql, op1)
    if obj1 is None:
        return
    v2, obj2 = _read_bigint(ql, op2)
    if obj2 is None:
        return

    res = v1 + v2
    if not _write_bigint(ql, dest, res, dest_obj):
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntSub(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]

    dest_obj = _require_bigint(dest)
    if dest_obj is None:
        _panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    v1, obj1 = _read_bigint(ql, op1)
    if obj1 is None:
        return
    v2, obj2 = _read_bigint(ql, op2)
    if obj2 is None:
        return

    res = v1 - v2
    if not _write_bigint(ql, dest, res, dest_obj):
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntNeg(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op": POINTER})
    dest = params["dest"]
    op = params["op"]

    dest_obj = _require_bigint(dest)
    if dest_obj is None:
        _panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    v, obj = _read_bigint(ql, op)
    if obj is None:
        return

    res = -v
    if not _write_bigint(ql, dest, res, dest_obj):
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntMul(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]

    dest_obj = _require_bigint(dest)
    if dest_obj is None:
        _panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    v1, obj1 = _read_bigint(ql, op1)
    if obj1 is None:
        return
    v2, obj2 = _read_bigint(ql, op2)
    if obj2 is None:
        return

    res = v1 * v2
    if not _write_bigint(ql, dest, res, dest_obj):
        return

    ql.arch.regs.arch_pc = ql.arch.regs.lr




# ---- 8.7.1 TEE_BigIntCmp ----
def TEE_BigIntCmp(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'op1': POINTER, 'op2': POINTER})
    v1 = bigint_to_int(ql, params['op1'])
    v2 = bigint_to_int(ql, params['op2'])
    result = (v1 > v2) - (v1 < v2)  # -1, 0, +1
    ql.log.info(f"{func_name}: {v1} ? {v2} => {result}")
    ql.os.fcall.cc.setReturnValue(result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.2 TEE_BigIntCmpS32 ----
def TEE_BigIntCmpS32(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'op': POINTER, 'shortVal': INT})
    v1 = bigint_to_int(ql, params['op'])
    v2 = params['shortVal']
    result = (v1 > v2) - (v1 < v2)
    ql.log.info(f"{func_name}: {v1} ? {v2} => {result}")
    ql.os.fcall.cc.setReturnValue(result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.3 TEE_BigIntShiftRight ----
def TEE_BigIntShiftRight(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op': POINTER, 'bits': INT})
    val = bigint_to_int(ql, params['op'])
    result = val >> params['bits'] if val >= 0 else -((-val) >> params['bits'])
    ql.log.info(f"{func_name}: {val} >> {params['bits']} = {result}")
    int_to_bigint(ql, params['dest'], result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.4 TEE_BigIntGetBit ----
def TEE_BigIntGetBit(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'src': POINTER, 'bitIndex': INT})
    val = abs(bigint_to_int(ql, params['src']))
    bit = (val >> params['bitIndex']) & 1
    ql.log.info(f"{func_name}: bit[{params['bitIndex']}] of {val} = {bit}")
    ql.os.fcall.cc.setReturnValue(bool(bit))
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.5 TEE_BigIntGetBitCount ----
def TEE_BigIntGetBitCount(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'src': POINTER})
    val = abs(bigint_to_int(ql, params['src']))
    count = val.bit_length()
    ql.log.info(f"{func_name}: bitcount({val}) = {count}")
    ql.os.fcall.cc.setReturnValue(count)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.6 TEE_BigIntSetBit ----
def TEE_BigIntSetBit(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'op': POINTER, 'bitIndex': INT, 'value': INT})
    val = bigint_to_int(ql, params['op'])
    mask = 1 << params['bitIndex']
    new_val = (val | mask) if params['value'] else (val & ~mask)

    if not int_to_bigint(ql, params['op'], new_val):
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
    else:
        ql.log.info(f"{func_name}: set bit {params['bitIndex']} to {params['value']} => {new_val}")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)

    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.7 TEE_BigIntAssign ----
def TEE_BigIntAssign(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'src': POINTER})
    val = bigint_to_int(ql, params['src'])
    if not int_to_bigint(ql, params['dest'], val):
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
    else:
        ql.log.info(f"{func_name}: assign {val} -> {hex(params['dest'])}")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ---- 8.7.8 TEE_BigIntAbs ----
def TEE_BigIntAbs(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'src': POINTER})
    val = abs(bigint_to_int(ql, params['src']))
    if not int_to_bigint(ql, params['dest'], val):
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
    else:
        ql.log.info(f"{func_name}: abs({params['src']}) -> {val}")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
