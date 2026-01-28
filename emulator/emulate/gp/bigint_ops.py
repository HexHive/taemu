from .utils.crypto import *
from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER, INT
from .utils.err import *
from .utils.object import *
from .utils.bigint import *
from ..common import CRASH_PC, crash
import unicorn


def TEE_BigIntInit(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'buf': POINTER, 'len': POINTER})
    buf = params['buf']
    length = params['len']
    ql.log.info(f"{func_name}: buf:{hex(buf)}, length:{hex(length)}")
    if buf in BIGINTS:
        ql.log.critical(f"double initialization of bigint! {hex(buf)}")
        crash(ql, hook_data.func_name)
        return
    BIGINTS[buf] = BigInt(buf, length, ql)

    #ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntConvertFromOctetString(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'buffer': POINTER, 'bufferLen': POINTER, 'sign': INT})
    dest = params['dest']
    buffer = params['buffer']
    bufferLen = params['bufferLen']
    sign = params['sign']
    ql.log.info(f"{func_name}: {ql.mem.read(buffer, bufferLen)} => {hex(dest)}")
    if dest not in BIGINTS:
        ql.log.critical(f"bigint dest buffer not initialized! {hex(dest)}")
        crash(ql, hook_data.func_name)
        return
    try:
        bigIntObj = BIGINTS[dest]
        hex_str = ql.mem.read(buffer, bufferLen).decode()
        if len(hex_str)/2 > bigIntObj.size*4:
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            nr = int.from_bytes(bytes.fromhex(hex_str), "big")
            if sign < 0:
                nr = -nr
        try:
            nr_bytes = nr.to_bytes(bigIntObj.size*4, "little", signed=True)
        except:
            ql.log.info(f"{func_name}: unable to convert hex string")
        ql.mem.write(dest, nr_bytes)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return 
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

def TEE_BigIntConvertToOctetString(ql: Qiling, hook_data):
    func_name = hook_data.func_name
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
        crash(ql, hook_data.func_name)
        return

    bigIntObj = BIGINTS[bigInt_ptr]

    try:
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
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return 
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntConvertFromS32(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'shortVal': INT})
    dest = params['dest']
    shortVal = params['shortVal']
    if dest not in BIGINTS:
        ql.log.critical(f"bigint dest buffer not initialized! {hex(dest)}")
        crash(ql, hook_data.func_name)
        return 
    bigIntObj = BIGINTS[dest]
    shortVal_bytes = shortVal.to_bytes(bigIntObj.size*4, "little", signed=True)
    
    try:
        ql.mem.write(dest, shortVal_bytes)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return 
    ql.os.fcall.cc.setReturnValue(dest)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

def TEE_BigIntAdd(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]

    # Ensure all operands are initialized
    dest_obj = require_bigint(dest)
    if dest_obj is None:
        ql.log.critical(f"bigint dest buffer not initialized! {hex(dest)}")
        crash(ql, hook_data.func_name)
        return

    try:
        v1, obj1 = read_bigint(ql, op1)
        if obj1 is None:
            return
        v2, obj2 = read_bigint(ql, op2)
        if obj2 is None:
            return

        res = v1 + v2
        if not write_bigint(ql, dest, res, dest_obj):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntSub(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]

    dest_obj = require_bigint(dest)
    if dest_obj is None:
        panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    try:
        v1, obj1 = read_bigint(ql, op1)
        if obj1 is None:
            return
        v2, obj2 = read_bigint(ql, op2)
        if obj2 is None:
            return

        res = v1 - v2
        if not write_bigint(ql, dest, res, dest_obj):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntNeg(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op": POINTER})
    dest = params["dest"]
    op = params["op"]

    dest_obj = require_bigint(dest)
    if dest_obj is None:
        panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return

    try:
        v, obj = read_bigint(ql, op)
        if obj is None:
            return

        res = -v
        if not write_bigint(ql, dest, res, dest_obj):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntMul(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op1": POINTER, "op2": POINTER})
    dest = params["dest"]
    op1 = params["op1"]
    op2 = params["op2"]
    dest_obj = require_bigint(dest)
    if dest_obj is None:
        panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
        return
    
    try:
        v1, obj1 = read_bigint(ql, op1)
        if obj1 is None:
            return
        v2, obj2 = read_bigint(ql, op2)
        if obj2 is None:
            return

        res = v1 * v2
        if not write_bigint(ql, dest, res, dest_obj):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntCmp(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'op1': POINTER, 'op2': POINTER})
    try:
        v1 = bigint_to_int(ql, params['op1'])
        v2 = bigint_to_int(ql, params['op2'])
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    result = (v1 > v2) - (v1 < v2)  # -1, 0, +1
    ql.log.info(f"{func_name}: {v1} ? {v2} => {result}")
    ql.os.fcall.cc.setReturnValue(result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntCmpS32(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'op': POINTER, 'shortVal': INT})
    try:
        v1 = bigint_to_int(ql, params['op'])
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    v2 = params['shortVal']
    result = (v1 > v2) - (v1 < v2)
    ql.log.info(f"{func_name}: {v1} ? {v2} => {result}")
    ql.os.fcall.cc.setReturnValue(result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntShiftRight(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op': POINTER, 'bits': INT})
    try:
        val = bigint_to_int(ql, params['op'])
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    result = val >> params['bits'] if val >= 0 else -((-val) >> params['bits'])
    ql.log.info(f"{func_name}: {val} >> {params['bits']} = {result}")
    int_to_bigint(ql, params['dest'], result)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntGetBit(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'src': POINTER, 'bitIndex': INT})
    try:
        val = abs(bigint_to_int(ql, params['src']))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    bit = (val >> params['bitIndex']) & 1
    ql.log.info(f"{func_name}: bit[{params['bitIndex']}] of {val} = {bit}")
    ql.os.fcall.cc.setReturnValue(bool(bit))
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntGetBitCount(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'src': POINTER})
    try:
        val = abs(bigint_to_int(ql, params['src']))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    count = val.bit_length()
    ql.log.info(f"{func_name}: bitcount({val}) = {count}")
    ql.os.fcall.cc.setReturnValue(count)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntSetBit(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'op': POINTER, 'bitIndex': INT, 'value': INT})
    try:
        val = bigint_to_int(ql, params['op'])
        mask = 1 << params['bitIndex']
        new_val = (val | mask) if params['value'] else (val & ~mask)

        if not int_to_bigint(ql, params['op'], new_val):
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
        else:
            ql.log.info(f"{func_name}: set bit {params['bitIndex']} to {params['value']} => {new_val}")
            ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntAssign(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'src': POINTER})
    try:
        val = bigint_to_int(ql, params['src'])
        if not int_to_bigint(ql, params['dest'], val):
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
        else:
            ql.log.info(f"{func_name}: assign {val} -> {hex(params['dest'])}")
            ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return 
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntAbs(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'src': POINTER})
    try:
        val = abs(bigint_to_int(ql, params['src']))
        if not int_to_bigint(ql, params['dest'], val):
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_OVERFLOW)
        else:
            ql.log.info(f"{func_name}: abs({params['src']}) -> {val}")
            ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntSquare(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "op": POINTER})
    dest = params["dest"]
    op   = params["op"]

    try:
        dest_obj = require_bigint(dest)
        if dest_obj is None:
            panic(ql, f"bigint dest buffer not initialized! {hex(dest)}")
            return

        v, obj = read_bigint(ql, op)
        if obj is None:  
            return

        ql.log.info(f"{func_name}: {v}**2")
        # Square (always non-negative)
        res = v * v

        # Write back (write_bigint should check capacity/overflow and panic if needed)
        if not write_bigint(ql, dest, res, dest_obj):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntDiv(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({
        "dest_q": POINTER,
        "dest_r": POINTER,
        "op1": POINTER,
        "op2": POINTER
    })
    dest_q = params["dest_q"]
    dest_r = params["dest_r"]
    op1    = params["op1"]
    op2    = params["op2"]

    try:
        # Read operands
        v1, obj1 = read_bigint(ql, op1)
        if obj1 is None:
            return
        v2, obj2 = read_bigint(ql, op2)
        if obj2 is None:
            return

        # Division by zero -> programming error -> panic
        if v2 == 0:
            panic(ql, f"{func_name}: division by zero")
            return
        
        ql.log.info(f"{func_name}: {v1} / {v2}")

        # Quotient rounded towards zero; Python // floors, so use trunc on true division
        # int(a / b) truncates toward zero for ints in Python
        q = int(v1 / v2)
        r = v1 - q * v2
        # r now has same sign as v1 (or zero) with truncation toward zero

        # Defer all memory writes until after we've computed both q and r
        # so dest_q/dest_r can alias op1/op2 safely (spec only forbids q<->r overlap)

        # Write quotient if requested
        if dest_q:
            dest_q_obj = require_bigint(dest_q)
            if dest_q_obj is None:
                panic(ql, f"bigint dest_q buffer not initialized! {hex(dest_q)}")
                return
            if not write_bigint(ql, dest_q, q, dest_q_obj):
                return

        # Write remainder if requested
        if dest_r:
            dest_r_obj = require_bigint(dest_r)
            if dest_r_obj is None:
                panic(ql, f"bigint dest_r buffer not initialized! {hex(dest_r)}")
                return
            if not write_bigint(ql, dest_r, r, dest_r_obj):
                return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_BigIntMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op': POINTER, 'n': POINTER})
    dest, op, n = params['dest'], params['op'], params['n']

    if not all(p in BIGINTS for p in (dest, op, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:
        op_val, _ = read_bigint(ql, op) 
        n_val, _ = read_bigint(ql, n)
        if op_val is None or n_val is None:
            return
        
        ql.log.info(f"{func_name}: {op_val} % {n_val}")

        result = op_val % n_val
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return 
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntAddMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op1': POINTER, 'op2': POINTER, 'n': POINTER})
    dest, op1, op2, n = params['dest'], params['op1'], params['op2'], params['n']

    if not all(p in BIGINTS for p in (dest, op1, op2, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:
        n_val, _ = read_bigint(ql, n) 
        op1_val, _ = read_bigint(op1, n) 
        op2_val, _ = read_bigint(op2, n) 
        if n_val is None or op1_val is None or op2_val is None:
            return 
        
        ql.log.info(f"{func_name}: {op1_val}+{op2_val} % {n_val}")

        result = (op1_val + op2_val) % n_val
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return 
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntSubMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op1': POINTER, 'op2': POINTER, 'n': POINTER})
    dest, op1, op2, n = params['dest'], params['op1'], params['op2'], params['n']

    if not all(p in BIGINTS for p in (dest, op1, op2, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:
        n_val, _ = read_bigint(ql, n)
        op1_val, _ = read_bigint(op1, n) 
        op2_val, _ = read_bigint(op2, n)
        if n_val is None or op1_val is None or op2_val is None:
            return 
        
        ql.log.info(f"{func_name}: {op1_val}-{op2_val} % {n_val}")

        result = (op1_val - op2_val) % n_val
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntMulMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op1': POINTER, 'op2': POINTER, 'n': POINTER})
    dest, op1, op2, n = params['dest'], params['op1'], params['op2'], params['n']

    if not all(p in BIGINTS for p in (dest, op1, op2, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:
        n_val, _ = read_bigint(ql, n)
        op1_val, _ = read_bigint(op1, n) 
        op2_val, _ = read_bigint(op2, n)
        if n_val is None or op1_val is None or op2_val is None:
            return 
        
        ql.log.info(f"{func_name}: {op1_val}*{op2_val} % {n_val}")

        result = (op1_val * op2_val) % n_val
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntSquareMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op': POINTER, 'n': POINTER})
    dest, op, n = params['dest'], params['op'], params['n']

    if not all(p in BIGINTS for p in (dest, op, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:
        n_val, _ = read_bigint(ql, n)
        op_val, _ = read_bigint(op, n) 
        if n_val is None or op_val is None:
            return 
        
        ql.log.info(f"{func_name}: {op_val}**2 % {n_val}")

        result = (op_val ** 2) % n_val
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntInvMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op': POINTER, 'n': POINTER})
    dest, op, n = params['dest'], params['op'], params['n']

    if not all(p in BIGINTS for p in (dest, op, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return
    
    try:
        op_val, _ = read_bigint(ql, op)
        n_val, _ = read_bigint(ql, n) 
        if op_val is None or n_val is None:
            return

        ql.log.info(f"{func_name}: pow({op_val}, -1, {n_val})")

        try:
            result = pow(op_val, -1, n_val)  # Python 3.8+ supports modular inverse
        except ValueError:
            ql.log.warning(f"{func_name}: inverse does not exist (gcd != 1)")

        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_BigIntExpMod(ql, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({'dest': POINTER, 'op1': POINTER, 'op2': POINTER, 'n': POINTER, 'context': POINTER})
    dest, op1, op2, n = params['dest'], params['op1'], params['op2'], params['n']

    if not all(p in BIGINTS for p in (dest, op1, op2, n)):
        ql.log.critical(f"{func_name}: one or more bigint not initialized!")
        crash(ql, hook_data.func_name)
        return

    try:    
        n_val, _ = read_bigint(ql, n)
        op1_val, _ = read_bigint(op1, n) 
        op2_val, _ = read_bigint(op2, n)
        if n_val is None or op1_val is None or op2_val is None:
            return 
        
        ql.log.info(f"{func_name}: pow({op1_val}, {op2_val}, {n_val})")

        result = pow(op1_val, op2_val, n_val)
        if not write_bigint(ql, dest, result, BIGINTS[dest]):
            return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr