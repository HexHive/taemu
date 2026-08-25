from qiling import Qiling
from qiling.os.const import UINT, POINTER
from .utils.err import *
from ..common import crash, crash_notimpl
import unicorn

TEE_PROPSET_TEE_IMPLEMENTATION = 0xFFFFFFFD
TEE_PROPSET_CURRENT_TA = 0xFFFFFFFF

def TEE_GetPropertyAsU32(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    p = ql.os.resolve_fcall_params({"propset": UINT, "name": POINTER, "value": POINTER})
    try:
        name = ql.mem.string(p["name"]) if p["name"] else ""
    except unicorn.unicorn_py3.unicorn.UcError:
        name = ""
    # plausible values for the common u32 properties; 0 (and SUCCESS) otherwise
    # so a TA's create/open path proceeds rather than erroring on an unknown one.
    defaults = {
        "gpd.tee.arith.maxBigIntSize": 2048,
        "gpd.ta.dataSize": 0x100000,
        "gpd.ta.stackSize": 0x100000,
        "gpd.client.identity": 0,           # TEE_LOGIN_PUBLIC
        "gpd.tee.systemTime.protectionLevel": 100,
        "gpd.tee.TAPersistentTime.protectionLevel": 100,
    }
    val = defaults.get(name, 0)
    ql.log.info(f"{func_name}: {name!r} -> {val}")
    try:
        ql.mem.write(p["value"], int(val).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GetPropertyAsString(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    p = ql.os.resolve_fcall_params(
        {"propset": UINT, "name": POINTER, "buf": POINTER, "buflen": POINTER}
    )
    try:
        name = ql.mem.string(p["name"]) if p["name"] else ""
    except unicorn.unicorn_py3.unicorn.UcError:
        name = ""
    defaults = {
        "gpd.tee.description": "TA_GP_emulator",
        "gpd.ta.description": "emulated TA",
        "gpd.tee.deviceID": "00000000-0000-0000-0000-000000000000",
        # root-of-trust pubkey hash: a plausible non-empty 32-byte value so a
        # RoT-checking create path gets *something* rather than ITEM_NOT_FOUND
        "rot.pubk_hash": "\xaa" * 32,
    }
    val = (defaults.get(name, "")).encode("latin-1") + b"\x00"
    try:
        cap = ql.mem.read_ptr(p["buflen"]) if p["buflen"] else len(val)
        out = val[:cap] if cap else b""
        if p["buf"] and out:
            ql.mem.write(p["buf"], out)
        if p["buflen"]:
            ql.mem.write_ptr(p["buflen"], len(val))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, func_name)
        return
    ql.log.info(f"{func_name}: {name!r} -> {val!r}")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GetPropertyAsUUID(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params(
        {
            "propsetOrEnumerator": UINT,
            "name": POINTER,
            "value": POINTER,
        }
    )
    para_propsetOrEnumerator = params["propsetOrEnumerator"]
    para_name = params["name"]
    para_value = params["value"]
    hook_data.emu.update_shm(para_name)

    if para_propsetOrEnumerator == TEE_PROPSET_TEE_IMPLEMENTATION:
        name = ql.mem.string(para_name)
        ql.log.info(f"{func_name}: property TEE_PROPSET_TEE_IMPLEMENTATION, {name}")
        if name != "gpd.tee.deviceID":
            ql.log.error(f"\tunknown name")
            ql.emu_stop()

        try:
            ql.mem.write(para_value, b"\xaa" * 0x10)
        except unicorn.unicorn_py3.unicorn.UcError as e:
            crash(ql, func_name)
            return

    elif para_propsetOrEnumerator == TEE_PROPSET_CURRENT_TA:
        name = ql.mem.string(para_name)
        if name == "gpd.ta.appID":
            try:
                ql.mem.write(para_value, hook_data.emu.taUUID)
            except unicorn.unicorn_py3.unicorn.UcError:
                crash(ql, func_name)
                return
        else:
            ql.log.error(f"\tunknown property {name}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"unknown property {name}")
                return
            ql.emu_stop()

    else:
        ql.log.error(f"{func_name}: unknown property {para_propsetOrEnumerator}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"unknown property {para_propsetOrEnumerator}")
            return
        ql.emu_stop()

    hook_data.emu.writeback_shm(para_value)
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
