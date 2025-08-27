from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.err import *

TEE_PROPSET_TEE_IMPLEMENTATION = 0xFFFFFFFD
TEE_PROPSET_CURRENT_TA = 0xFFFFFFFF

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

    if para_propsetOrEnumerator == TEE_PROPSET_TEE_IMPLEMENTATION:
        name = ql.mem.string(para_name)
        ql.log.info(f"{func_name}: property TEE_PROPSET_TEE_IMPLEMENTATION, {name}")
        if name != "gpd.tee.deviceID":
            ql.log.error(f"\tunknown name")
            ql.emu_stop()
         
        ql.mem.write(para_value, b'\xaa'*0x10)

    elif para_propsetOrEnumerator == TEE_PROPSET_CURRENT_TA:
        name = ql.mem.string(para_name)
        if name == "gpd.ta.appID":
            ql.mem.write(para_value, hook_data.emu.taUUID)
        else:
            ql.log.error(f'\tunknown property {name}')
            ql.emu_stop()

    else:
        ql.log.error(f"{func_name}: unknown property {para_propsetOrEnumerator}")
        ql.emu_stop()

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
