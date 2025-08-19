from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from .utils.err import *

TEE_PROPSET_TEE_IMPLEMENTATION = 0xFFFFFFFD

def TEE_GetPropertyAsUUID(ql: Qiling, func_name):
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

    else:
        ql.log.error(f"{func_name}: unknown property {para_propsetOrEnumerator}")
        ql.emu_stop()

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
