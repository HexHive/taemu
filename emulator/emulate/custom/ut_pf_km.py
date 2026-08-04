"""
ut pf keymaster
"""

from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from pwn import *

# from emulator_no_loader import TA_ELF
from ..gp.session import *


### ut_pf_km_get_hmac_key
# libuTkeymaster.so

### ut_pf_log_msg
# libuTlog.so

# for global and local varaibles
EMULATED_LIB_BSS_MEM = 0x850000




    # temp_mem = ql.mem.map_anywhere(
    #     0x1000, minaddr=EMULATED_LIB_BSS_MEM, perms=3, info="emulated_libc_bss"
    # )

    # v9_addr = temp_mem
    # unk_9188 = v9_addr + 4 * 8
    # v8_addr = unk_9188 + 0x20
    # # 497 typedef struct
    # # 498 {
    # # 499 uint32_t timeLow;
    # # 500 uint16_t timeMid;
    # # 501 uint16_t timeHiAndVersion;
    # # 502 uint8_t clockSeqAndNode[8];
    # # 503 } TEE_UUID;
    # ql.mem.write(unk_9188, p32(0xC09C9C5D))
    # ql.mem.write(unk_9188 + 4, p16(0xAA50))
    # ql.mem.write(unk_9188 + 6, p16(0x4B78))
    # ql.mem.write(unk_9188 + 8, p32(0xDA6EE4B0))
    # ql.mem.write(unk_9188 + 12, p32(0x3A6C5561))

    # v2 = a2 == 0
    # if a2:
    #     v2 = a1 == 0
    # v3 = v2
    # if v2:
    #     ut_pf_log_msg_fake(
    #         ql,
    #         5,
    #         "[%s:%d/%s]<err>%sbad params\n"
    #         % ("ut_pf_km.cc", 30, "ut_pf_km_get_hmac_key", ""),
    #     )
    #     ql.mem.unmap(temp_mem, 0x1000)
    #     ql.os.fcall.cc.setReturnValue(-1)
    #     ql.arch.regs.arch_sp += 0x38
    #     ql.arch.regs.arch_pc = current_lr
    # else:
    #     ql.mem.write_ptr(a2, 32)
    #     ql.mem.write_ptr(v9_addr, v3)
    #     ql.mem.write_ptr(v9_addr + 4, v3)
    #     ql.mem.write_ptr(v9_addr + 8, a1)
    #     v10 = 32
    #     ql.mem.write_ptr(v9_addr + 12, v10)  # v10
    #     ql.mem.write_ptr(v9_addr + 16, v3)  # v11
    #     ql.mem.write_ptr(v9_addr + 20, v3)
    #     ql.mem.write_ptr(v9_addr + 24, v3)
    #     ql.mem.write_ptr(v9_addr + 28, v3)  # v14

    #     # call TEE_OpenTASession(&unk_9188, v3, 98, v9, &v8, v3)
    #     ql.arch.regs.r0 = unk_9188
    #     ql.arch.regs.r1 = v3
    #     ql.arch.regs.r2 = 98
    #     ql.arch.regs.r3 = v9_addr
    #     ql.mem.write(ql.arch.regs.arch_sp, p32(v8_addr))
    #     ql.mem.write(ql.arch.regs.arch_sp + 4, p32(v3))

    #     TEE_OpenTASession(ql, "TEE_OpenTASession", True)
    #     v5 = ql.arch.regs.r0

    #     if v5:
    #         ut_pf_log_msg_fake(
    #             ql,
    #             5,
    #             "[%s:%d/%s]<err>%sopenssion failed, %d\n"
    #             % ("ut_pf_km.cc", 51, "ut_pf_km_get_hmac_key", "", v5),
    #         )
    #         ql.mem.unmap(temp_mem, 0x1000)
    #         ql.os.fcall.cc.setReturnValue(v5)
    #         ql.arch.regs.arch_sp += 0x38
    #         ql.arch.regs.arch_pc = current_lr
    #     else:
    #         # call TEE_InvokeTACommand(v8, 0, 1001, 98, v9, 0);
    #         v8 = ql.mem.read_ptr(v8_addr, 4)
    #         ql.arch.regs.r0 = v8
    #         ql.arch.regs.r1 = 0
    #         ql.arch.regs.r2 = 1001
    #         ql.arch.regs.r3 = 98
    #         ql.mem.write(ql.arch.regs.arch_sp, p32(v9_addr))
    #         ql.mem.write(ql.arch.regs.arch_sp + 4, p32(0))
    #         TEE_InvokeTACommand(ql, "TEE_InvokeTACommand", True)
    #         v6 = ql.arch.regs.r0

    #         if v6:
    #             ut_pf_log_msg_fake(
    #                 ql,
    #                 5,
    #                 "[%s:%d/%s]<err>%sinvoke cmd failed, %d\n"
    #                 % ("ut_pf_km.cc", 57, "ut_pf_km_get_hmac_key", "", v6),
    #             )
    #         else:
    #             v6 = ql.mem.read_ptr(v9_addr)
    #             if v6:
    #                 ut_pf_log_msg_fake(
    #                     ql,
    #                     5,
    #                     "[%s:%d/%s]<err>%skm ta inner error, %d\n"
    #                     % ("ut_pf_km.cc", 63, "ut_pf_km_get_hmac_key", "", v6),
    #                 )
    #             ql.mem.write_ptr(a2, v10)

    #         # call TEE_CloseTASession(v8)
    #         ql.arch.regs.r0 = v8
    #         TEE_CloseTASession(ql, "TEE_CloseTASession", True)

    #         ql.mem.unmap(temp_mem, 0x1000)
    #         ql.os.fcall.cc.setReturnValue(v6)
    #         ql.arch.regs.arch_sp += 0x38
    #         ql.arch.regs.arch_pc = current_lr


def ut_pf_log_msg_fake(ql, log_level, log):
    # dont wanna fully emualte everything, we just treat it as a bug-free log function
    if log_level > 0:
        ql.log.info(log)


def ut_pf_km_enc_pw(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params(
        {"a1": POINTER, "a2": UINT, "a3": POINTER, "a4": POINTER}
    )
    a1 = params["a1"]
    a2 = params["a2"]
    a3 = params["a3"]
    a4 = params["a4"]

    ql.log.info(f"{func_name}: {a1:#0x} {a2:#0x} {a3:#0x} {a4:#0x}")

    ql.mem.write_ptr(a4, 0x20)
    ql.mem.write(a3, b"b" * 0x20)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
