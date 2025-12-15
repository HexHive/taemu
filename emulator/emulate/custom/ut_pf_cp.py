from qiling import Qiling
from qiling.os.const import STRING, UINT, POINTER
from pwn import *


from Crypto.PublicKey import RSA  # provided by pycryptodome

from ..gp.utils.string import malloc_core, memset_core, free_core

### ut_pf_cp_open, ut_pf_cp_gk_rsakey, ut_pf_cp_close
# libuTcrypto.so


def ut_pf_cp_open(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"a1": POINTER, "a2": UINT, "a3": UINT})
    a1 = params["a1"]
    a2 = params["a2"]
    a3 = params["a3"]

    ql.log.info(f"{func_name}: {a1:#0x}, {a2}, {a3:#0x}")

    if a2 == 1:
        if not a3 - 0x1000 <= 6:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a2 == 2:
        if a3 - 0x2000 > 0xA:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a2 == 3:
        if a3 - 0x3000 > 0xC:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a2 == 4:
        if a3 - 0x4000 > 1:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a2 == 5:
        if a3 > 0x501F and a3 - 0x5100 > 6:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
        elif a3 < 0x501C and a3 - 0x5000 > 0x1A:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a2 == 6:
        if a3 - 0x6000 > 0xE or ((1 << (a3 - 0x6000)) & 0x6FFB) == 0:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
    elif a3 == 7:
        if not a3 == 0x7004:
            ql.os.fcall.cc.setReturnValue(-1)
            ql.arch.regs.arch_pc = ql.arch.regs.lr

    ql.arch.regs.r0 = 0x5A0
    malloc_core(ql, "malloc", True)
    v6 = ql.arch.regs.r0
    ql.log.info(f"\t write {v6:#0x} to {a1:#0x}")
    ql.mem.write_ptr(a1, v6)
    if v6 == 0:
        ql.os.fcall.cc.setReturnValue(-2)
        ql.arch.regs.arch_pc = ql.arch.regs.lr

    ql.arch.regs.r0 = v6
    ql.arch.regs.r1 = 0
    ql.arch.regs.r2 = 0x5A0
    memset_core(ql, "memset", True)

    ql.mem.write_ptr(v6 + 4, a3)
    ql.mem.write_ptr(v6 + 8, 0)
    ql.mem.write_ptr(v6 + 12, 0)

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_cp_gk_rsakey(ql: Qiling, func_name):
    tmp = {}
    for i in range(1, 10):
        tmp[f"a{i}"] = UINT
    params = ql.os.resolve_fcall_params(tmp)
    a1 = params["a1"]
    e = params["a4"]
    e_size = params["a5"]
    n = params["a6"]
    n_size = params["a7"]
    d = params["a8"]
    d_size = params["a9"]

    ql.log.info(f"{func_name}: {a1:#0x}")

    if not a1 or ql.mem.read_ptr(a1) != 6:
        ql.os.fcall.cc.setReturnValue(-1)
        ql.arch.regs.arch_pc = ql.arch.regs.lr

    # @TODO: other params ignored
    n_con = 20310516630830819019711807965302169161665120012366961241503941538143216891403407887750652984739052711340282428052009523362556671158851695047051730429914689221887218962890960143290933101752146366299572197199063192239919684480560796578840319553962915251912733416981639847335046947998612848256787418483196281123410093197657641444507880424367140098797131025675201448354769339545013866343624252651588785655350504551296967288818678701811612704270462890312154454137407953634405799833008428838423977002872417162927809388285431701707471299765565171295527320153832532220210684092090568796662453374871225720970441861292119331919
    n_con = n_con.to_bytes(0x100, "big")
    e_con = 65537
    e_con = e_con.to_bytes(3, "big")
    d_con = 9664827069427802950222507029707088323781809248297542659528845092215608922826902030721452980485406684099944272719684590316686640321649586672221115784782939378881773815962242443637503085451614150471008110561209465083756279356863588539416119224405869585824046025023870794802794972615236283103226764008376325176705858228013168525722790923355881701188941719155601028839075207245890990543723878280205088783929381457779405928215089529405241319410185978180474060369375189136153521394922123415199336911291091008542090888140316971964920477338327969632052118806825115367398561398049108431436663453983526121313561071204178213761
    d_con = d_con.to_bytes(0x100, "big")

    ql.mem.write(e, e_con)
    ql.mem.write_ptr(e_size, 3)
    ql.mem.write(n, n_con)
    ql.mem.write_ptr(n_size, 0x100)
    ql.mem.write(d, d_con)
    ql.mem.write_ptr(d_size, 0x100)

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_cp_close(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"a1": POINTER})
    a1 = params["a1"]

    if a1:
        if ql.mem.read_ptr(a1) == 4 and ql.mem.read_ptr(a1 + 4) == 0x4001:
            v2 = ql.mem.read_ptr(a1 + 0xAC * 4)
            if v2:
                ql.arch.regs.r0 = v2
                free_core(ql, "free", True)
                ql.mem.write_ptr(a1 + 0xAC * 4, 0)
        ql.arch.regs.r0 = a1
        free_core(ql, "free", True)

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

