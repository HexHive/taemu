import pwn

import random


try:
    from emulate.non_gp.qsee.running import InteractiveCmd, QseeInteractiveMsg
    from emulate.non_gp.qsee.params import QseeCommandParams
except ImportError:
    from emulator.emulate.non_gp.qsee.running import InteractiveCmd, QseeInteractiveMsg
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams




    # display_resp = None
    # with pwn.context.local(
    #     binary=emu.ta_elf
    # ), stop_hooks_at(
    #     emu.ql,
    #     *command_handler_fn.end,
    #     user_data="command_handler:tz_app_cmd_handler_end",
    # ):
    #     if emu.ta_path.name == "engmode.elf":
    #         cmd_id = 0xB
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: b"\x01",  # payload_version em_context_make_request:218, has to be 0x01
    #                     1: pwn.p64(cmd_id | 0xC000),  # Cmd id
    #                     1303: pwn.p64(cmd_id | 0xC000),  # Cmd id2?
    #                 },
    #                 length=0x21C7D,
    #             ),
    #             0x20936,
    #         )

    #     elif emu.ta_path.name == "vaultkeeper.elf":
    #         req, resp_len = (
    #             pwn.flat({0: pwn.p32(0)}, length=0xADF8),
    #             0xAE00,
    #         )

    #         def _vaultkeep_resp(ql: Qiling, resp_mem, resp_len):
    #             message_loc = resp_mem + 0x5AF6
    #             message = ql.mem.string(message_loc)
    #             resp_code = ql.mem.read_ptr(resp_mem + 1)
    #             ql.log.info(
    #                 "vaultkeeper response: message=%s, resp_code=%#x",
    #                 message,
    #                 resp_code,
    #             )

    #         display_resp = _vaultkeep_resp

    #     elif emu.ta_path.name == "fingerpr.elf":
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0x74),
    #                 },
    #                 length=0xC5,
    #             ),
    #             0xDEF,
    #         )
    #     elif emu.ta_path.name == "evautil64.elf":
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0),
    #                     4: 0xDEADBEEF,  # pointer to the thing?
    #                     12: pwn.p32(0x100),  # size of the thing?
    #                 },
    #                 length=0xABC,
    #             ),
    #             0xDEF,
    #         )
    #     elif emu.ta_path.name == "featenabler.elf":
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0x4),  # cmdid
    #                 },
    #                 length=0xABC,
    #             ),
    #             0x100,
    #         )

    #     elif emu.ta_path.name == "ops.elf":
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0),  # only command = 0x0
    #                 },
    #                 length=0xC5,
    #             ),
    #             0xDEF,
    #         )

    #     elif emu.ta_path.name == "hwvault.elf":
    #         records = pwn.flat(
    #             [
    #                 {0: b"\x01", 1: b"\x00" * 7},  # chunk type 0x01, fixed length 8
    #                 # {
    #                 #     0: b"\x02", # chunk type 0x02, variable length
    #                 #     1: b"\x10", # Size
    #                 #     2: b"\x00" * (0x10 - 2)
    #                 # }
    #             ]
    #         )
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0),
    #                     4: pwn.p32(
    #                         len(records)
    #                     ),  # has to be <= 0x9ff8, and < length - 8
    #                     0xB: records,
    #                 },
    #             ),
    #             0xDEF,
    #         )

    #     elif emu.ta_path.name == "mst.elf":
    #         req, resp_len = (
    #             pwn.flat(
    #                 {
    #                     0: pwn.p32(0xA0000),  # commands [0xa0001, 0xa0000]
    #                 },
    #                 length=0xABC,
    #             ),
    #             0xDEF,
    #         )

    #     else:
    #         raise ValueError(f"Unknown TA: {emu.ta_path.name}")

r = pwn.remote("localhost", 1337)


BIN_LEN_MAP = {
    "engmode.elf": {
        "req_len": 0x21C7D,
        "rsp_len": 0x20936,
    },
    "vaultkeeper.elf": {
        "req_len": 0xADF8,
        "rsp_len": 0xAE00,
    },
    "mst.elf": {
        "req_len": 0xABC,
        "rsp_len": 0xDEF,
    },
}

def _send_msg(msg: 'QseeInteractiveMsg'):
    r.send(msg.to_bytes())
    return QseeInteractiveMsg._receive_message(r)

def send_exit():
    return _send_msg(QseeInteractiveMsg(InteractiveCmd.Exit, b""))

def build_params(cmd: int, req_len: int, rsp_len: int, data: bytes):
    data = pwn.flat({
        0: cmd,
        4: data,
    })
    return QseeCommandParams(data, req_len=req_len, rsp_len=rsp_len)

def send_invoke_command(cmd: int, req_len: int, rsp_len: int, data: bytes):
    params = build_params(cmd, req_len, rsp_len, data)
    return _send_msg(params.to_msg())

random.seed(42)
data = random.randbytes(200)
print(f"data: {data.hex()}")

# p = send_invoke_command(0xA0000, 0xADF8, 0xAE00, data)
# p = send_invoke_command(1, 0xadf8, 0xAE00, data)
# p = send_invoke_command(1, 0x21C7D, 0x20936, data)

print("Sending init")
p = send_invoke_command(0x66, 0x1000, 0x3c0, data)
print("Sent init", p.data)
print("Send Cert")
p = send_invoke_command(0x67, 0x1000, 0x3c0, data)
print(p.data)
p = send_exit()
print(p.data)
r.close()
