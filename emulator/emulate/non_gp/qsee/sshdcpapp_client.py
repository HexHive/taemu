import pwn

import random


try:
    from emulate.non_gp.qsee.running import InteractiveCmd, QseeInteractiveMsg
    from emulate.non_gp.qsee.params import QseeCommandParams
except ImportError:
    from emulator.emulate.non_gp.qsee.running import InteractiveCmd, QseeInteractiveMsg
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams


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
    return QseeInteractiveMsg.receive_DataMsg(r)

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
print("Sent init", p)
print("Send Cert")
p = send_invoke_command(0x67, 0x1000, 0x3c0, data)
print(p)
p = send_exit()
print(p.data)
r.close()
