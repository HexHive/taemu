import pwn

import random


try:
    from emulate.non_gp.qsee.interactive import InteractiveCmd
    from emulate.non_gp.qsee.interactive import QseeInteractiveMsg
except ImportError:
    from emulator.emulate.non_gp.qsee.interactive import InteractiveCmd
    from emulator.emulate.non_gp.qsee.interactive import QseeInteractiveMsg


r = pwn.remote("localhost", 1337)

def _send_msg(msg: 'QseeInteractiveMsg'):
    r.send(msg.to_bytes())
    return QseeInteractiveMsg.receive_message(r)

def send_exit():
    return _send_msg(QseeInteractiveMsg(InteractiveCmd.Exit, b""))

def send_invoke_command(cmd: int, data: bytes):
    return _send_msg(QseeInteractiveMsg(InteractiveCmd.InvokeCommand, pwn.flat({
        0: cmd,
        4: data,
    })))

random.seed(42)
data = random.randbytes(200)
print(f"data: {data.hex()}")
p = send_invoke_command(0xA0000, data)
print(p.data)
p = send_exit()
print(p.data)
r.close()