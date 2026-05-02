from dataclasses import dataclass
from enum import Enum
import socket
import struct

import pwn


class SetupTeardownAction(Enum):
    SETUP = 0
    TEARDOWN = 1


class QseeTzCmdIdent(Enum):
    Cmd0 = 0
    Cmd1 = 1


class InteractiveCmd(Enum):
    InvokeCommand = 0x0
    Exit = 0xFF
    Print = 0xFE
    Error = 0xFD


@dataclass
class QseeInteractiveMsg:
    cmd: InteractiveCmd
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)

    @staticmethod
    def from_bytes(b: bytes) -> "QseeInteractiveMsg":
        try:
            cmd = InteractiveCmd(b[0])
        except ValueError:
            raise ValueError(f"Invalid interactive command: {b[0]:#0x}")
        length = b[1]
        data = b[2 : 2 + length]
        return QseeInteractiveMsg(cmd, data)

    @staticmethod
    def receive_message(channel: pwn.tube) -> "QseeInteractiveMsg":
        d = channel.recv(2)
        cmd = InteractiveCmd(d[0])
        length = d[1]
        data = channel.recv(length)
        return QseeInteractiveMsg(cmd, data)

    def to_bytes(self) -> bytes:
        return struct.pack("BB", self.cmd.value, self.length) + self.data

    @staticmethod
    def send_print(s: socket.socket, data: bytes):
        msg = QseeInteractiveMsg(InteractiveCmd.Print, data)
        s.send(msg.to_bytes())
        return msg
