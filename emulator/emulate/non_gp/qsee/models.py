from dataclasses import dataclass
from enum import Enum
import socket
import struct
from typing import Tuple

import pwn


class SetupTeardownAction(Enum):
    SETUP = 0
    TEARDOWN = 1


class InteractiveCmd(Enum):
    InvokeCommand = 0x0
    Exit = 0xFF
    Error = 0xFD
    MsgData = 0x11


@dataclass
class QseeInteractiveMsg:
    cmd: InteractiveCmd
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data) + 8

    @staticmethod
    def from_bytes(b: bytes) -> "QseeInteractiveMsg":
        length, cmd_no = struct.unpack("II", b[:8])
        data = b[8:8+length]
        try:
            cmd = InteractiveCmd(cmd_no)
        except ValueError:
            raise ValueError(f"Invalid interactive command: {cmd_no:#0x}")
        return QseeInteractiveMsg(cmd, data)

    def to_bytes(self) -> bytes:
        return struct.pack("II", self.length, self.cmd.value) + self.data


    @staticmethod
    def _receive_message(channel: pwn.tube) -> "QseeInteractiveMsg":
        d = channel.recv(8)
        length, cmd_no = struct.unpack("II", d)
        data = channel.recv(length)
        try:
            cmd = InteractiveCmd(cmd_no)
        except ValueError:
            raise ValueError(f"Invalid interactive command: {cmd_no:#0x}")
        return QseeInteractiveMsg(cmd, data)
    
    def _send_message(self, channel: pwn.tube) -> None:
        b = self.to_bytes()
        channel.send(b)


    @staticmethod
    def send_DataMsg(s: socket.socket, msg: bytes, data: bytes = None):
        if data is None:
            data = b""
        msg = struct.pack("II", len(msg), len(data)) + msg + data
        msg = QseeInteractiveMsg(InteractiveCmd.MsgData, msg)
        s.send(msg.to_bytes())
        return msg
    
    @staticmethod
    def receive_DataMsg(s: socket.socket) -> Tuple[bytes, bytes]:
        m = QseeInteractiveMsg._receive_message(s)
        if m.cmd != InteractiveCmd.MsgData:
            raise ValueError(f"Expected MsgData, got {m.cmd}")
        msg, data = struct.unpack("II", m.data[:8])
        return m.data[8:8+msg], m.data[8+msg:8+msg+data]
