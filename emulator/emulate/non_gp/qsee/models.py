from dataclasses import dataclass, field
from enum import Enum
import socket
import struct
from typing import TYPE_CHECKING, Any, Tuple

import pwn
from qiling import Qiling
from qiling.core_hooks import HookRet
from qiling.os.const import INT, POINTER
import unicorn

if TYPE_CHECKING:
    from emulator.emulate.ta_mgr import TAEMU


QSEE_EXEC_REF_SLOT_SIZE = 0x10
QSEE_EXEC_REF_MAX_SLOTS = 0x100
QSEE_EXEC_REF_TOTAL_SIZE = QSEE_EXEC_REF_SLOT_SIZE * QSEE_EXEC_REF_MAX_SLOTS


@dataclass
class HookData:
    emu: "TAEMU"
    func_name: str


class SetupTeardownAction(Enum):
    SETUP = 0
    TEARDOWN = 1


@dataclass
class QseeObject:
    objdid: int
    name: str


@dataclass
class QseeCallback:
    addr: int
    kind: str
    name: str
    objdid: int | None = None
    singleton_key: str | None = None


def _noop_callback(ql: Qiling, hook_data: HookData) -> None:
    args = ql.os.resolve_fcall_params(
        {
            "function": POINTER,
            "arg1": POINTER,
            "arg1len": INT,
            "arg2": POINTER,
            "arg2len": INT,
        }
    )
    function = args["function"]
    arg1 = args["arg1"]
    arg1len = args["arg1len"]
    arg2 = args["arg2"]
    arg2len = args["arg2len"]
    ql.log.info(
        "qsee_callback[%s](addr:%#x, ptr:%#x/%#x, ptr:%#x/%#x)",
        hook_data.func_name,
        function,
        arg1,
        arg1len,
        arg2,
        arg2len,
    )
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _resolve_callback(kind: str):
    if kind == "noop":
        return _noop_callback
    raise ValueError(f"Unknown QSEE callback kind: {kind}")


@dataclass
class QseeSessionState:
    params_mem: int
    params_size: int
    exec_ref_base: int
    exec_ref_size: int
    exec_ref_next: int
    params: tuple[int, ...] = field(default_factory=tuple)
    setup_done: bool = False
    objects: dict[int, QseeObject] = field(default_factory=dict)
    callbacks: list[QseeCallback] = field(default_factory=list)
    _hooks: dict[int, HookRet] = field(default_factory=dict, init=False, repr=False)

    def reserve_exec_ref_slot(self) -> int:
        if self.exec_ref_next + QSEE_EXEC_REF_SLOT_SIZE > self.exec_ref_base + self.exec_ref_size:
            raise RuntimeError(
                "QSEE exec ref space exhausted: exceeded 0x100 callback refs of size 0x10"
            )
        addr = self.exec_ref_next
        self.exec_ref_next += QSEE_EXEC_REF_SLOT_SIZE
        return addr

    def _bind_callback(
        self,
        ql: Qiling,
        emu: "TAEMU",
        callback: QseeCallback,
    ) -> None:
        if callback.addr in self._hooks:
            return
        hook_fn = _resolve_callback(callback.kind)
        self._hooks[callback.addr] = ql.hook_address(
            hook_fn,
            callback.addr,
            user_data=HookData(emu, callback.name),
        )

    def _allocate_callback(
        self,
        ql: Qiling,
        emu: "TAEMU",
        *,
        kind: str,
        name: str,
        objdid: int | None = None,
        singleton_key: str | None = None,
    ) -> QseeCallback:
        callback = QseeCallback(
            addr=self.reserve_exec_ref_slot(),
            kind=kind,
            name=name,
            objdid=objdid,
            singleton_key=singleton_key,
        )
        self.callbacks.append(callback)
        self._bind_callback(ql, emu, callback)
        return callback

    def register_named_noop(
        self,
        ql: Qiling,
        emu: "TAEMU",
        *,
        name: str,
        singleton_key: str,
    ) -> int:
        for callback in self.callbacks:
            if callback.singleton_key == singleton_key:
                raise RuntimeError(
                    f"QSEE callback {singleton_key!r} already registered at {callback.addr:#x}"
                )
        callback = self._allocate_callback(
            ql,
            emu,
            kind="noop",
            name=name,
            singleton_key=singleton_key,
        )
        return callback.addr

    def get_callback_addr(self, singleton_key: str) -> int:
        for callback in self.callbacks:
            if callback.singleton_key == singleton_key:
                return callback.addr
        raise RuntimeError(f"QSEE callback {singleton_key!r} is missing from active state")

    def open_object(self, ql: Qiling, emu: "TAEMU", objdid: int) -> QseeCallback:
        name = f"qsee_open_{objdid:x}"
        self.objects.setdefault(objdid, QseeObject(objdid=objdid, name=name))
        return self._allocate_callback(
            ql,
            emu,
            kind="noop",
            name=name,
            objdid=objdid,
        )

    def rebind_runtime(self, ql: Qiling, emu: "TAEMU") -> None:
        self._hooks.clear()
        for callback in self.callbacks:
            self._bind_callback(ql, emu, callback)

    def release_runtime_hooks(self, ql: Qiling) -> None:
        for hook in self._hooks.values():
            ql.hook_del(hook)
        self._hooks.clear()

    def teardown(self, ql: Qiling) -> None:
        ql.log.debug("teardown QSEE session state")
        self.release_runtime_hooks(ql)
        for addr, size, label in (
            (self.exec_ref_base, self.exec_ref_size, "exec_ref"),
            (self.params_mem, self.params_size, "params_mem"),
        ):
            try:
                ql.mem.unmap(addr, size)
            except Exception as exc:
                ql.log.warning(
                    "Failed to unmap setup_or_teardown %s %#0x/%#0x: %s",
                    label,
                    addr,
                    size,
                    exc,
                )

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "params_mem": self.params_mem,
            "params_size": self.params_size,
            "exec_ref_base": self.exec_ref_base,
            "exec_ref_size": self.exec_ref_size,
            "exec_ref_next": self.exec_ref_next,
            "params": list(self.params),
            "setup_done": self.setup_done,
            "objects": [
                {"objdid": obj.objdid, "name": obj.name}
                for obj in self.objects.values()
            ],
            "callbacks": [
                {
                    "addr": callback.addr,
                    "kind": callback.kind,
                    "name": callback.name,
                    "objdid": callback.objdid,
                    "singleton_key": callback.singleton_key,
                }
                for callback in self.callbacks
            ],
        }

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> "QseeSessionState":
        state = cls(
            params_mem=snapshot["params_mem"],
            params_size=snapshot["params_size"],
            exec_ref_base=snapshot["exec_ref_base"],
            exec_ref_size=snapshot["exec_ref_size"],
            exec_ref_next=snapshot["exec_ref_next"],
            params=tuple(snapshot.get("params", [])),
            setup_done=snapshot.get("setup_done", False),
        )
        state.objects = {
            obj["objdid"]: QseeObject(objdid=obj["objdid"], name=obj["name"])
            for obj in snapshot.get("objects", [])
        }
        state.callbacks = [
            QseeCallback(
                addr=callback["addr"],
                kind=callback["kind"],
                name=callback["name"],
                objdid=callback.get("objdid"),
                singleton_key=callback.get("singleton_key"),
            )
            for callback in snapshot.get("callbacks", [])
        ]
        return state


def get_active_qsee_session_state(emu: "TAEMU") -> QseeSessionState:
    qsee_state = getattr(emu, "_qsee_setup_state", None)
    if qsee_state is None:
        raise RuntimeError("QSEE setup state not found")
    return qsee_state


def save_active_qsee_state(emu: "TAEMU") -> dict[str, Any] | None:
    state = getattr(emu, "_qsee_setup_state", None)
    if state is None:
        raise RuntimeError("QSEE setup state is missing while saving a cached CElfFile_invoke snapshot")
    return state.to_snapshot()


def restore_active_qsee_state(
    emu: "TAEMU", snapshot: dict[str, Any] | None
) -> QseeSessionState | None:
    if snapshot is None:
        raise RuntimeError("QSEE snapshot payload is missing for cached CElfFile_invoke restore")

    state = QseeSessionState.from_snapshot(snapshot)
    state.rebind_runtime(emu.ql, emu)
    emu._qsee_setup_state = state
    emu.ql.log.info("QSEE setup state restored. QseeObjects/Callbacks: %d/%d", len(state.objects), len(state.callbacks))
    return state


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
        data = b[8 : 8 + length]
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
        return m.data[8 : 8 + msg], m.data[8 + msg : 8 + msg + data]
