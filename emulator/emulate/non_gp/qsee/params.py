"""Helpers for building and mapping QSEE command-handler parameters."""

from contextlib import contextmanager
import hashlib
import struct
from typing import TYPE_CHECKING, Generator, Tuple
import pwn
from qiling import Qiling
import unicorn

from emulate.params import MIN_PARAM_ADDR
from emulate.non_gp.qsee.models import InteractiveCmd, QseeInteractiveMsg

if TYPE_CHECKING:
    from emulate.ta_mgr import TAEMU


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

ReqResParam = Tuple[int, int, int]


class QseeCommandParams:
    def __init__(
        self,
        req_data: bytes,
        bin_name: str = None,
        *,
        req_len: int = None,
        rsp_len: int = None,
    ):
        self.req_data = req_data
        self.req_len, self.resp_len = self._resolve_reqrsp_len(
            bin_name, req_len, rsp_len
        )
        self.mem_regions = {}

    def _resolve_reqrsp_len(
        self, bin_name: str | None, given_req_len: int, given_rsp_len: int
    ) -> int:
        req_len = None
        rsp_len = None
        if bin_name is not None:
            if bin_name in BIN_LEN_MAP:
                req_len = BIN_LEN_MAP[bin_name]["req_len"]
                rsp_len = BIN_LEN_MAP[bin_name]["rsp_len"]
            else:
                raise ValueError(f"Unknown bin name: {bin_name}")
        if given_req_len is not None:
            req_len = given_req_len
        if given_rsp_len is not None:
            rsp_len = given_rsp_len
        if req_len is None:
            raise ValueError("req_len is not set")
        if rsp_len is None:
            raise ValueError("rsp_len is not set")
        return req_len, rsp_len

    def _map_region(self, ql: Qiling, size: int, info: str) -> int:
        addr = ql.mem.map_anywhere(
            size,
            minaddr=MIN_PARAM_ADDR,
            perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
            info=info,
        )
        self.mem_regions[addr] = size
        return addr

    def setup(self, ql: Qiling) -> ReqResParam:
        req_mem = self._map_region(ql, len(self.req_data), "command_handler[qsee_ns]")
        ql.mem.write(req_mem, self.req_data)

        resp_mem = self._map_region(ql, self.resp_len, "command_handler[qsee_ns]")

        params_mem = self._map_region(ql, 0x1000, "command_handler[params]")
        assert (
            self.req_len | self.resp_len
        ) >> 0x20 == 0, "req_len | resp_len is not 32bit max."
        payload = pwn.flat(
            {
                0x0: {0x0: params_mem + 0x20, 0x8: 0x24},
                # args for tz_command_handler
                0x20: {
                    # (cmd len | resp len) >> 0x20 == 0 # they should be 32bit max
                    # cmd ptr
                    0x0: req_mem,
                    # cmd len
                    0x8: self.req_len,  # min 0x24. For engmode, has to be 0x21c7d
                    # resp ptr
                    0x10: resp_mem,
                    # resp len
                    0x18: self.resp_len,  # min 0x8
                    # arg4
                    # - arg4 should be a null byte, so we don't invoke GPAppLib_*
                    0x20: 0,  # arg4
                },
            },
            filler=b"\x00",
        )

        ql.mem.write(params_mem, payload)

        # First argument selects tz_cmd_handler with 0x0
        ql.os.fcall.cc.setRawParam(1, 0x0)
        ql.os.fcall.cc.setRawParam(2, params_mem)
        ql.os.fcall.cc.setRawParam(3, 0x0001)
        return req_mem, resp_mem, params_mem

    def teardown(self, ql: Qiling):
        for addr, size in self.mem_regions.items():
            try:
                ql.mem.unmap(addr, size)
                del self.mem_regions[addr]
            except Exception as e:
                ql.log.error(f"Error unmapping memory: {e}")
        if len(self.mem_regions) > 0:
            ql.log.error(f"Memory regions not cleared: {self.mem_regions}")

    @contextmanager
    def setup_ctx(self, ql: Qiling) -> Generator[ReqResParam, None, None]:
        req_mem, resp_mem, params_mem = self.setup(ql)
        try:
            yield req_mem, resp_mem, params_mem
        finally:
            self.teardown(ql)

    def to_msg(self) -> QseeInteractiveMsg:
        h = struct.pack("II", self.req_len, self.resp_len)
        return QseeInteractiveMsg(InteractiveCmd.InvokeCommand, h + self.req_data)
    
    @staticmethod
    def from_msg(b: 'QseeInteractiveMsg') -> "QseeCommandParams":
        req_len, resp_len = struct.unpack("II", b.data[:8])
        req_data = b.data[8:]
        return QseeCommandParams(req_data, req_len=req_len, rsp_len=resp_len)


def setup_qsee_fuzz(ql: Qiling, params: QseeCommandParams, input: bytes):
    # TODO: Why do we hash input, why not params directly?
    ql.emu.curr_input = input
    seed_id = f"run:id:{hashlib.md5(input).hexdigest()}"
    ql.emu.curr_record_key = seed_id
    ql.emu.curr_params = params
    params.setup(ql)
