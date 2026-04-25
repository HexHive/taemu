from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Tuple
import struct
import pwn
from qiling import Qiling
from qiling.os.const import INT, POINTER

if TYPE_CHECKING:
    from emulator.emulate.emulator_no_loader import HookData

# ------------------------
# Stateful model
# ------------------------

SECTOR_SIZE = 512

@dataclass
class EmuPartition:
    part_id: int
    name: str = ""
    sector_size: int = SECTOR_SIZE
    sectors: Dict[int, bytes] = field(default_factory=dict)  # lba -> 512-byte block

@dataclass
class EmuDevice:
    handle_addr: int
    backend_type: int          # first u32 stored in backing object
    dev_id: int
    init_arg: int
    partitions: Dict[int, EmuPartition] = field(default_factory=dict)

@dataclass
class EmuClient:
    handle_addr: int
    backend_type: int          # first u32 stored in backing object
    dev_handle: int
    part_id: int

class StorModel:
    def __init__(self, ql):
        self.ql = ql
        self.devices: Dict[int, EmuDevice] = {}   # handle_addr -> device
        self.clients: Dict[int, EmuClient] = {}   # handle_addr -> client
        self.next_handle = 0x71000000

    def alloc_handle(self, size=0x40) -> int:
        # Good enough for emulation; bump allocator in a fake range.
        addr = self.next_handle
        self.next_handle += ((size + 0xF) & ~0xF)
        return addr

    def ensure_mapped(self, addr: int, size: int):
        # Map page if needed; ignore if already mapped.
        page = addr & ~0xFFF
        end = (addr + size + 0xFFF) & ~0xFFF
        cur = page
        while cur < end:
            try:
                self.ql.mem.read(cur, 1)
            except:
                self.ql.mem.map(cur, 0x1000, info="[qsee_stor_stub]")
            cur += 0x1000

    def write_u32(self, addr: int, val: int):
        self.ql.mem.write(addr, struct.pack("<I", val & 0xffffffff))

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.ql.mem.read(addr, 4))[0]

    def create_device(self, dev_id: int, init_arg: int) -> EmuDevice:
        # Mirror the wrapper behavior enough:
        # dev_id == 3 goes to rpmbw path; use backend_type 1
        # everything else: generic storage backend_type 0x10
        backend_type = 1 if dev_id == 3 else 0x10

        h = self.alloc_handle(0x40)
        self.ensure_mapped(h, 0x40)

        # First dword is what libcmnlib wrappers inspect.
        self.write_u32(h + 0x00, backend_type)

        # Some filler fields to make accidental reads less crashy.
        self.write_u32(h + 0x04, dev_id)
        self.write_u32(h + 0x08, 0)
        self.write_u32(h + 0x0C, 0)

        dev = EmuDevice(
            handle_addr=h,
            backend_type=backend_type,
            dev_id=dev_id,
            init_arg=init_arg,
        )

        # Pre-create a default partition 0 with a few sectors
        part0 = EmuPartition(part_id=0, name="default")
        for lba in range(16):
            part0.sectors[lba] = bytes([lba & 0xff]) * SECTOR_SIZE
        dev.partitions[0] = part0

        self.devices[h] = dev
        return dev

    def open_partition(self, dev_handle: int, part_id: int) -> EmuClient:
        dev = self.devices[dev_handle]

        if part_id not in dev.partitions:
            dev.partitions[part_id] = EmuPartition(part_id=part_id, name=f"part{part_id}")

        h = self.alloc_handle(0x40)
        self.ensure_mapped(h, 0x40)

        # First dword again matters.
        self.write_u32(h + 0x00, dev.backend_type)
        self.write_u32(h + 0x04, part_id)
        self.write_u32(h + 0x08, dev_handle & 0xffffffff)
        self.write_u32(h + 0x0C, 0)

        cli = EmuClient(
            handle_addr=h,
            backend_type=dev.backend_type,
            dev_handle=dev_handle,
            part_id=part_id,
        )
        self.clients[h] = cli
        return cli

    def read_sectors(self, client_handle: int, start_sector: int, sector_count: int) -> bytes:
        cli = self.clients[client_handle]
        dev = self.devices[cli.dev_handle]
        part = dev.partitions[cli.part_id]

        out = bytearray()
        for lba in range(start_sector, start_sector + sector_count):
            blk = part.sectors.get(lba)
            if blk is None:
                blk = b"\x00" * part.sector_size
            elif len(blk) != part.sector_size:
                blk = blk[:part.sector_size].ljust(part.sector_size, b"\x00")
            out += blk
        return bytes(out)

    def write_sectors(self, client_handle: int, start_sector: int, sector_count: int, data: bytes):
        cli = self.clients[client_handle]
        dev = self.devices[cli.dev_handle]
        part = dev.partitions[cli.part_id]

        need = sector_count * part.sector_size
        data = data[:need].ljust(need, b"\x00")

        for i in range(sector_count):
            lba = start_sector + i
            off = i * part.sector_size
            part.sectors[lba] = data[off:off + part.sector_size]

def get_stor_model(ql):
    if not hasattr(ql, "_qsee_stor_model"):
        ql._qsee_stor_model = StorModel(ql)
    return ql._qsee_stor_model


# ------------------------
# Return helper
# ------------------------

def _ret0(ql):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def _ret_err(ql, err=0xfffffffe):
    ql.os.fcall.cc.setReturnValue(err & 0xffffffff)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# ------------------------
# Stubs
# ------------------------

def qsee_stor_device_init(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "dev_id": INT,        # w0
        "init_arg": POINTER,  # x1
        "out_dev": POINTER,   # x2
    })

    dev_id = args["dev_id"]
    init_arg = args["init_arg"]
    out_dev = args["out_dev"]

    ql.log.info("qsee_stor_device_init(dev_id=%#x, init_arg=%#x, out_dev=%#x)",
                dev_id, init_arg, out_dev)

    if out_dev == 0:
        return _ret_err(ql)

    stor = get_stor_model(ql)
    dev = stor.create_device(dev_id, init_arg)

    # out_dev is a pointer-to-handle/object pointer
    ql.mem.write(out_dev, pwn.p64(dev.handle_addr))
    return _ret0(ql)


def qsee_stor_open_partition(ql:Qiling, hook_data):
    args = ql.os.resolve_fcall_params({
        "stor_device": POINTER,  # x0
        "part_id": INT,          # w1
        "out_client": POINTER,   # x2
    })

    stor_device_ptr = args["stor_device"]
    part_id = args["part_id"]
    out_client = args["out_client"]

    ql.log.info("qsee_stor_open_partition(dev=%#x, part_id=%#x, out_client=%#x)",
                stor_device_ptr, part_id, out_client)

    if stor_device_ptr == 0 or out_client == 0:
        return _ret_err(ql)
    stor_device = ql.mem.read_ptr(stor_device_ptr)

    stor = get_stor_model(ql)
    if stor_device not in stor.devices:
        ql.log.warning("unknown stor_device %#x", stor_device)
        return _ret_err(ql)

    cli = stor.open_partition(stor_device, part_id)
    ql.mem.write(out_client, pwn.p64(cli.handle_addr))
    return _ret0(ql)


def qsee_stor_read_sectors(ql, hook_data):
    args = ql.os.resolve_fcall_params({
        "client": POINTER,       # x0
        "start_sector": INT,     # w1
        "sector_count": INT,     # w2
        "buf": POINTER,          # x3
    })

    client = args["client"]
    start_sector = args["start_sector"]
    sector_count = args["sector_count"]
    buf = args["buf"]

    ql.log.info("qsee_stor_read_sectors(client=%#x, start=%#x, count=%#x, buf=%#x)",
                client, start_sector, sector_count, buf)

    if client == 0 or buf == 0:
        return _ret_err(ql)

    stor = get_stor_model(ql)
    client = ql.mem.read_ptr(client)
    if client not in stor.clients:
        ql.log.warning("unknown client %#x", client)
        return _ret_err(ql)

    data = stor.read_sectors(client, start_sector, sector_count)
    ql.mem.write(buf, data)
    return _ret0(ql)


def qsee_stor_write_sectors(ql, hook_data):
    args = ql.os.resolve_fcall_params({
        "client": POINTER,       # x0
        "start_sector": INT,     # w1
        "sector_count": INT,     # w2
        "buf": POINTER,          # x3
    })

    client = args["client"]
    start_sector = args["start_sector"]
    sector_count = args["sector_count"]
    buf = args["buf"]

    ql.log.info("qsee_stor_write_sectors(client=%#x, start=%#x, count=%#x, buf=%#x)",
                client, start_sector, sector_count, buf)

    if client == 0 or buf == 0:
        return _ret_err(ql)

    stor = get_stor_model(ql)
    if client not in stor.clients:
        ql.log.warning("unknown client %#x", client)
        return _ret_err(ql)

    total = sector_count * SECTOR_SIZE
    data = ql.mem.read(buf, total)
    stor.write_sectors(client, start_sector, sector_count, data)
    return _ret0(ql)


def qsee_stor_device_get_info(ql, hook_data):
    args = ql.os.resolve_fcall_params({
        "stor_device": POINTER,  # x0
        "info_out": POINTER,     # x1
    })

    stor_device = args["stor_device"]
    info_out = args["info_out"]

    ql.log.info("qsee_stor_device_get_info(dev=%#x, info_out=%#x)",
                stor_device, info_out)

    if stor_device == 0 or info_out == 0:
        return _ret_err(ql)

    stor = get_stor_model(ql)
    dev = stor.devices.get(stor_device)
    if dev is None:
        ql.log.warning("unknown stor_device %#x", stor_device)
        return _ret_err(ql)

    # Real wrapper pre-seeds first u32 with 3 on rpmb path.
    # For generic consistency:
    #   +0x00 : version/type-ish field
    #   +0x04 : sector size
    #   +0x08 : partition count
    #   +0x0c : dev_id
    version_or_type = 3 if dev.backend_type == 1 else 1

    blob = b"".join([
        pwn.p32(version_or_type),
        pwn.p32(SECTOR_SIZE),
        pwn.p32(len(dev.partitions)),
        pwn.p32(dev.dev_id),
        pwn.p32(dev.backend_type),
        pwn.p32(0),   # reserved
        pwn.p64(0),   # reserved
    ])

    ql.mem.write(info_out, blob)
    return _ret0(ql)