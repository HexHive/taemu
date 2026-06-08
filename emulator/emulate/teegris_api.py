from enum import Enum
import os
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp.session import TEE_OpenTASession
from Crypto.Random import get_random_bytes
from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from .common import crash, crash_notimpl

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf

def TEES_GetClientCredentials(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"out": POINTER})
    ql.mem.write_ptr(p["out"], 0x133)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def vltkpr_authenticate_ca_softpass(ql: Qiling, hook_data):
    # Phase-B model of vltkpr's PROCA soft-pass. On a custom-kernel /
    # PROCA-stripped device vk_authenticate_ca (RE @0x1a6a0) returns 0 and
    # TA_InvokeCommandEntryPoint dispatches to vk_switcher. The emulator has no
    # PROCA driver (ioctl on /dev/pa_driver is unmodeled -> emu_stop), so we
    # model the documented soft-pass directly via an inline address hook.
    # See RE/samsung_teegris/vltkpr.md "Caller authentication" (returns
    # 0 / 0x110019 custom-kernel / 0x120000 no-PROCA all proceed).
    ql.log.info("[vltkpr] vk_authenticate_ca stubbed -> 0 (PROCA soft-pass)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_GetIrsFlagValue(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_IsREESharedMemory(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_DeriveKeyKDF(ql: Qiling, hook_data):
    # Samsung TEE syscall: derive key material from the HW device-bound root
    # key into both an out-buffer and a transient object handle.
    # Signature (RE/samsung_teegris/fbckmr.md fk_custom_so_derive_key @0x130CC):
    #   TEES_DeriveKeyKDF(salt, salt_len, out_buf, out_len, key_len, obj_handle)
    # The emulator has no HW root key, so we derive a deterministic,
    # length-correct surrogate (SHA256 chain over the salt). Correctness is
    # irrelevant to the downstream GCM overflow — only the *length* and the
    # object becoming initialized matter so TEE_GetObjectBufferAttribute and
    # the subsequent EVP_*Init_ex/EVP_DecryptUpdate path proceed.
    import hashlib
    from .gp.utils.object import handle2obj
    from .gp.utils.attribute import ATTRIBUTE_MEM
    p = ql.os.resolve_fcall_params({"salt": POINTER, "salt_len": INT, "out": POINTER,
                                    "out_len": INT, "key_len": INT, "obj": POINTER})
    salt = b""
    try:
        if p["salt"] and p["salt_len"]:
            salt = bytes(ql.mem.read(p["salt"], p["salt_len"]))
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    key_len = p["key_len"] or p["out_len"] or 32
    derived = b""
    i = 0
    while len(derived) < key_len:
        derived += hashlib.sha256(b"TEEGRIS-EMU-KDF" + salt + bytes([i & 0xFF])).digest()
        i += 1
    derived = derived[:key_len]
    ql.log.info(f"TEES_DeriveKeyKDF: salt_len={p['salt_len']} key_len={key_len} "
                f"obj={hex(p['obj'])} -> derived {len(derived)}B (surrogate)")
    try:
        if p["out"]:
            ql.mem.write(p["out"], derived)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    obj_handle = p["obj"]
    if obj_handle in handle2obj:
        obj = handle2obj[obj_handle]
        kb = ql.mem.map_anywhere(0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="derived_key")
        ql.mem.write(kb, derived)
        obj.attrs[0xC0000000] = (kb, key_len)   # TEE_ATTR_SECRET_VALUE
        obj.key = derived
        obj.initialized = True
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_CheckSecureObjectCreator(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({
        "in": POINTER, 
        "in_size": INT,
    })
    in_buf = p["in"]
    in_size = p["in_size"]
    hook_data.emu.update_shm(in_buf, in_size)
    ql.log.info(f"{hook_data.func_name} returning 1")
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_InitDriver(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_FiniDriver(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

fd_counter = 5
fds = {}


def _parse_flags(flags:int):
    all_possible_flags = {k[2:]:v for k, v in vars(os).items() if isinstance(v, int) and k.startswith("O_")}
    return [flag for flag, v in all_possible_flags.items() if flags & v]

def _open(ql: Qiling, hook_data):
    global fds, fd_counter
    p = ql.os.resolve_fcall_params(
        {
            "path": STRING,
            "flags": INT,
        }
    )
    
    path = p["path"]
    flags = p["flags"]
    parsed_flags = _parse_flags(flags)
    ql.log.info(f"{hook_data.func_name} called for {path} ({parsed_flags}) returning fd {fd_counter}")
    
    ql.os.fcall.cc.setReturnValue(fd_counter)
    fds[fd_counter] = path
    fd_counter += 1
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _write(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT, "buf": POINTER, "len": INT})
    fd = p["fd"]
    if fd not in fds:
        if hook_data.emu.tee == "optee":
            ql.log.info(f"write: fd {fd}")
            if fd == 2:
                buf = p["buf"]
                lenn = p["len"]
                data = ql.mem.read(buf, lenn)
                ql.log.info(f"[optee write to stderr] {data}")
                ql.os.fcall.cc.setReturnValue(p["len"])
                ql.arch.regs.arch_pc = ql.arch.regs.lr
                return
        else:
            ql.log.warning(f"fd {fd} not in {fds}")
            crash(ql, hook_data.func_name)
            return
    if fds[fd] == "/dev/kmsg":
        ql.os.fcall.cc.setReturnValue(p["len"])
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f'write on unknown device {fds[fd]}: discarding {p["len"]} bytes')
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f'write on unknown device: {fds[fd]}')
            return
        # benign default: pretend the write succeeded and return to the caller
        # (previously fell through without setting a result or advancing PC)
        ql.os.fcall.cc.setReturnValue(p["len"])
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def _close(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT})
    fd = p["fd"]
    if fd not in fds:
        ql.log.warning(f"fd {fd} not in {fds}")
        crash(ql, hook_data.func_name)
        return
    del fds[fd]
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# --- TEEGRIS driver-client I/O ----------------------------------------------
# TEEGRIS TAs talk to kernel drivers (/dev/iccc_driver, /dev/pa_driver,
# /dev/vk_driver, /dev/crypto_manager, ...) through the libc-style
# open()/ioctl()/read()/write()/close() wrappers that libteesl exposes as
# drv_client_*.  Without an ioctl/read model the *create* path of every driver
# TA (STST, vltkpr, ...) dies the moment it issues its first ioctl -- before a
# single command can be driven.  We model the driver client benignly: open
# hands out an fd (already done above), ioctl/read succeed and return zeroed
# data.  For the common "read a config/phys cell" ioctl this yields an
# all-zero cell, which is the unprovisioned / nothing-set state the create
# path treats as success (e.g. STST's Iccc_phys_read -> flags clear).  Devices
# that need a non-zero answer can register a handler in IOCTL_HANDLERS.

# Per-device ioctl handlers: dev-path-substring -> fn(ql, fd, request, argp) -> int.
# Return an int to use as the ioctl() result; the handler is responsible for
# writing any out-data into argp.  Absent/None handler => benign success (0).
IOCTL_HANDLERS = {}
# NB: the corpus Knox TAs (KEYMST, vltkpr, knxgud) authenticate the caller via
# the /dev/pa_driver PROCA ioctl, not TEE_OpenTASession. The driver writes a
# build-specific verdict struct that the TA reads back; the corpus build maps
# the unmodelled-driver case to its own failure code (knxgud: "PROCA
# Authentication is failed. : 100006"), and the soft-pass codes / struct offsets
# differ from the RE writeup's build. Soft-passing it therefore needs a per-TA
# inline hook on the authenticate function (the pattern vltkpr already uses,
# vltkpr_authenticate_ca_softpass), not a generic ioctl model -- writing a
# guessed verdict through the request pointer risks corrupting live TA state.

def _ioctl_dispatch(ql: Qiling, fd, request, argp):
    dev = fds.get(fd, "")
    for needle, handler in IOCTL_HANDLERS.items():
        if needle in dev:
            return handler(ql, fd, request, argp)
    return 0

def ioctl(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT, "request": INT, "argp": POINTER})
    fd = p["fd"]
    request = p["request"]
    argp = p["argp"]
    dev = fds.get(fd, "<unknown-fd>")
    try:
        ret = _ioctl_dispatch(ql, fd, request, argp)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(
        f"ioctl(fd={fd} dev={dev} request={hex(request)} argp={hex(argp)}) -> {ret} "
        f"(driver-client stub)"
    )
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def _read(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT, "buf": POINTER, "len": INT})
    fd = p["fd"]
    buf = p["buf"]
    length = p["len"]
    dev = fds.get(fd, "<unknown-fd>")
    # A device/file the create path opened returns benign zeros (an unmodeled
    # driver / /dev/random surrogate).  Cap the fill so a bogus length can't
    # blow up, and report exactly that many bytes "read".
    n = max(0, min(length, 0x10000))
    if buf and n:
        try:
            ql.mem.write(buf, b"\x00" * n)
        except unicorn.unicorn_py3.unicorn.UcError:
            crash(ql, hook_data.func_name)
            return
    ql.log.info(f"read(fd={fd} dev={dev} len={length}) -> {n} zero bytes (stub)")
    ql.os.fcall.cc.setReturnValue(n)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# --- socket-family stubs ----------------------------------------------------
# A few TEEGRIS TAs reach an external peer over a unix/local socket: SEMeSE
# (eSE APDU bridge: socket/select/send/recv), spidrv (socket at driver-init),
# knxgud (send).  The peer is not modeled, so the goal is only to keep boot
# alive and let the TA take its own timeout / error path rather than die at an
# unimplemented import.  socket() hands out an fd via the same table as
# open(); the wait primitives report "nothing ready" so the TA does not block
# forever on a reply that will never come.

def socket(ql: Qiling, hook_data):
    global fds, fd_counter
    ql.os.fcall.cc.setReturnValue(fd_counter)
    fds[fd_counter] = f"socket:{fd_counter}"
    ql.log.info(f"socket() -> fd {fd_counter} (stub)")
    fd_counter += 1
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def connect(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def bind(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def listen(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def accept(ql: Qiling, hook_data):
    # No incoming connection in the model.
    ql.os.fcall.cc.setReturnValue(-1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def socketpair(ql: Qiling, hook_data):
    # socketpair(domain, type, protocol, int sv[2]) -> two connected fds.
    global fds, fd_counter
    p = ql.os.resolve_fcall_params({"domain": INT, "type": INT, "protocol": INT, "sv": POINTER})
    a, b = fd_counter, fd_counter + 1
    fds[a] = f"socketpair:{a}"
    fds[b] = f"socketpair:{b}"
    fd_counter += 2
    try:
        ql.mem.write(p["sv"], a.to_bytes(4, "little") + b.to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"socketpair() -> fds ({a},{b}) (stub)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def send(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT, "buf": POINTER, "len": INT})
    ql.log.info(f"send(fd={p['fd']} len={p['len']}) -> {p['len']} (stub, discarded)")
    ql.os.fcall.cc.setReturnValue(p["len"])
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def recv(ql: Qiling, hook_data):
    # No peer data -> 0 = orderly shutdown / no bytes.
    ql.log.info(f"recv() -> 0 (stub, no peer)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def select(ql: Qiling, hook_data):
    # 0 = timeout, nothing ready (no peer is modeled).
    ql.log.info(f"select() -> 0 (stub, timeout)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def poll(ql: Qiling, hook_data):
    ql.log.info(f"poll() -> 0 (stub, timeout)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def epoll_create(ql: Qiling, hook_data):
    global fds, fd_counter
    ql.os.fcall.cc.setReturnValue(fd_counter)
    fds[fd_counter] = f"epoll:{fd_counter}"
    ql.log.info(f"epoll_create() -> fd {fd_counter} (stub)")
    fd_counter += 1
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def epoll_create1(ql: Qiling, hook_data):
    epoll_create(ql, hook_data)

def epoll_ctl(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def epoll_wait(ql: Qiling, hook_data):
    # 0 = no events ready before timeout (no peer is modeled).
    ql.log.info(f"epoll_wait() -> 0 (stub, no events)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def eventfd(ql: Qiling, hook_data):
    global fds, fd_counter
    ql.os.fcall.cc.setReturnValue(fd_counter)
    fds[fd_counter] = f"eventfd:{fd_counter}"
    fd_counter += 1
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# --- pthread ----------------------------------------------------------------
# The emulator runs a single guest thread, so mutexes/cond-vars/rwlocks are
# uncontended no-ops. TIdspl/TIthLl (and others) take a pthread_mutex_lock in
# TA_OpenSessionEntryPoint, so without these the TA dies in OpenSession and is
# never drivable -- it boots (Create) but can't be invoked. pthread_create is a
# no-op that does NOT run the thread body (no threading model); fine for TAs
# whose worker thread is not on the critical create/open/invoke path.

def _ok0(ql):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def pthread_mutex_lock(ql: Qiling, hook_data):       _ok0(ql)
def pthread_mutex_unlock(ql: Qiling, hook_data):     _ok0(ql)
def pthread_mutex_trylock(ql: Qiling, hook_data):    _ok0(ql)
def pthread_mutex_init(ql: Qiling, hook_data):       _ok0(ql)
def pthread_mutex_destroy(ql: Qiling, hook_data):    _ok0(ql)
def pthread_mutexattr_init(ql: Qiling, hook_data):   _ok0(ql)
def pthread_mutexattr_destroy(ql: Qiling, hook_data): _ok0(ql)
def pthread_mutexattr_settype(ql: Qiling, hook_data): _ok0(ql)
def pthread_cond_init(ql: Qiling, hook_data):        _ok0(ql)
def pthread_cond_destroy(ql: Qiling, hook_data):     _ok0(ql)
def pthread_cond_signal(ql: Qiling, hook_data):      _ok0(ql)
def pthread_cond_broadcast(ql: Qiling, hook_data):   _ok0(ql)
def pthread_cond_wait(ql: Qiling, hook_data):        _ok0(ql)
def pthread_cond_timedwait(ql: Qiling, hook_data):   _ok0(ql)
def pthread_rwlock_init(ql: Qiling, hook_data):      _ok0(ql)
def pthread_rwlock_destroy(ql: Qiling, hook_data):   _ok0(ql)
def pthread_rwlock_rdlock(ql: Qiling, hook_data):    _ok0(ql)
def pthread_rwlock_wrlock(ql: Qiling, hook_data):    _ok0(ql)
def pthread_rwlock_unlock(ql: Qiling, hook_data):    _ok0(ql)

def pthread_self(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1)   # a single fixed thread id
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# --- process / thread identity ----------------------------------------------
# Fixed identities for the single emulated TA process.
def getpid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1337)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def gettid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1337)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def getuid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def geteuid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def getgid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def getegid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def pthread_create(ql: Qiling, hook_data):
    # No threading model: don't run the start routine, just report success so
    # the caller proceeds. (Worker threads that ARE the only consumer of their
    # work won't run -- acceptable for create/open/invoke-path verification.)
    ql.log.warning("pthread_create: stubbed, thread body NOT run")
    _ok0(ql)

def pthread_join(ql: Qiling, hook_data):    _ok0(ql)
def pthread_detach(ql: Qiling, hook_data):  _ok0(ql)

def pthread_once(ql: Qiling, hook_data):
    # Faithfully run a one-time init: if not yet done, set the flag and
    # tail-call init_routine with lr unchanged so it RETs to our caller (a
    # plain redirect, no separate stack frame needed). A no-op here would skip
    # initialization the TA relies on.
    p = ql.os.resolve_fcall_params({"once": POINTER, "init": POINTER})
    once, init = p["once"], p["init"]
    done = 0
    try:
        done = int.from_bytes(ql.mem.read(once, 4), "little")
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    if done != 0 or not init:
        _ok0(ql)
        return
    try:
        ql.mem.write(once, (1).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    ql.log.info(f"pthread_once -> running init_routine {hex(init)}")
    ql.arch.regs.arch_pc = init   # lr still points at pthread_once's caller


# --- errno / mmap / driver registration -------------------------------------
# A handful of TEEGRIS TAs touch plain libc/runtime primitives during their
# create path that the emulator did not model, so they died at boot before any
# command could be driven: get_errno_addr (HvAUtW), mmap (fingerprint), and the
# driver-registration TEES_RegisterDriver{Constructor,Destructor} (Mps* driver
# TAs). These are runtime plumbing, not security-relevant logic -- model them
# benignly so the TA reaches TA_InvokeCommandEntryPoint.

_errno_addr = None

def get_errno_addr(ql: Qiling, hook_data):
    # libc get_errno_addr()/__errno_location() returns a stable int* the TA
    # reads/writes errno through. Back it with a single page mapped on first use.
    global _errno_addr
    if _errno_addr is None:
        _errno_addr = ql.mem.map_anywhere(0x1000, minaddr=0x70000, perms=UC_PROT_READ | UC_PROT_WRITE, info="errno")
        ql.mem.write(_errno_addr, b"\x00" * 8)
    ql.os.fcall.cc.setReturnValue(_errno_addr)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def __errno_location(ql: Qiling, hook_data):
    get_errno_addr(ql, hook_data)

def mmap(ql: Qiling, hook_data):
    # Anonymous-only mmap model: ignore the addr hint / fd, hand back a fresh
    # zero-filled region of the requested length with prot-derived perms.
    p = ql.os.resolve_fcall_params(
        {"addr": POINTER, "length": INT, "prot": INT, "flags": INT, "fd": INT, "offset": INT}
    )
    length = p["length"]
    if length <= 0 or length > 0x10000000:
        ql.os.fcall.cc.setReturnValue(0xFFFFFFFFFFFFFFFF)  # MAP_FAILED
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    size = (length + 0xFFF) & ~0xFFF
    prot = p["prot"]
    perms = 0
    if prot & 1:
        perms |= UC_PROT_READ
    if prot & 2:
        perms |= UC_PROT_WRITE
    if prot & 4:
        perms |= UC_PROT_EXEC
    if perms == 0:
        perms = UC_PROT_READ | UC_PROT_WRITE
    try:
        addr = ql.mem.map_anywhere(size, minaddr=0x50000000, perms=perms, info="mmap")
    except Exception as e:
        ql.log.warning(f"mmap(len={hex(length)}) failed: {e}")
        ql.os.fcall.cc.setReturnValue(0xFFFFFFFFFFFFFFFF)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    ql.log.info(f"mmap(len={hex(length)} prot={hex(prot)}) -> {hex(addr)} (anon, {hex(size)}B)")
    ql.os.fcall.cc.setReturnValue(addr)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def munmap(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"addr": POINTER, "length": INT})
    try:
        size = (p["length"] + 0xFFF) & ~0xFFF
        ql.mem.unmap(p["addr"] & ~0xFFF, size)
    except Exception:
        pass  # best-effort; unmapping an unknown region is harmless here
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_RegisterDriverConstructor(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_RegisterDriverDestructor(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_WrapSecureObject(ql: Qiling, hook_data):
    # Pair to the existing TEES_UnwrapSecureObject stub; returns success so the
    # wrap path proceeds (no real secure-object cryptography is modeled).
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def teegris_log_encrypt(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def OPENSSL_malloc(ql: Qiling, hook_data):
    size = ql.os.resolve_fcall_params({"size": INT})["size"]
    malloc_core(ql, size, hook_data, False)

def OPENSSL_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    free_core(ql, ptr, hook_data, False)


def EVP_PKEY_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def EC_KEY_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def EC_POINT_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def TEES_RPMBCheckEnable(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_RPMBRead(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def hdm_ICCC_check(ql: Qiling, hook_data):
    ql.log.info(f"hooking hdm ICCC Check, returning expected value")
    ql.os.fcall.cc.setReturnValue(0x19)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def mpos_ICCC_check(ql: Qiling, hook_data):
    ql.log.info(f"hooking hdm ICCC Check, returning expected value")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def nanosleep(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TA_Communication_mpos_check_iccc(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"result": POINTER})["result"]
    ql.mem.write(p, (0).to_bytes(4, "little"))
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_TUIOpenSession(ql, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_TUIDrawImage(ql, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
