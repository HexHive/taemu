import os
import argparse
import json

from pwn import ELF
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE


from .emulator_no_loader import simple_diassembler, hook_ta_plt, trace_block, simple_diassembler, hook_ta_dl
from .beanpod_ta import start

DIR = dir_path = os.path.dirname(os.path.realpath(__file__))

def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    # add flags
    parser.add_argument(
        "-g",
        "--gdb",
        action="store_true",
        help="Debug the target.",
    )
    parser.add_argument(
        "-d",
        "--disas",
        action="store_true",
        help="Disassemble the target.",
    )
    parser.add_argument(
        "-t",
        "--trace",
        action="store_true",
        help="Trace the target.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose mode output.",
    )
        
    parser.add_argument("ta", help="The Trusted Application to be executed.")

    return parser


if __name__ == "__main__":

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    ta_name = args.ta
    ta_path = ta_name
    ta_elf = ELF(ta_path)

    if args.verbose:
        v = QL_VERBOSE.DEBUG
    else:
        v = QL_VERBOSE.DEFAULT

    ql = Qiling(
        [ta_path],
        rootfs=os.path.join(DIR, "../rootfs/"),
        ostype=QL_OS.LINUX,
        archtype=QL_ARCH.ARM,
        verbose=v,
        thumb=True,
        env={"LD_LIBRARY_PATH": "rom"},
        profile="beanpod.ql"
    )

    if args.gdb:
        ql.debugger = True
    if args.disas:
        ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
    if args.trace:
        ql.hook_block(trace_block)
    # you're drunk qiling
    ql.mem.protect(0x7ff0d000, 0x00030000, 3)
    # flag
    if os.path.exists("/srv/flag1.txt"):
        flag = open("/srv/flag1.txt").read()
    else:
        flag = "EPFL{emulatorflag}"
    ql.mem.map(0x61a000, 0x1000, perms=3, info="flag")
    ql.mem.write(0x61a000, flag.encode() + b"\x00")
    # start emulation
    hook_ta_dl(ql, ta_path, ta_elf)
    ql.do_lib_patch()
    ql.log.info(f"[{ta_name}] emulation start")
    start(ql, ta_name)
    ql.log.info(f"[{ta_name}] emulation end")
