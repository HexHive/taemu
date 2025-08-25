import os
import argparse
import json

from pwn import ELF
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

from .emulator_no_loader import simple_diassembler, trace_block, simple_diassembler, hook_ta_dl, fixup_got, hook_ta_custom, setup_tls
from .ta_mgr import start

DIR = dir_path = os.path.dirname(os.path.realpath(__file__))
TEE = ""

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
    parser.add_argument(
        "--tee",
        help="specify the TEE.",
        required=False,
        default="beanpod"
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

    if b"TEEGRIS" in open(ta_path, "rb").read():
        TEE = "teegris"
    elif b"rom/libld-l4.so" in open(ta_path, "rb").read():
        TEE = "beanpod"
    elif b"ld.so.1" in open(ta_path, "rb").read():
        TEE = "mitee"
    if TEE == "":
        TEE = args.tee

    if TEE == "beanpod":
        ql = Qiling(
            [ta_path],
            rootfs=os.path.join(DIR, "../rootfs/"),
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            thumb=True,
            env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql"
        )
    elif TEE == "teegris":
        print("doing teegris")
        ql = Qiling(
            [ta_path],
            rootfs=os.path.join(DIR, "../rootfs/"),
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "lib64"},
            profile="tee.ql"
        )
    elif TEE == "mitee":
        print("doing mitee")
        ql = Qiling(
            [ta_path],
            rootfs=os.path.join(DIR, "../rootfs/"),
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/"},
            profile="tee.ql"
        )
    else:
        print(f'[!] TEE not set  [!]')
        exit(-1)

    if args.gdb:
        ql.debugger = True
    if args.disas:
        ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
    if args.trace:
        ql.hook_block(trace_block)
    # start emulation
    fixup_got(ql, ta_path, ta_elf)
    hook_ta_dl(ql, ta_path, ta_elf)
    hook_ta_custom(ql, ta_path, ta_elf)
    if TEE == "mitee":
        # handle tpidr_el0
        setup_tls(ql, ta_path, ta_elf)
    ql.do_lib_patch()
    ql.log.info(f"[{ta_name}] emulation start")
    start(ql, ta_name, TEE)
    ql.log.info(f"[{ta_name}] emulation end")
