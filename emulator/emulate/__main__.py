import os
import argparse
import json

from pwn import ELF
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

from .emulator_no_loader import simple_diassembler, trace_block, simple_diassembler
from .ta_mgr import TAEMU

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
        "-f",
        "--fuzz",
        required=False,
        help="Fuzz the target with provided file.",
        default=None
    )
    parser.add_argument(
        "--fuzz_harness",
        required=False,
        help="path to fuzzing harness",
        default=None,
    )
    parser.add_argument(
        "--fuzz_replay",
        required=False,
        help="path to fuzz replay seed",
        default=None,
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
    elif b"ta_head" in open(ta_path, "rb").read():
        TEE = "t6"
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
    elif TEE == "t6":
        ql = Qiling(
            [ta_path],
            rootfs=os.path.join(DIR, "../rootfs/"),
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            thumb=True,
            #env={"LD_LIBRARY_PATH": "rom"},
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
    emu = TAEMU(ql, TEE, ta_path, ta_elf)
    emu.setup()
    emu.hook()
    if args.fuzz:
        ql.log.info(f"[{ta_name}] fuzz start")
        emu.start_fuzz(args.fuzz, args.fuzz_harness)
        ql.log.info(f"[{ta_name}] fuzz end")
    if args.fuzz_replay:
        ql.log.info(f"[{ta_name}] fuzz replay start")
        emu.start_fuzz(args.fuzz_replay, args.fuzz_harness, fuzz_replay=True)
        ql.log.info(f"[{ta_name}] fuzz replay end")
    else:
        ql.log.info(f"[{ta_name}] emulation start")
        emu.start_interactive()
        ql.log.info(f"[{ta_name}] emulation end")
