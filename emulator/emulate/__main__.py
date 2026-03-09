import os
from multiprocessing import Process
import argparse

from pwn import ELF
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

from .emulator_no_loader import simple_diassembler, trace_block, simple_diassembler
from .ta_mgr import TAEMU, Status
from .custom.tc_loader import tc_load

DIR = dir_path = os.path.dirname(os.path.realpath(__file__))
ROOTFS_PATH = os.path.join(DIR, "../rootfs")
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
        required=True,
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
    parser.add_argument(
        "--no_std_apis",
        help="don't hook standard (GP and libc) APIs",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--no_tee_apis",
        help="don't hook standard TEE specific APIs",
        default=False,
        action="store_true"
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
    elif b"optee" in open(ta_path, "rb").read() and b"ta_head" in open(ta_path, "rb").read():
        TEE = "optee"
    elif b"com.huawei.hidisk" in open(ta_path, "rb").read():
        TEE = "trustedcore"
    elif b"GPAppLib_handleRequest" in open(ta_path, "rb").read():
        TEE = "qsee"
    if TEE == "":
        TEE = args.tee

    if TEE == "beanpod":
        if ta_elf.header["e_flags"] & 0x200 == 0:
            is_thumb = True
        else:
            is_thumb = False
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            thumb=is_thumb,
            env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql"
        )
    elif TEE == "teegris":
        print("doing teegris", ta_elf.arch)
        if ta_elf.arch == "aarch64":
            ql = Qiling(
                [ta_path],
                rootfs=ROOTFS_PATH,
                ostype=QL_OS.LINUX,
                archtype=QL_ARCH.ARM64,
                verbose=v,
                env={"LD_LIBRARY_PATH": "lib64"},
                profile="tee.ql"
            )
        else:
           ql = Qiling(
                [ta_path],
                rootfs=ROOTFS_PATH,
                ostype=QL_OS.LINUX,
                archtype=QL_ARCH.ARM,
                verbose=v,
                env={"LD_LIBRARY_PATH": "lib64"},
                profile="tee.ql"
            ) 
    elif TEE == "mitee":
        print("doing mitee")
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/"},
            profile="tee.ql"
        )
    elif TEE == "qsee":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/"},
            profile="tee.ql",
        )
    elif TEE == "optee":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/"},
            profile="tee.ql",
        )
    elif TEE == "t6":
        if ta_elf.header['e_flags'] & 0x200 == 0:
            is_thumb = False
        else:
            is_thumb = True
        if "face1d41-2636-11e1-ad9e0002a5d6c51b" in ta_path:
            is_thumb = False
        if "edcf9395-3518-9067-614cafae2909775b" in ta_path:
            is_thumb = False
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            thumb=is_thumb,
            #env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql"
        )
    elif TEE == "trustedcore":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            #env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql"
        )
        tc_load(ql, ta_path)
    else:
        print(f'[!] TEE not set  [!]')
        exit(-1)

    if args.gdb:
        ql.debugger = True
    if args.disas:
        ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
    if args.trace:
        ql.hook_block(trace_block)

    std_apis = True
    tee_apis = True
    if args.no_std_apis:
        std_apis = False
    if args.no_tee_apis:
        tee_apis = False

    def launch_taemu():
        print(
            f"[+] Loaded TA {ta_name} for TEE {TEE} with Qiling {ql.arch.type}/{ql.os.type}"
        )
        with TAEMU(
            ql,
            TEE,
            ta_path,
            ta_elf,
            status=(
                Status.FUZZING if args.fuzz
                else Status.REPLAYING if args.fuzz_replay 
                else Status.INTERACTIVE
            ),
            std_implemented=std_apis, 
            tee_specific_implemented=tee_apis
        ) as emu:
            try:
                emu.start(
                    args.fuzz or args.fuzz_replay, 
                    args.fuzz_harness
                    )
            #except KeyboardInterrupt:
                #print("[+] Keyboard interrupt received...")
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"[+] Error occurred: {e}")

    launch_taemu()


