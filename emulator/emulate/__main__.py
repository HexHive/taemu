from multiprocessing import Process
import os
import argparse

from pwn import ELF

# from qiling import Qiling
from .qiling_extend import QilingExtend as Qiling
from .redis_queue import create_redis_queue
from qiling.const import QL_STOP, QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from .fuzz_record import SimpleFilterRecorder, Record
from .redis_queue import RedisQueue
from .emulator_no_loader import simple_diassembler, trace_block, simple_diassembler, unicorn_why
from .ta_mgr import TAEMU, Status
from .custom.tc_loader import tc_load
from concurrent_log_handler import ConcurrentRotatingFileHandler


DIR = dir_path = os.path.dirname(os.path.realpath(__file__))
ROOTFS_PATH = os.path.join(DIR, "../rootfs")
TEE = ""

def to_int(x):
    return int(x, 0)

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
        default=None,
    )
    parser.add_argument(
        "-dff",
        "--df_fuzz",
        required=False,
        help="fuzz a double fetch with provided file",
        default=None
    )
    parser.add_argument(
        "--df_reg_hash",
        required=False,
        type=to_int,
        help="hash of registers at the point where double fetch is happening",
        default=None
    )
    parser.add_argument(
        "--df_seed",
        required=False,
        help="path to seed that triggered the double fetch",
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
        "--sus_in_replay",
        required=False,
        help="replay sus input",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--df_replay",
        required=False,
        help="path to replay df seed",
        default=None,
    )
    parser.add_argument(
        "--df_validate",
        required=False,
        help="path to replay+validate df seed",
        default=None
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose mode output.",
    )
    parser.add_argument(
        "--log_file", required=False, help="Log output to specified file.", default=None
    )
    parser.add_argument(
        "--tee", help="specify the TEE.", required=False, default=""
    )
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="Use cache for loading state after execution of entrypoint(s).",
        default=False,
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

    custom_logger = None
    if args.log_file:
        print(f"[+] Logging to {args.log_file} [+]")
        import logging

        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                ConcurrentRotatingFileHandler(
                    args.log_file,
                    mode="a",
                    maxBytes=10 * 1024 * 1024,
                    backupCount=2,
                    encoding="utf-8",
                ),
                logging.StreamHandler(),
            ],
        )
        custom_logger = logging.getLogger()

    if args.tee != "":
        TEE = args.tee
    elif b"TEEGRIS" in open(ta_path, "rb").read():
        TEE = "teegris"
    elif b"optee" in open(ta_path, "rb").read() and b"ta_head" in open(ta_path, "rb").read():
        TEE = "optee"
    elif b"rom/libld-l4.so" in open(ta_path, "rb").read():
        TEE = "beanpod"
    elif b"ld.so.1" in open(ta_path, "rb").read():
        TEE = "mitee"
    elif b"ta_head" in open(ta_path, "rb").read():
        TEE = "t6"
    elif b"com.huawei.hidisk" in open(ta_path, "rb").read():
        TEE = "trustedcore"
    elif b"GPAppLib_handleRequest" in open(ta_path, "rb").read():
        if b"CElfFile_invoke" in open(ta_path, "rb").read():
            TEE = "qsee_nongp"
        else:
            TEE = "qsee"
    print(f"[+] TEE: {TEE} [+]")
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
            profile="tee.ql",
            log_override=custom_logger,
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
                profile="tee.ql",
                log_override=custom_logger,
            )
        else:
            ql = Qiling(
                [ta_path],
                rootfs=ROOTFS_PATH,
                ostype=QL_OS.LINUX,
                archtype=QL_ARCH.ARM,
                verbose=v,
                env={"LD_LIBRARY_PATH": "lib64"},
                profile="tee.ql",
                log_override=custom_logger,
            )
    elif TEE == "mitee":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/:/lib64"},
            profile="tee.ql",
            log_override=custom_logger,
        )
    elif TEE == "qsee" or TEE == "qsee_nongp":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM64,
            verbose=v,
            env={"LD_LIBRARY_PATH": "/"},
            profile="tee.ql",
            stop=QL_STOP.EXIT_TRAP,
            log_override=custom_logger,
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
            log_override=custom_logger,
        )
    elif TEE == "t6":
        if ta_elf.header["e_flags"] & 0x200 == 0:
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
            # env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql",
            log_override=custom_logger,
        )
    elif TEE == "trustedcore":
        ql = Qiling(
            [ta_path],
            rootfs=ROOTFS_PATH,
            ostype=QL_OS.LINUX,
            archtype=QL_ARCH.ARM,
            verbose=v,
            # env={"LD_LIBRARY_PATH": "rom"},
            profile="tee.ql",
            log_override=custom_logger,
        )
        tc_load(ql, ta_path)
    else:
        print(f"[!] TEE not set  [!]")
        exit(-1)

    if args.gdb:
        ql.debugger = True
    if args.disas:
        ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
    if args.trace:
        ql.hook_block(trace_block)
    if args.sus_in_replay:
        ql.hook_code(unicorn_why)
        
    
    if args.fuzz or args.fuzz_replay:
        # Create Redis queue
        try:
            record_q: RedisQueue = create_redis_queue(
                queue_name="ta_emulator_queue_{}_{}".format(os.path.basename(os.path.dirname(args.fuzz_harness)), os.path.basename(ta_path)[:-3]),
                redis_host=os.environ.get("REDIS_HOST", "localhost"),
                redis_port=int(os.environ.get("REDIS_PORT", "6379")),
                redis_db=int(os.environ.get("REDIS_DB", "0")),
                logger=custom_logger,
            )
        except Exception as e:
            print(
                f"[+] Error creating Redis queue: {e}; Disable recording feature... [+]"
            )
            record_q = None
    else:
        record_q = None
        
        
    def launch_taemu(curr_record_q):
        print(
            f"[+] Loaded TA {ta_name} for TEE {TEE} with Qiling {ql.arch.type}/{ql.os.type}"
        )
        with TAEMU(
            ql,
            TEE,
            ta_path,
            ta_elf,
            status=(
                Status.FUZZING
                if args.fuzz
                else Status.REPLAYING if args.fuzz_replay 
                else Status.DF_FUZZING if args.df_fuzz
                else Status.DF_REPLAY if args.df_replay
                else Status.DF_VALIDATE if args.df_validate
                else Status.INTERACTIVE
            ),
            record_q=curr_record_q,
            use_cache=args.use_cache,
        ) as emu:
            try:
                print(args.df_validate)
                emu.start(
                    args.fuzz or args.fuzz_replay or args.df_fuzz or args.df_replay or args.df_validate, 
                    args.fuzz_harness,
                    args.df_seed,
                    args.df_reg_hash
                    )
            except KeyboardInterrupt:
                print("[+] Keyboard interrupt received...")
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"[+] Error occurred: {e}")


    def launch_recorder(curr_record_q):
        if curr_record_q is None:
            print(f"[+] Recorder is disabled and stopped automatically... [+]")
            return
        

        suspicious_seeds_save_dir = os.path.join(
            os.path.dirname(args.fuzz_harness),
            "in/suspicious_inputs" + ("_replay" if args.fuzz_replay else ""),
        )
        if not os.path.exists(suspicious_seeds_save_dir):
            os.makedirs(suspicious_seeds_save_dir)

        print(f"[+] Saving suspicious inputs at dir: {suspicious_seeds_save_dir}")

        record_meta_dir = os.path.join(
            os.path.dirname(args.fuzz_harness),
            "record_meta"
        ) if args.fuzz else None

        if record_meta_dir is not None and not os.path.exists(record_meta_dir):
            os.makedirs(record_meta_dir)

        with SimpleFilterRecorder(
            curr_record_q, suspicious_seeds_save_dir, record_meta_dir, custom_logger
        ) as recorder:
            recorder.start()


    print("[+] Starting all the processes... [+]")
    p1 = Process(target=launch_taemu, args=(record_q,))
    p1.start()

    p2 = Process(target=launch_recorder, args=(record_q,))
    p2.start()

    print(f"[+] children pids {p1.pid}, {p2.pid}")

    p1.join()
    print(f"[+] TAEMU process stopped (exit code: {p1.exitcode})")

    if record_q:
        print(f"[+] Sending STOP message to recorder process...")
        record_q.put("STOP")

    p2.join(timeout=15.0)

    if p2.is_alive():
        p2.terminate()
        p2.join(timeout=5.0)
        if p2.is_alive():
            p2.kill()
            p2.join()

    if record_q:
        record_q.close()
    print(f"[+] Recorder process stopped (exit code: {p2.exitcode})")

    print("[+] Exiting all the procedures completed successfully. [+]")
