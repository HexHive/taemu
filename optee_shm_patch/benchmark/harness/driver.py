#!/usr/bin/env python3
"""Boot OP-TEE under QEMU and drive the SHM-mitigation benchmark.

Two sweeps:
  * size sweep     : work=0, buffer size varied
  * workload sweep : buffer size fixed, per-call TA workload varied

RESULT line from the host binary (all integers):
  RESULT,which,cmd,size,iters,work,total_ns,mean_ns,min_ns,median_ns
"""
import os
import re
import sys
import pexpect

# Paths are taken from the environment (with sensible defaults) so this can be
# run outside the session it was authored in:
#   OPTEE_DIR : the built OP-TEE tree (contains qemu/, out/bin/, out-br/)
#   BENCH_OUT : build output dir produced by build.sh (contains run/ and share/)
OPTEE_DIR = os.environ.get("OPTEE_DIR", "/home/philipp/taemu/df/optee")
BENCH_OUT = os.environ.get(
    "BENCH_OUT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "out"))
RUN = f"{BENCH_OUT}/run"
SHARE = f"{BENCH_OUT}/share"
RESULTS_CSV = os.environ.get("RESULTS_CSV", f"{BENCH_OUT}/results_v2.csv")
QEMU = f"{OPTEE_DIR}/qemu/build/qemu-system-aarch64"

QEMU_ARGS = [
    "-L", f"{OPTEE_DIR}/qemu/pc-bios",
    "-nographic",
    "-smp", "2",
    "-cpu", "max,sme=off,pauth-impdef=on",
    "-d", "unimp",
    "-semihosting-config", "enable=on,target=native",
    "-m", "1057",
    "-bios", "bl1.bin",
    "-initrd", "rootfs.cpio.gz",
    "-kernel", "Image",
    "-append", "console=ttyAMA0,38400 keep_bootcon root=/dev/vda2",
    "-machine", "virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false",
    "-object", "rng-random,filename=/dev/urandom,id=rng0",
    "-device", "virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000",
    "-fsdev", f"local,id=fsdev0,path={SHARE},security_model=none",
    "-device", "virtio-9p-device,fsdev=fsdev0,mount_tag=host",
    "-serial", "mon:stdio",
    "-serial", f"file:{RUN}/sw.log",
]

# (which, cmd, label)
CONFIGS = [(0, 0, "baseline"), (1, 1, "mitig_shared"), (1, 0, "mitig_copied")]
SIZES = [64, 256, 1024, 4096, 16384, 65536]            # size sweep (work=0)
WORK_SIZE = 4096                                        # workload sweep buffer
WORKLOADS = [0, 20000, 100000, 500000, 2000000, 8000000]
ITERS = 3000          # size sweep: fast calls, many samples
WORK_ITERS = 400      # workload sweep: slower calls, fewer samples
WARMUP = 300
WORK_WARMUP = 40

RESULT_RE = re.compile(r"RESULT," + ",".join([r"[0-9]+"] * 9))


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    smoke = "--smoke" in sys.argv
    # points: (sweep, size, work, iters, warmup)
    if smoke:
        points = [("size", 4096, 0, 50, 20)]
        points += [("work", WORK_SIZE, w, 50, 20) for w in (0, 500000)]
    else:
        points = [("size", s, 0, ITERS, WARMUP) for s in SIZES]
        points += [("work", WORK_SIZE, w, WORK_ITERS, WORK_WARMUP)
                   for w in WORKLOADS]

    os.chdir(RUN)
    child = pexpect.spawn(QEMU, QEMU_ARGS, encoding="utf-8", timeout=240)
    child.logfile_read = sys.stdout

    child.expect(r"ogin:", timeout=240)
    child.sendline("root")
    child.expect_exact("# ")
    print("\n=== BOOTED ===")

    child.sendline("mkdir -p /mnt/h && "
                   "mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/h && "
                   "ls /mnt/h/ && echo LSDONE")
    child.expect_exact("LSDONE")
    child.expect_exact("# ")

    child.sendline("cp /mnt/h/*.ta /lib/optee_armtz/ && "
                   "cp /mnt/h/optee_shm_bench /root/ && "
                   "chmod +x /root/optee_shm_bench && echo CPDONE")
    child.expect_exact("CPDONE")
    child.expect_exact("# ")

    results = []
    for sweep, size, work, iters, warmup in points:
        for which, cmd, label in CONFIGS:
            child.sendline(f"/root/optee_shm_bench {which} {cmd} {size} "
                          f"{iters} {warmup} {work}")
            child.expect_exact("# ", timeout=600)
            m = RESULT_RE.search(child.before)
            if not m:
                print(f"\n!!! bench error: {label} size={size} work={work}")
                continue
            results.append((sweep, label, m.group(0).strip()))

    print("\n\n===== COLLECTED RESULTS =====")
    with open(RESULTS_CSV, "w") as f:
        f.write("sweep,label,tag,which,cmd,size,iters,work,"
                "total_ns,mean_ns,min_ns,median_ns\n")
        for sweep, label, line in results:
            print(f"{sweep},{label},{line}")
            f.write(f"{sweep},{label},{line}\n")

    child.sendline("poweroff -f")
    try:
        child.expect(pexpect.EOF, timeout=60)
    except pexpect.TIMEOUT:
        child.terminate(force=True)
    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
