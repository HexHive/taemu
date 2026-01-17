import os
from dataclasses import dataclass
import subprocess
import re
from enum import Enum


class FuzzMode(Enum):
    ORG = "ORG"
    DF = "DF"
    ALL = "ALL"


@dataclass(frozen=True)
class RawFuzzingInfo:
    id: str
    tee: str
    ta_name: str
    ta_path: str
    ta_rpath: str
    tee_path: str
    harness_path: str
    fuzz_mode: FuzzMode
    cov_dir: str
    queue_dir: str


class BB:
    def __init__(self, ta, start, size, mod_id):
        self.ta = ta
        self.start = start
        self.size = size
        self.mod_id = mod_id

    def __eq__(self, other):
        return (
            self.start == other.start
            and self.size == other.size
            and self.ta == other.ta
            and self.mod_id == other.mod_id
        )

    def __str__(self):
        return f"BB(ta: {self.ta}, start: {self.start}, size: {self.size}, mod_id: {self.mod_id})"

    def __hash__(self):
        return hash((self.start, self.size, self.ta, self.mod_id))

    def __lt__(self, other):
        return self.start < other.start


def list_tas(path="/root/TA_GP_emulator"):
    return set(
        [
            os.path.join(dir_path, filename)
            for dir_path, _, filenames in os.walk(path)
            for filename in filenames
            if filename.endswith(".ta") and "harness" in dir_path
        ]
    )


def parse_drcov(tee, ta, path):
    bbs_out = []
    raw = open(path, "rb").read()
    ta_base = raw.split(b"timestamp, path\n")[-1]
    for l in ta_base.split(b"\n"):
        if b"emulator/rootfs" in l and b".ta" in l:
            base = l.split(b",")[1]
            base = int(base.decode())
            ta_id = int(l.split(b",")[0])
    nr_bbs = raw.split(b"BB Table: ")[-1]
    nr_bbs = int(nr_bbs.split(b"bbs\n")[0].decode())
    bbs = raw.split(b"bbs\n")[-1]
    for _ in range(nr_bbs):
        start = int.from_bytes(bbs[0:4], "little")
        size = int.from_bytes(bbs[4:6], "little")
        mod_id = int.from_bytes(bbs[6:8], "little")
        if mod_id == ta_id:
            if tee == "beanpod" or tee == "t6":
                start = base + start
            bbs_out.append(BB(ta, start, size, mod_id))
        bbs = bbs[8:]
    return bbs_out

_pattern = re.compile(r"^/root/TA_GP_emulator/(?P<tee>[^/]+)/harness/(?P<harness_name>[^/]+)/(?P<ta_name>.*)$")
def get_fuzzing_basic_info(ta: str, fuzz_mode: FuzzMode) -> list[RawFuzzingInfo]:
    all = []
    match = _pattern.match(ta)
    if match is None:
        raise ValueError(f"Invalid ta path: {ta}")
    
    tee = match.group("tee")
    harness_name = match.group("harness_name")
    ta_name = match.group("ta_name")
    if fuzz_mode == FuzzMode.ORG:
        all.append(
            RawFuzzingInfo(
                id=f"{tee}_{harness_name}",
                tee=tee,
                ta_name=ta_name,
                ta_path=ta,
                ta_rpath=os.path.realpath(ta),
                tee_path=f"/root/TA_GP_emulator/{tee}",
                harness_path=f"/root/TA_GP_emulator/{tee}/harness/{harness_name}",
                fuzz_mode=fuzz_mode,
                cov_dir=f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/out/cov",
                queue_dir=f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/out/default/queue",
            )
        )
    elif fuzz_mode == FuzzMode.DF:
        cov_dir_tmp = "/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz/{df_seed_with_context}/out/cov"
        queue_dir_tmp = "/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz/{df_seed_with_context}/out/default/queue"
        for df_seed_with_context in os.listdir(
            f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz"
        ):
            cov_dir = cov_dir_tmp.format(
                tee=tee,
                harness_name=harness_name,
                df_seed_with_context=df_seed_with_context,
            )

            queue_dir = queue_dir_tmp.format(
                tee=tee,
                harness_name=harness_name,
                df_seed_with_context=df_seed_with_context,
            )

            all.append(
                RawFuzzingInfo(
                    id=f"{tee}_{harness_name}_{df_seed_with_context}",
                    tee=tee,
                    ta_name=ta_name,
                    ta_path=ta,
                    ta_rpath=os.path.realpath(ta),
                    tee_path=f"/root/TA_GP_emulator/{tee}",
                    fuzz_mode=fuzz_mode,
                    harness_path=f"/root/TA_GP_emulator/{tee}/harness/{harness_name}",
                    cov_dir=cov_dir,
                    queue_dir=queue_dir,
                )
            )
    else:
        raise ValueError(f"Invalid fuzz mode: {fuzz_mode}")
    return all


def parse_cov(tee, ta, drcov_path) -> dict[int, list[BB]]:
    out = {}
    for cov_file in os.listdir(drcov_path):
        try:
            timestamp = int(int(cov_file.split("time:")[-1].split(",")[0]) / 1000)
        except:
            continue
        bbs = parse_drcov(tee, ta, os.path.join(drcov_path, cov_file))
        out[timestamp] = bbs
    return out


def calc_bbs(fuzzing_infos: list[RawFuzzingInfo]):
    for fuzzing_info in fuzzing_infos:
        for cov_dir in fuzzing_info.cov_dirs:
            if os.path.exists(cov_dir):
                cov_size = os.path.getsize(cov_dir)
                if cov_size == 0:
                    print(f"[-] Coverage file {cov_dir} is empty")
                    exit(-1)
                else:
                    print(f"[+] Coverage file {cov_dir} is {cov_size} bytes")


class DockerPool:
    def __init__(self, image_name: str, *, num_containers: int, param_str: str):
        self.image_name = image_name
        self.num_containers = num_containers
        self.param_str = param_str

        ps = subprocess.run("docker ps", shell=True, capture_output=True)
        if image_name in str(ps.stdout):
            print(f"[-] {image_name}-related containers are not running")
            print(
                f"[-] Do you want to remove the {image_name}-related containers and continue? (y/N)"
            )
            reply = input().lower()
            if reply == "y":
                subprocess.run(
                    "docker ps | grep {image_name} | awk '{print $1}' | xargs docker rm -f",
                    shell=True,
                    capture_output=True,
                )

    def __enter__(self):
        print(
            f"[+] Spawning docker pool for {self.image_name} with {self.num_containers} containers"
        )
        for i in range(self.num_containers):
            subprocess.run(
                f"docker run -d --name {self.image_name}_{i} {self.param_str} {self.image_name} bash &>/dev/null",
                shell=True,
            )

    def __exit__(self):
        for i in range(self.num_containers):
            subprocess.run(
                f"docker rm -f {self.image_name}_{i}",
                shell=True,
            )
