import os
from dataclasses import dataclass
from typing import Literal
import re
from enum import Enum

class FuzzMode(Enum):
    ORG = "org"
    DF = "df"
    ALL = "all"


@dataclass(frozen=True)
class RawFuzzingInfo:
    ta_name: str
    ta_path: str
    ta_rpath: str
    tee_path: str
    fuzz_mode: FuzzMode
    cov_dirs: list[str]
    queue_dirs: list[str]

def list_tas(path="/root/TA_GP_emulator"):
    return set([
        os.path.join(dir_path, filename)
        for dir_path, _, filenames in os.walk(path)
        for filename in filenames
        if filename.endswith(".ta") and "harness" in dir_path
    ])



def get_fuzzing_basic_info(ta: str, fuzz_mode: FuzzMode) -> RawFuzzingInfo:
    match = re.match(r"^/root/TA_GP_emulator/(?P<tee>[^/]+)/harness/(?P<harness_name>[^/]+)/(?P<ta_name>.*)$", ta)
    if match is None:
        raise ValueError(f"Invalid ta path: {ta}")
    tee = match.group("tee")
    harness_name = match.group("harness_name")
    ta_name = match.group("ta_name")
    if fuzz_mode == FuzzMode.ORG:
        return RawFuzzingInfo(
            ta_name=ta_name,
            ta_path=ta,
            ta_rpath=os.path.realpath(ta),
            tee_path=f"/root/TA_GP_emulator/{tee}",
            fuzz_mode=fuzz_mode,
            cov_dir=[f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/out/cov"],
            queue_dir=[f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/out/default/queue"],
        )
    elif fuzz_mode == FuzzMode.DF:
        cov_dir_tmp = "/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz/{df_seed_with_context}/out/cov"
        queue_dir_tmp = "/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz/{df_seed_with_context}/out/default/queue"
        
        cov_dirs = [cov_dir_tmp.format(tee=tee, harness_name=harness_name, df_seed_with_context=df_seed_with_context) 
        for df_seed_with_context in os.listdir(f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz")]
        
        queue_dirs = [queue_dir_tmp.format(tee=tee, harness_name=harness_name, df_seed_with_context=df_seed_with_context) 
        for df_seed_with_context in os.listdir(f"/root/TA_GP_emulator/{tee}/harness/{harness_name}/df_fuzz")]

        return RawFuzzingInfo(
            ta_name=ta_name,
            ta_path=ta,
            ta_rpath=os.path.realpath(ta),
            tee_path=f"/root/TA_GP_emulator/{tee}",
            fuzz_mode=fuzz_mode,
            cov_dirs=cov_dirs,
            queue_dirs=queue_dirs,
        )
    else:
        raise ValueError(f"Invalid fuzz mode: {fuzz_mode}")

