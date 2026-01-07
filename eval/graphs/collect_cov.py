from typing import Literal
from common import get_fuzzing_basic_info, RawFuzzingInfo
from common import FuzzMode
from bb import build_tee_cfg

def gen_coverage(fuzz_mode: Literal["org", "df", "all"] = "all", ta: str = None):
    pass


def collect_cov_denominator(ta: str):
    org_fuzzing_info = get_fuzzing_basic_info(ta, FuzzMode.ORG)
    bb_count = analyze_call_graph(org_fuzzing_info)
    return bb_count


def analyze_call_graph(fuzzing_info: RawFuzzingInfo):
    build_tee_cfg(fuzzing_info.tee_path, only_tee=True)
    

