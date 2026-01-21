import matplotlib.pyplot as plt
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode
from typing import List
from collect_cov import FuzzingInfo


def parse_unique_bbs(fuzzing_info_list: List[FuzzingInfo]):
    for fuzzing_info in fuzzing_info_list:
        raw_fuzzing_info: RawFuzzingInfo = fuzzing_info.raw_fuzzing_info
        unique_bbs_ts_based = {}
        cov_bbs: dict[str, list[BB]] = parse_cov(
            raw_fuzzing_info.tee,
            raw_fuzzing_info.ta_name,
            raw_fuzzing_info.cov_dir,
        )
        for timestamp, bbs in cov_bbs.items():
            if timestamp not in unique_bbs_ts_based:
                unique_bbs_ts_based[timestamp] = set()
            unique_bbs_ts_based[timestamp].update(bbs)
        fuzzing_info.unique_cov_bbs = unique_bbs_ts_based


def org_control_flow_graph(fuzzing_info_list: List[FuzzingInfo]):
    ## plt
    whole_fig = plt.figure()

    return whole_fig


def df_control_flow_graph(fuzzing_info_list: List[FuzzingInfo]):
    # key: vanilla id, value: set of dfs
    grouped_df_bbs = {}
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.DF:
            continue
        curr_linked_ta_finfo: RawFuzzingInfo = fuzzing_info.linked_ta_finfo
        if curr_linked_ta_finfo.id not in grouped_df_bbs:
            grouped_df_bbs[curr_linked_ta_finfo.id] = []
            
        grouped_df_bbs[curr_linked_ta_finfo.id].append(fuzzing_info.unique_cov_bbs)

    # paint the grouped_df_bbs
    whole_fig = plt.figure()
    return whole_fig
