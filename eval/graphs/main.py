import argparse
from loguru import logger
from common import list_tas, FuzzMode
from collect_cov import collect_cov_denominator
from collect_cov import gen_coverage_files
from graphing import org_control_flow_graph, df_control_flow_graph, parse_unique_bbs
from common import DockerPool
from typing import List
from graphing import FuzzingInfo
from collect_cov import linking
import sys


def main(
    fuzz_mode: FuzzMode = FuzzMode.ALL,
    tees: list[str] = None,
    regen_coverage: bool = False,
):
    all_tas: set[str] = list_tas()  # TODO
    tees = tees or ["mitee", "teegris", "beanpod", "t6", "qsee"]
    filtered_tas = filter(lambda ta: any(tee in ta for tee in tees), all_tas)

    ## get the cfg and basic raw fuzzing info
    fuzzing_info_list: List[FuzzingInfo] = []
    for ta in filtered_tas:
        raw_covs, raw_fuzzing_infos = collect_cov_denominator(ta)
        for raw_fuzzing_info in raw_fuzzing_infos:
            fuzzing_info_list.append(FuzzingInfo(raw_fuzzing_info, raw_covs, 0, 0, {}))
        if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
            linking(fuzzing_info_list)

    ## generate coverage files based on queue
    if regen_coverage:
        ### spawn docker pools
        with DockerPool(
            image_name="emu",
            num_containers=10,
            param_str="--network host -it -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g",
        ):
            for each_fuzzing_info in fuzzing_info_list:
                gen_coverage_files(
                    each_fuzzing_info.raw_fuzzing_info,
                    image_name="ta_emu",
                    pre_clean=True,
                )

    parse_unique_bbs(fuzzing_info_list)

    ## generate graphs for each ta
    if fuzz_mode == FuzzMode.ORG or fuzz_mode == FuzzMode.ALL:
        org_graph = org_control_flow_graph(fuzzing_info_list)

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        df_graph = df_control_flow_graph(fuzzing_info_list)

    # if fuzz_mode == FuzzMode.ALL:
    #     uniq_trace = compare_graphs(org_graph, df_graph)
    #     logger.info(f"Unique traces: {uniq_trace}")

    # res = number_statistics(fuzz_mode, filtered_tas)
    # logger.info(f"Number statistics: {res}")
    # return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fuzz_mode", choices=["org", "df", "all"], default="all")
    parser.add_argument("--tees", nargs="+", default=None, help="Filter by TEEs")
    parser.add_argument("--regen_coverage", action="store_true", default=False)
    args = parser.parse_args()
    logger.info(f"[+] {sys.argv[0]} Args: {args}")
    main(fuzz_mode=args.fuzz_mode, tees=args.tees, regen_coverage=args.regen_coverage)
