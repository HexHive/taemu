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
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from tqdm import tqdm
import time
import matplotlib.pyplot as plt


logger.add("graphs.log", rotation="100 MB", retention="10 days")

def main(
    fuzz_mode: FuzzMode = FuzzMode.ALL,
    path: str = "/root/TA_GP_emulator",
    tees: list[str] = None,
    regen_coverage: bool = False,
    show_plots: bool = True,
    save_plots: bool = True,
):
    all_tas: set[str] = list_tas(path)
    tees = tees or ["mitee", "teegris", "beanpod", "t6", "qsee"]
    filtered_tas = list(filter(lambda ta: any(tee in ta for tee in tees), all_tas))

    ## get the cfg and basic raw fuzzing info
    logger.info(f"[+] Collecting cfg and basic raw fuzzing info for each TA")
    fuzzing_info_list: List[FuzzingInfo] = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        future_to_idx = {ex.submit(collect_cov_denominator, ta, fuzz_mode, path): i for i, ta in enumerate(filtered_tas)}
        
        for fut in tqdm(as_completed(future_to_idx), total=len(filtered_tas), desc="Collecting cfg for each TA"):
            _i = future_to_idx[fut]
            ## TODO: add a TRY-EXCEPT block here
            raw_covs, raw_fuzzing_infos = fut.result()
            for raw_fuzzing_info in raw_fuzzing_infos:
                fuzzing_info_list.append(FuzzingInfo(raw_fuzzing_info, raw_covs, 0, 0, set(),{}))
    
    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        linking(fuzzing_info_list)

    ## generate coverage files based on queue
    if regen_coverage:
        logger.info(f"[+] Generating coverage files for each TA")
        num_containers = 40
        ### spawn docker pools
        with DockerPool(
            image_name="ta_emu",
            num_containers=num_containers,
            param_str=f"--network host -v /tmp:/tmp -v {path}:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=5g ",
        ):
            time.sleep(1)
            gen_coverage_files(
                [each.raw_fuzzing_info for each in fuzzing_info_list],
                image_name="ta_emu",
                num_containers=num_containers,
                path=path,
                pre_clean=True,
            )

    logger.info(f"[+] Parsing unique bbs for each TA")
    parse_unique_bbs(fuzzing_info_list)

    ## generate graphs for each ta
    if fuzz_mode == FuzzMode.ORG or fuzz_mode == FuzzMode.ALL:
        logger.info(f"[+] Generating org graph")
        org_graph = org_control_flow_graph(fuzzing_info_list)
        if org_graph:
            logger.info(f"[+] Finished generating org graph")
            if save_plots:
                # Save the figure
                output_path = os.path.join(path, "eval/graphs/org_control_flow_graph.png")
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                org_graph.savefig(output_path, dpi=300, bbox_inches='tight')
                logger.info(f"[+] Saved org graph to {output_path}")
            if show_plots:
                # Display the figure
                plt.show()

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        logger.info(f"[+] Generating df graph")
        df_graph = df_control_flow_graph(fuzzing_info_list)
        if df_graph:
            logger.info(f"[+] Finished generating df graph")
            if save_plots:
                # Save the figure
                output_path = os.path.join(path, "eval/graphs/df_control_flow_graph.png")
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                df_graph.savefig(output_path, dpi=300, bbox_inches='tight')
                logger.info(f"[+] Saved df graph to {output_path}")
            if show_plots:
                # Display the figure
                plt.show()

    # if fuzz_mode == FuzzMode.ALL:
    #     uniq_trace = compare_graphs(org_graph, df_graph)
    #     logger.info(f"Unique traces: {uniq_trace}")

    # res = number_statistics(fuzz_mode, filtered_tas)
    # logger.info(f"Number statistics: {res}")
    # return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fuzz_mode", choices=[mode.value for mode in FuzzMode], default=FuzzMode.ALL.value)
    parser.add_argument("--tees", nargs="+", default=None, help="Filter by TEEs")
    parser.add_argument("--regen_coverage", action="store_true", default=False)
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    
    
    args = parser.parse_args()
    main(fuzz_mode=FuzzMode(args.fuzz_mode), path=args.path, tees=args.tees, 
         regen_coverage=args.regen_coverage, show_plots=False, save_plots=True)
