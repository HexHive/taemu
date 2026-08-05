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
from typing import Optional
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import taemu_env

logger.add("graphs.log", rotation="100 MB", retention="10 days")


def main(
    fuzz_mode: FuzzMode = FuzzMode.ALL,
    path: str = None,
    tees: list[str] = None,
    tas: list[str] = None,
    regen_coverage: bool = False,
    bk_suspicious_inputs_cov_rdir: str = None,
    show_plots: bool = True,
    save_plots: bool = True,
    grouping_field_name: Optional[str] = None,
    show_rate: bool = False,
    max_timestamps: int = 86400,
):
    path = path or taemu_env.repo_root()
    all_tas: set[str] = list_tas(path)
    tees = tees or ["mitee", "teegris", "beanpod", "t6", "qsee"]
    if tees == ["kinibi"]:
        kinibi_tas = ["df1edda8627911e980ae507b9d9a7e7d", "abcd270ea5c44c58bcd3384a2fa2539e", "08010203000000000000000000000000"]
        filtered_tas = list(filter(lambda ta: any(kinibi_ta in ta for kinibi_ta in kinibi_tas), all_tas))
    else:
        filtered_tas = list(filter(lambda ta: any(tee in ta for tee in tees), all_tas))

    if tas is not None:
        filtered_tas = list(filter(lambda ta: any(ta_name in ta for ta_name in tas), filtered_tas)) 

    ## get the cfg and basic raw fuzzing info
    logger.info(f"[+] Collecting cfg and basic raw fuzzing info for each TA")
    fuzzing_info_list: List[FuzzingInfo] = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        future_to_idx = {
            ex.submit(collect_cov_denominator, ta, fuzz_mode, path): i
            for i, ta in enumerate(filtered_tas)
        }

        for fut in tqdm(
            as_completed(future_to_idx),
            total=len(filtered_tas),
            desc="Collecting cfg for each TA",
        ):
            _i = future_to_idx[fut]
            ## TODO: add a TRY-EXCEPT block here
            raw_covs, raw_fuzzing_infos = fut.result()
            if raw_covs is None:
                continue
            for raw_fuzzing_info in raw_fuzzing_infos:
                fuzzing_info_list.append(
                    FuzzingInfo(raw_fuzzing_info, raw_covs, None, {})
                )

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        linking(fuzzing_info_list)
        
    sys.stdout.flush()
    sys.stderr.flush()

    ## generate coverage files based on queue
    if regen_coverage:
        logger.info(f"[+] Generating coverage files for each TA")
        num_containers = 30
        ### spawn docker pools
        with DockerPool(
            image_name=taemu_env.image(),
            num_containers=num_containers,
            # TAEMU_NO_RECORD: replaying seeds for coverage must not record new
            # suspicious inputs, otherwise collecting the data changes it.
            param_str=f"--network host -v {path}:/srv -w /srv/emulator -v /dev/shm:/dev/shm "
                      f"--ipc=host --shm-size=5g -e TAEMU_NO_RECORD=1 ",
        ):
            time.sleep(1)
            gen_coverage_files(
                [each.raw_fuzzing_info for each in fuzzing_info_list],
                image_name=taemu_env.image(),
                num_containers=num_containers,
                path=path,
                # pre_clean=True,
            ) # TODO: check whether need to clean coverage files

    logger.info(f"[+] Parsing unique bbs for each TA")
    parse_unique_bbs(fuzzing_info_list)
    
    sys.stdout.flush()
    sys.stderr.flush()

    if tees == ["kinibi"]:
        for fi in fuzzing_info_list:
            fi.raw_fuzzing_info.tee = "kinibi"
            
    ## generate graphs for each ta
    if fuzz_mode == FuzzMode.ORG or fuzz_mode == FuzzMode.ALL:
        logger.info(f"[+] Generating org graph")
        org_graph = org_control_flow_graph(
            fuzzing_info_list,
            max_timestamps=max_timestamps,
            grouping_field_name=grouping_field_name,
            show_rate=show_rate,
            path=path,
        )
        if org_graph:
            logger.info(f"[+] Finished generating org graph")
            if save_plots:
                # Save the figure
                output_path = os.path.join(
                    path, "eval/graphs/org_control_flow_graph.png"
                )
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                org_graph.savefig(output_path, dpi=300, bbox_inches="tight")
                logger.info(f"[+] Saved org graph to {output_path}")
            if show_plots:
                # Display the figure
                plt.show()

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        logger.info(f"[+] Generating df graph")
        df_graph = df_control_flow_graph(
            fuzzing_info_list,
            show_rate=show_rate,
            bk_suspicious_inputs_cov_rdir=bk_suspicious_inputs_cov_rdir,
            path=path,
        )
        if df_graph:
            logger.info(f"[+] Finished generating df graph")
            if save_plots:
                # Save the figure
                output_path = os.path.join(
                    path, "eval/graphs/df_control_flow_graph.png"
                )
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                df_graph.savefig(output_path, dpi=300, bbox_inches="tight")
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
    parser.add_argument(
        "--fuzz_mode",
        choices=[mode.value for mode in FuzzMode],
        default=FuzzMode.ALL.value,
    )
    parser.add_argument("--tees", nargs="+", default=None, help="Filter by TEEs")
    parser.add_argument("--tas", nargs="+", default=None, help="Filter by TAs")
    parser.add_argument("--regen_coverage", action="store_true", default=False)
    parser.add_argument("--path", type=str, default=taemu_env.repo_root())
    parser.add_argument("--ss_cov_rdir", type=str, default=None, required=True)
    parser.add_argument("--org_group_field", type=str, default=None, choices=["tee", None])
    parser.add_argument("--show_rate", action="store_true", default=False)
    parser.add_argument("--max_timestamps", type=int, default=86400,
                        help="length of the x-axis of the exploration graph in seconds "
                             "(the paper's campaign ran for 86400 s per repetition)")
    
    args = parser.parse_args()

    #user_input = input(f"[-] Have you back up the coverage files of suspicious inputs to the directory `{args.ss_cov_rdir}`? (y/n)\n")
    #if user_input != "y":
    #    raise Exception("[-] Please back up the coverage files of suspicious inputs first. Run `./bk_suspicious_inputs.sh <root_dir> <back_dir>`.")

    if os.path.exists(args.ss_cov_rdir) is False or len(os.listdir(args.ss_cov_rdir)) == 0:
        raise Exception("[-] The directory of the backup coverage files of suspicious inputs does not exist or is empty.")
    
    main(
        fuzz_mode=FuzzMode(args.fuzz_mode),
        path=args.path,
        tees=args.tees,
        tas=args.tas,
        regen_coverage=args.regen_coverage,
        bk_suspicious_inputs_cov_rdir=args.ss_cov_rdir,
        grouping_field_name=args.org_group_field,
        show_rate=args.show_rate,
        max_timestamps=args.max_timestamps,
        show_plots=False,
        save_plots=True,
    )
