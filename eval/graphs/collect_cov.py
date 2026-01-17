from common import get_fuzzing_basic_info, RawFuzzingInfo
from common import FuzzMode
from bb import build_tee_cfg, cfg_ta, trim_cfg, root, generate_graph
import os
import networkx as nx
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import subprocess
from typing import List
import matplotlib.pyplot as plt
from common import BB


@dataclass
class Coverage:
    uniq_identity: str
    max_nodes: int
    hit_nodes: int
    cfg: nx.DiGraph


@dataclass
class FuzzingInfo:
    raw_fuzzing_info: RawFuzzingInfo
    raw_covs: Coverage
    fuzz_graphs: dict[str, plt.Figure]
    unique_cov_bbs: dict[str, set[BB]]
    linked_ta_finfo: RawFuzzingInfo


def gen_coverage_files(
    fuzzing_infos: list[RawFuzzingInfo], image_name: str, pre_clean: bool = False
):
    if pre_clean:
        for fuzzing_info in fuzzing_infos:
            if os.path.exists(fuzzing_info.cov_dir):
                os.rmdir(fuzzing_info.cov_dir)

    replay_tasks = [
        (fuzzing_info.harness_path, os.path.join(fuzzing_info.queue_dir, file))
        for fuzzing_info in fuzzing_infos
        for file in os.listdir(fuzzing_info.queue_dir)
    ]

    def _replay_seed(container_name, harness_path, seed_path):
        # TODO rebase the path
        subprocess.run(
            f"docker exec {container_name} ./replay.sh {harness_path} {seed_path}",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    ## replay seeds from queue
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        _futures = [
            ex.submit(_replay_seed, +f"{image_name}_{i}", harness_path, seed_path)
            for i, (image_name, harness_path, seed_path) in enumerate(replay_tasks)
        ]

    ## validate the size of coverage
    for fuzzing_info in fuzzing_infos:
        for i, cov_dir in enumerate(fuzzing_info.cov_dirs):
            assert os.exists(cov_dir), f"Coverage file {cov_dir} does not exist"
            assert len(os.listdir(cov_dir)) == len(
                os.listdir(fuzzing_info.queue_dirs[i])
            ), f"The size of coverage file {cov_dir} and queue file {fuzzing_info.queue_dirs[i]} are different"


def linking(fuzzing_info_list: List[FuzzingInfo]):
    for df_fuzzing_info in fuzzing_info_list:
        if df_fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.DF:
            continue
        for org_fuzzing_info in fuzzing_info_list:
            if (
                f"{df_fuzzing_info.raw_fuzzing_info.tee}_{df_fuzzing_info.raw_fuzzing_info.harness_path.split('/')[-1]}"
                == org_fuzzing_info.raw_fuzzing_info.id
            ):
                df_fuzzing_info.linked_ta_finfo = org_fuzzing_info
                break


def collect_cov_denominator(
    ta: str, fuzz_mode: FuzzMode
) -> tuple[Coverage, RawFuzzingInfo]:
    all_fuzzing_info = []
    # vanilla fuzzing
    org_fuzzing_info = get_fuzzing_basic_info(ta, FuzzMode.ORG)
    assert len(org_fuzzing_info) == 1, f"Expected 1 fuzzing info for {ta} during vanilla fuzzing, got {len(org_fuzzing_info)}"
    partial_cov = _analyze_cfg_ta(org_fuzzing_info[0])
    all_fuzzing_info.extend(org_fuzzing_info)

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        # df fuzzing
        df_fuzzing_infos = get_fuzzing_basic_info(ta, FuzzMode.DF)
        all_fuzzing_info.extend(df_fuzzing_infos)

    return partial_cov, all_fuzzing_info


def _analyze_cfg_tee(fuzzing_info: RawFuzzingInfo):
    tee_cfg = build_tee_cfg(fuzzing_info.tee_path, only_tee=True)
    (
        reachable,
        max_nodes,
        all_gp_idx,
        all_libc_idx,
        all_tee_std_idx,
        all_tee_idx,
        implemented_apis,
    ) = generate_graph(tee_cfg, todo=fuzzing_info.tee_path)

    return Coverage(fuzzing_info.tee_path, max_nodes, reachable, tee_cfg)


def _analyze_cfg_ta(fuzzing_info: RawFuzzingInfo):
    """similar to analyze_ta, but without plotting the graph

    Args:
        ta_path (str): path to the TA
    """
    ta_cfg = cfg_ta(fuzzing_info.ta_rpath)
    for node, data in ta_cfg.nodes(data=True):
        if "svc" in data and len(data["svc"]) > 0:
            # Find all simple paths from start_node to this node
            path = list(nx.shortest_path(ta_cfg, source=root, target=node))
            print(" -> ".join(path), "svc:", data["svc"])

    print(len(nx.descendants(ta_cfg, root)))
    nothing_cfg = trim_cfg(ta_cfg, [])  # TODO: should we add some implemented APIs?
    print(len(nx.descendants(nothing_cfg, root)))
    for ta_fw in ta_cfg.neighbors(root):
        print(ta_fw, len(nx.descendants(ta_cfg, ta_fw)))
    (
        reachable,
        max_nodes,
        all_gp_idx,
        all_libc_idx,
        all_tee_std_idx,
        all_tee_idx,
        implemented_apis,
    ) = generate_graph(ta_cfg)
    print("max_nodes", max_nodes)
    return Coverage(fuzzing_info.ta_name, max_nodes, reachable, ta_cfg)


def _build_replay_params(fuzzing_info: RawFuzzingInfo):
    replay_params_list = []
    seed_pools = fuzzing_info.queue_dirs
    harness_path = fuzzing_info.harness_path
    for seed_pool in seed_pools:
        for seed in os.listdir(seed_pool):
            seed_path = os.path.join(seed_pool, seed)
            with open(seed_path, "r") as f:
                seed_content = f.read()
            print(seed_content)
