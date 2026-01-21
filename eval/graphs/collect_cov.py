from common import get_fuzzing_basic_info, RawFuzzingInfo
from common import FuzzMode
from bb import build_tee_cfg, cfg_ta, trim_cfg, root, get_apis, reachable_nodes
import os
import networkx as nx
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import subprocess
from loguru import logger
from typing import List
import pdb
import matplotlib.pyplot as plt
import shutil
from common import BB
from tqdm import tqdm
from concurrent.futures import as_completed


@dataclass
class Coverage:
    uniq_identity: str
    max_nodes: int
    cfg: nx.DiGraph


@dataclass
class FuzzingInfo:
    raw_fuzzing_info: RawFuzzingInfo
    raw_covs: Coverage
    fuzz_graphs: dict[str, plt.Figure]
    unique_cov_bbs: dict[str, set[BB]]
    linked_ta_finfo: RawFuzzingInfo


def gen_coverage_files(
    raw_fuzzing_infos: list[RawFuzzingInfo], image_name: str, num_containers: int, path: str, pre_clean: bool = False, slient: bool = True
):
    if pre_clean:
        for each in raw_fuzzing_infos:
            if os.path.exists(each.cov_dir):
                shutil.rmtree(each.cov_dir)

    replay_tasks = [
        (fuzzing_info.harness_path, os.path.join(fuzzing_info.queue_dir, file))
        for fuzzing_info in raw_fuzzing_infos
        for file in os.listdir(fuzzing_info.queue_dir) if ".state" not in file
    ]

    def _replay_seed(container_name, harness_path, seed_path) -> tuple[bool, str, str]:
        if "/df_fuzz/" in seed_path:
            org_seed_file = seed_path.split("/")[5].split("_")[0]
            org_seed_path = os.path.join(harness_path, "in/suspicious_inputs_replay", org_seed_file)
            df_reg_hash = seed_path.split("/")[5].split("_")[1]
            logger.info(f"[+] Docker command: docker exec -it {container_name} ./df_fuzz.sh {harness_path} {org_seed_path} {df_reg_hash} {seed_path}")
            result = subprocess.run(
                f"docker exec -it {container_name} ./df_fuzz.sh {harness_path} {org_seed_path} {df_reg_hash} {seed_path}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            logger.info(f"[+] Docker command: docker exec -it {container_name} ./fuzz.sh {harness_path} {seed_path}")
            result = subprocess.run(
                f"docker exec -it {container_name} ./fuzz.sh {harness_path} {seed_path}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
        logger.info(f"[+] Replaying seed {seed_path} from {harness_path} on container {container_name}")
        stderr = result.stderr.decode("utf-8").strip()
        stdout = result.stdout.decode("utf-8").strip()
        logger.info(f"[+][+][+][+] {seed_path} Stdout: {stdout} [+][+][+][+]")
        if stderr != "":
            logger.error(f"Error on replaying seed {seed_path} from {harness_path}: {stderr}")
            return False, harness_path, seed_path
        else:
            return True, "", ""
        
        
    logger.info(f"[+] Replaying seeds from queue")
    num_workers = os.cpu_count()
    bad_cases = []
    ## replay seeds from queue
    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        _futures = [
            ex.submit(_replay_seed, f"{image_name}_{i%num_containers}", harness_path.replace(path, ".."), seed_path.replace(path, ".."))
            for i, (harness_path, seed_path) in enumerate(replay_tasks)
        ]
        
        for fut in tqdm(as_completed(_futures), total=len(replay_tasks), desc="Replaying seeds"):
            success, harness_path, seed_path = fut.result()
            if not success:
                bad_cases.append((harness_path, seed_path))
                
    if not slient:
        logger.info(f"[-] There are {len(bad_cases)} bad cases")
        details = '\n'.join([f'{each[0]} {each[1]}' for each in bad_cases])
        logger.info(f"[-] Bad cases: {details}")
        user_input = input("[-] Do you want to continue? (y/n)")
        if user_input != "y":
            raise Exception("[-] User interrupted")
        
        
    logger.info(f"[+] Validating the size of coverage")
    ## validate the size of coverage
    cnt = 0
    accpted_bad_harnesses = [each[0] for each in bad_cases]
    for each in raw_fuzzing_infos:
        if not slient and each.harness_path not in accpted_bad_harnesses:
                assert os.path.exists(each.cov_dir), f"Coverage file {each.cov_dir} does not exist"
        else:
            if not os.path.exists(each.cov_dir):
                cnt += 1
            # assert os.path.exists(each.cov_dir), f"Coverage file {each.cov_dir} does not exist"
    logger.warning(f"[-] in total, {cnt} coverage files are missing")
    return 

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
    ta: str, fuzz_mode: FuzzMode, path: str
) -> tuple[Coverage, RawFuzzingInfo]:
    all_fuzzing_info = []
    # vanilla fuzzing
    org_fuzzing_info = get_fuzzing_basic_info(ta, FuzzMode.ORG, path)
    assert len(org_fuzzing_info) == 1, f"Expected 1 fuzzing info for {ta} during vanilla fuzzing, got {len(org_fuzzing_info)}"
    partial_cov = _analyze_cfg_ta(org_fuzzing_info[0])
    all_fuzzing_info.extend(org_fuzzing_info)

    if fuzz_mode == FuzzMode.DF or fuzz_mode == FuzzMode.ALL:
        # df fuzzing
        df_fuzzing_infos = get_fuzzing_basic_info(ta, FuzzMode.DF, path)
        all_fuzzing_info.extend(df_fuzzing_infos)

    return partial_cov, all_fuzzing_info


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
    
    max_nodes = generate_graph_custom(ta_cfg)
    print("max_nodes", max_nodes)
    return Coverage(fuzzing_info.ta_name, max_nodes, ta_cfg)


def generate_graph_custom(cfg, todo=None):
    used_apis = get_apis(cfg)
    max_nodes = reachable_nodes(cfg, used_apis)
    print("nr used apis", len(used_apis))
    print("nr gp apis", len([a for a in used_apis if a.api_type == "gp_api"]))
    print("nr libc apis", len([a for a in used_apis if a.api_type == "libc"]))
    print("nr tee apis", len([a for a in used_apis if a.api_type.startswith("tee")]))
    print(f"max nodes: {max_nodes}")
    return max_nodes

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
