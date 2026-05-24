# Purpose: Build CFGs from bb_*.json dumps, rank APIs by reachable basic-block
# coverage gain, and write per-TA/per-TEE API order and ranking artifacts.
# Depends on: TA .ta/.elf files, adjacent .json metadata, tas/bbs/bb_<ta>.json
# dumps, networkx/matplotlib/colorama, and optional bbs_out cache files.
# Input: CLI argument is a TA path, TEE directory path, "all", "full", or
# "tee-select" followed by TA paths.

from collections import Counter
import hashlib
import logging
from pathlib import Path
from typing import List, Tuple
import networkx as nx
import matplotlib
import json
import os
import pickle
import sys
import subprocess
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout
from multiprocessing import Pool, cpu_count

import yaml

ta_uuid = None
tee_name = None
do_ta_uuid = False
do_tee_name = False
ALL_TEES = ["mitee", "teegris", "beanpod", "t6"]
ALL_TEES = ["qsee_nongp"]


log = logging.getLogger("bb")
log.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
# Make log coloured
import colorama
COLOR_MAP = {
    "DEBUG": colorama.Fore.WHITE,
    "INFO": colorama.Fore.GREEN,
    "WARNING": colorama.Fore.BLACK + colorama.Style.BRIGHT + colorama.Back.YELLOW,
    "ERROR": colorama.Fore.RED,
    "CRITICAL": colorama.Fore.RED,
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt):
        super().__init__(fmt)
        self.color_map = COLOR_MAP

    def format(self, record):
        levelname = record.levelname
        if levelname in self.color_map:
            record.levelname = self.color_map[levelname] + levelname + colorama.Style.RESET_ALL
        return super().format(record)

handler.setFormatter(ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
log.addHandler(handler)



def int2hex(nr):
    h = hex(nr)[2:]
    return '0' * (8-len(h)) + h

def label(addr, no_uuid=False, do_tee_name=False):
    global ta_uuid
    global tee_name
    if no_uuid:
        return addr
    if do_tee_name:
        return f'{tee_name}_{addr}'
    if do_ta_uuid:
        if do_tee_name:
            return f'{tee_name}_{ta_uuid}_{addr}'
        else:
            return f'{ta_uuid}_{addr}'
    else:
        return addr

class Call:
    def __init__(self, json_data):
        self.func = json_data["func"]
        self.is_api = json_data["api"]
        self.api_type = json_data["api_type"]
        self.family = json_data.get("family", self.api_type)
        self.traits = tuple(json_data.get("traits", []))
        self.name_source = json_data.get("name_source", "function")
        self.target_addr = json_data.get("target_addr")

    def __hash__(self):
        return hash(f'{self.func}_{self.is_api}_{self.api_type}')
    
    def __str__(self):
        return f'{self.func}_{self.is_api}_{self.api_type}'
    
    def __repr__(self):
        return f'{self.func}_{self.is_api}_{self.api_type}'
    
    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def to_dict(self):
        return {
            "func": self.func,
            "api": self.is_api,
            "api_type": self.api_type,
            "family": self.family,
            "traits": list(self.traits),
            "name_source": self.name_source,
            "target_addr": self.target_addr,
        }

root = '0'*8
CFG_CACHE_VERSION = 1
CFG_CACHE_DIR = Path(__file__).resolve().parent / ".cache" / "bb_cfg"
CFG_CACHE_DISABLED = os.environ.get("TAEMU_DISABLE_CFG_CACHE") == "1"
BBS_OUT_DIR = Path(__file__).resolve().parent / "bbs_out"
_reachable_nodes_cache = {}

def is_address(func_name):
    try:
        a = int("0x"+func_name, 16)
        return True
    except:
        return False


def entry_addrs(ta_json, tee)->List[Tuple[str,int]]:
    if tee == "qsee_nongp":
        key = "tz_app_cmd_handler_start"
        return [(key, ta_json[key])]
    
    out = []
    for key, value in ta_json.items():
        if not key.endswith("_start"):
            continue
        if not isinstance(value, int):
            continue
        if value == -1:
            continue
        out.append((key, value))
    return out


def bb_key(addr):
    return "0x" + int2hex(addr).lstrip("0")

def address_keys(addr:int)->List[str|int]:
    return [bb_key(addr), hex(addr), int2hex(addr)]

def find_bb_entry(bb_data:dict, addr:int)->dict:
    keys = address_keys(addr)
    if addr == 0:
        keys.append("0x0")
    for key in keys:
        if key in bb_data:
            return bb_data[key]
    raise KeyError(f"missing BB CFG for entry address {hex(addr)}")


def file_signature(path):
    path = Path(path)
    st = path.stat()
    return {
        "path": path.resolve().as_posix(),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
    }


def cache_key(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def read_pickle_cache(namespace, payload):
    if CFG_CACHE_DISABLED:
        return None
    path = CFG_CACHE_DIR / namespace / f"{cache_key(payload)}.pickle"
    try:
        with path.open("rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning(f"ignoring corrupt CFG cache {path}: {exc}")
        return None


def write_pickle_cache(namespace, payload, value):
    if CFG_CACHE_DISABLED:
        return
    path = CFG_CACHE_DIR / namespace / f"{cache_key(payload)}.pickle"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("wb") as f:
        pickle.dump(value, f, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp_path, path)


def iter_ta_targets(tas_dir):
    for ta in sorted(os.listdir(tas_dir)):
        ta_path = Path(tas_dir, ta)
        if not ta_path.is_file():
            continue
        if ta_path.suffix not in {".ta", ".elf"}:
            continue
        if "patched" in ta_path.name or "nopauth" in ta_path.name:
            continue
        if not ta_path.with_suffix(".json").exists() and not ta_path.with_suffix(".yml").exists():
            log.warning(f"missing metadata for {ta_path}")
            continue
        if not (ta_path.parent / "bbs" / f"bb_{ta}.json").exists():
            log.warning(f"missing BB CFG for {ta_path}")
            continue
        yield ta_path


def load_ta_json(ta_path):
    json_path = Path(ta_path).with_suffix(".json")
    if json_path.exists():
        return json.load((json_path).open("r"))
    raise FileNotFoundError(f"missing metadata for {ta_path}")

def load_ta_yml(yml_path: Path):
    with yml_path.open("r") as f:
        yml_info = yaml.safe_load(f)
    ta_info = {}
    for k, v in yml_info.items():
        if not isinstance(v, dict):
            continue
        if not {"start", "end"} <= set(v):
            continue
        ta_info[f"{k}_start"] = v["start"]
        ta_info[f"{k}_end"] = v["end"]
    return ta_info

def find_bbs_json_path(ta_dir: str, ta_name: str):
    p1 = Path(ta_dir, 'bbs', 'bb_' + ta_name + '.json')
    p2 = Path(ta_dir, 'bbs', 'bb_' + ta_name.replace(".nopauth", "") + '.json')
    for p in (p1, p2):
        if p.exists():
            return p
    raise FileNotFoundError(f"missing BB CFG for {ta_name}")


def load_bbs_json(ta_dir:str, ta_name:str):
    with find_bbs_json_path(ta_dir, ta_name).open("r") as f:
        return json.load(f)


def cfg_ta_cache_payload(ta_path):
    _ta_path = Path(ta_path)
    ta_dir = os.path.dirname(ta_path)
    ta_name = os.path.basename(ta_path)
    yml_path = _ta_path.with_suffix(".yml")
    bbs_path = find_bbs_json_path(ta_dir, ta_name)
    return {
        "version": CFG_CACHE_VERSION,
        "kind": "cfg_ta",
        "ta": file_signature(_ta_path),
        "yml": file_signature(yml_path),
        "bbs": file_signature(bbs_path),
        "do_ta_uuid": do_ta_uuid,
    }


def cfg_ta(ta_path):
    payload = cfg_ta_cache_payload(ta_path)
    cached = read_pickle_cache("cfg_ta", payload)
    if cached is not None:
        log.info(f"cfg_ta cache hit: {ta_path}")
        return cached
    cfg = cfg_ta_uncached(ta_path)
    write_pickle_cache("cfg_ta", payload, cfg)
    return cfg


def cfg_ta_uncached(ta_path):
    global ta_uuid
    cfg = nx.DiGraph()
    _ta_path = Path(ta_path)
    ta_dir = os.path.dirname(ta_path)
    tee = _ta_path.parent.parent.name
    log.info(f"cfg_ta: {ta_path} {tee}")
    ta_name = os.path.basename(ta_path)
    ta_uuid = os.path.splitext(ta_name)[0]
    ta_json = load_ta_yml(_ta_path.with_suffix(".yml"))
    bb_data = load_bbs_json(ta_dir, ta_name)
    cfg.add_node(label(root))
    for ta_entry, ta_entry_addr in entry_addrs(ta_json, tee):
        try:
            entry_cfg = find_bb_entry(bb_data, ta_entry_addr)
        except KeyError:
            log.warning(f"skipping missing entry CFG: {ta_path} {ta_entry} {hex(ta_entry_addr)}")
            continue
        cfg.add_node(label(int2hex(ta_entry_addr)))
        cfg.add_edge(label(root), label(int2hex(ta_entry_addr)))
        log.info(f"{ta_path} {ta_entry} {len(entry_cfg['nodes'])}")
    for f, data in bb_data.items():
        if f.startswith("0x"):
            f = int2hex(int(f,16))
        f_l = label(f)
        if f_l not in cfg.nodes:
            cfg.add_node(f_l)
        nodes = data['nodes']
        bbname2bbll = {}
        # add all bb nodes and inter procedural edges
        for bb in nodes:
            bb_l = label(bb['start'])
            if bb_l not in cfg.nodes:
                cfg.add_node(bb_l) 
            bbname2bbll[bb["name"]] = bb_l
            node = cfg.nodes[bb_l]
            node["api_calls"] = []
            node["svc"] = bb["svc"]
            node["start"] = bb["start"]
            node["end"] = bb["end"]
            for call in bb["calls"]:
                if not call['api']:
                    fcall_lbl = label(call["func"])
                    if fcall_lbl not in cfg.nodes:
                        cfg.add_node(fcall_lbl)
                    cfg.add_edge(bb_l, fcall_lbl)
                else:
                    if (
                        call["api_type"] == "tee"
                        and is_address(call["func"])
                        and "family" not in call
                    ):
                        # ignore ghidra fu
                        log.info(f'ignoring: {call["func"]}')
                        continue
                    node["api_calls"].append(Call(call))    
        # add intraprocedural edges    
        for bb in nodes:
            bb_l = label(bb['start'])
            for edge in bb["edges"]:
                cfg.add_edge(bb_l, bbname2bbll[edge])
    return cfg    

def get_apis(cfg):
    out = set() 
    for node, data in cfg.nodes(data=True):
        if "api_calls" in data:
            for call in data["api_calls"]:
                out.add(call)
    return out

def trim_cfg(cfg, implemented_apis):
    to_remove = []
    for node, data in cfg.nodes(data=True):
        if "api_calls" in data:
            for call in data["api_calls"]:
                if call not in implemented_apis:
                    to_remove.append(node)
    return nx.restricted_view(cfg, to_remove, [])

def _api_cache_key(api):
    return (api.func, api.is_api, api.api_type)


def _implemented_apis_cache_key(implemented_apis):
    return tuple(sorted(_api_cache_key(api) for api in implemented_apis))


def reachable_nodes(cfg, implemented_apis):
    cache_key = (id(cfg), root, _implemented_apis_cache_key(implemented_apis))
    if cache_key in _reachable_nodes_cache:
        return _reachable_nodes_cache[cache_key]
    trimmed_cfg = trim_cfg(cfg, implemented_apis)
    reachable = len(nx.descendants(trimmed_cfg, root))
    _reachable_nodes_cache[cache_key] = reachable
    return reachable

def pool_worker(data):
    cfg, implemented_apis, api = data
    reach = reachable_nodes(cfg, implemented_apis + [api]) 
    return (api, reach)

def find_best_add(cfg, all_apis, implemented_apis, filterf):
    max_api = None
    max_nr = -1
    work_queue = []
    if not do_ta_uuid:
        for api in all_apis:
            if not filterf(api): continue
            if api in implemented_apis: continue
            reach = reachable_nodes(cfg, implemented_apis + [api])
            if reach > max_nr:
                max_nr = reach
                max_api = api 
    else:
        for api in all_apis:
            if not filterf(api): continue
            if api in implemented_apis: continue
            work_queue.append((cfg, implemented_apis, api))
        with Pool(10) as pool:
            results = pool.map(pool_worker, work_queue, chunksize=5)
        for api, reach in results:
           if reach > max_nr:
                max_nr = reach
                max_api = api 
    return max_api 


def is_gp(call):
    return call.api_type == "gp_api"

def is_libc(call):     
    return call.api_type == "libc"

def is_tee(call):
    return call.api_type.startswith("tee")

def match_all(call):
    return True

def uses_pure_gain_ranking(cfg):
    apis = get_apis(cfg)
    return any(api.func.startswith("qsee_") or api.func.startswith("GPAppLib_") for api in apis)

def get_api(api_list, api_name):
    for api in api_list:
        if api.func == api_name:
            return api
    return None

def generate_graph(cfg, todo=None, strategy="legacy"):
    #TODO: implemented using the cache
    reachable = []
    used_apis = get_apis(cfg)
    max_nodes = reachable_nodes(cfg, used_apis)
    nr_gp = len([a for a in used_apis if a.api_type == "gp_api"])
    nr_libc = len([a for a in used_apis if a.api_type == "libc"])
    nr_tee = len([a for a in used_apis if a.api_type.startswith("tee")])
    print("nr used apis", len(used_apis))
    print("nr gp apis", len([a for a in used_apis if a.api_type == "gp_api"]))
    print("nr libc apis", len([a for a in used_apis if a.api_type == "libc"]))
    print("nr tee apis", len([a for a in used_apis if a.api_type.startswith("tee")]))
    print(f"max nodes: {max_nodes}")
    implemented_apis = []
    i = 0
    reachable.append(reachable_nodes(cfg, implemented_apis))
    i+= 1
    if strategy == "pure_gain":
        while 1:
            max_api = find_best_add(cfg, used_apis, implemented_apis, match_all)
            if max_api is None:
                break
            print("api", max_api)
            used_apis.remove(max_api)
            implemented_apis.append(max_api)
            reachable.append(reachable_nodes(cfg, implemented_apis))
            i += 1
    elif "BB_USE_CACHE" in os.environ and os.path.exists(f'bbs_out/{todo}_order.txt'):
        api_order = open(f'bbs_out/{todo}_order.txt').read().split('\n')
        for api_name in api_order:
            max_api = get_api(used_apis, api_name)
            if max_api is None: continue
            print(max_api)
            implemented_apis.append(max_api)
            reachable.append(reachable_nodes(cfg, implemented_apis)) 
            i += 1
    else:
        while 1:
            max_api = find_best_add(cfg, used_apis, implemented_apis, is_gp)
            if max_api is None: 
                break
            print("gp", max_api)
            used_apis.remove(max_api)
            implemented_apis.append(max_api)
            reachable.append(reachable_nodes(cfg, implemented_apis))
            i += 1
        while 1:
            max_api = find_best_add(cfg, used_apis, implemented_apis, is_libc)
            if max_api is None: 
                break
            print("libc", max_api)
            used_apis.remove(max_api)
            implemented_apis.append(max_api)
            reachable.append(reachable_nodes(cfg, implemented_apis))
            i += 1
        while 1:
            max_api = find_best_add(cfg, used_apis, implemented_apis, is_tee)
            if max_api is None: 
                break
            print("tee", max_api)
            used_apis.remove(max_api)
            implemented_apis.append(max_api)
            reachable.append(reachable_nodes(cfg, implemented_apis))
            i += 1
    print("imlemented apis", len(implemented_apis)) 
    return reachable, max_nodes, nr_gp, nr_libc, nr_tee, implemented_apis

def get_root_node(ta_cfg, tee=None):
    for n in ta_cfg.nodes:
        if tee is not None:
            if n.endswith(f'{tee}_{root}'):
                return n
        elif n.endswith(root):   
            return n

def gen_plot(reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy="legacy"):
    plt.clf()
    matplotlib.rcParams['mathtext.fontset'] = 'custom'
    matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
    matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
    matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
    matplotlib.rcParams['mathtext.fontset'] = 'stix'
    matplotlib.rcParams['font.family'] = 'STIXGeneral'
    percentages = [r / max_nodes * 100 for r in reachable]
    positive_percentages = [p for p in percentages if p > 0]
    if strategy == "pure_gain":
        std_max = min(positive_percentages) if positive_percentages else 0.001
    else:
        percentages = percentages[-nr_tee-1::]
        positive_percentages = [p for p in percentages if p > 0]
        std_max = min(positive_percentages) if positive_percentages else 0.001
    print(percentages)
    print(f"nr data points: {len(percentages)}")
    print(f"std_max: {std_max}")
    plt.gca().set_xticklabels([])
    #plt.gca().tick_params(axis='x', which='both', length=8)
    #plt.gca().tick_params(axis='y', which='both', length=8)
    plt.yticks([std_max, 100], ["",  ""])
    plt.ylim(std_max, 100)
    plt.xlim(0, len(percentages))
    plt.yscale('log')
    plt.plot(range(len(percentages)), percentages, label="Reachable %")

    #if all_gp_idx != 0:
        #plt.axvline(all_gp_idx, color="blue", linestyle="--", label="GP index")
    #if all_tee_std_idx != 0:
    #    plt.axvline(all_tee_std_idx, color="orange", linestyle="--", label="TEE std index")
    #if all_tee_idx != 0:
        #plt.axvline(all_tee_idx, color="red", linestyle="--", label="TEE index")
    #if all_libc_idx != 0:
        #plt.axvline(all_libc_idx, color="green", linestyle="--", label="libc index")

    plt.tight_layout()
    
    #plt.xlabel("API")
    #plt.ylabel("Reachable (%)")
    #plt.title("Reachable Nodes as % of Max Nodes")
    #plt.legend()
    #plt.grid(True, linestyle="--", alpha=0.6) 
    return plt

def print_info(cfg, reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy="legacy"):
    print(f'overall reachable bbs: {max_nodes}')
    print(f'nr gp_api funcs: {nr_gp}')
    print(f'nr libc funcs: {nr_libc}')
    print(f'nr tee funcs: {nr_tee}')
    if strategy != "pure_gain":
        std_reachable = min(reachable[-nr_tee-1::])
        print(f'% reachable with gp, libc and tee-std', 100* std_reachable/reachable[-1], '%')

def build_ranking_output(reachable, max_nodes, implemented_apis, strategy):
    ranking = []
    previous = reachable[0] if reachable else 0
    for idx, call in enumerate(implemented_apis):
        current = reachable[idx + 1]
        ranking.append({
            "rank": idx + 1,
            "gain": current - previous,
            "reachable_bbs": current,
            "reachable_pct": (100.0 * current / max_nodes) if max_nodes else 0.0,
            "api": call.to_dict(),
        })
        previous = current
    return {
        "strategy": strategy,
        "baseline_reachable_bbs": reachable[0] if reachable else 0,
        "max_reachable_bbs": max_nodes,
        "implemented_api_count": len(implemented_apis),
        "ranking": ranking,
    }

def analyze_ta(ta_path):
    cfg = cfg_ta(ta_path)
    strategy = "pure_gain" if uses_pure_gain_ranking(cfg) else "legacy"
    print("=== OS interactions: ===")
    for node, data in cfg.nodes(data=True):
        if "svc" in data and len(data["svc"]) > 0:
            # Find all simple paths from start_node to this node
            path = list(nx.shortest_path(cfg, source=root, target=node))       
            print(" -> ".join(path), "svc:", data["svc"])
     
    print(len(nx.descendants(cfg, root)))
    nothing_cfg = trim_cfg(cfg, []) 
    print(len(nx.descendants(nothing_cfg, root)))
    for ta_fw in cfg.neighbors(root):
        print(ta_fw, len(nx.descendants(cfg, ta_fw)))
    """
    pos = graphviz_layout(cfg, prog="dot", args="-Grankdir=TB")
    nx.draw(cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    plt.show()    
    pos = graphviz_layout(nothing_cfg, prog="dot", args="-Grankdir=TB")
    nx.draw(nothing_cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    plt.show()    
    """
    reachable, max_nodes, nr_gp, nr_libc, nr_tee, implemented_apis = generate_graph(
        cfg, strategy=strategy
    )
    print("max_nodes", max_nodes)
    plt = gen_plot(reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy=strategy)
    out_path = f'ta_reach.pdf'
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1) 
    ta_path = os.path.abspath(ta_path)
    ta_dir = os.path.dirname(ta_path)
    ta_name = os.path.basename(ta_path)
    ranking_json = build_ranking_output(reachable, max_nodes, implemented_apis, strategy)
    open(os.path.join(ta_dir, "bbs", f"rank_{ta_name}.json"), "w+").write(json.dumps(ranking_json, indent=2))
    open(os.path.join(ta_dir, "bbs", f"order_{ta_name}.txt"), "w+").write('\n'.join(c.func for c in implemented_apis))
    print_info(cfg, reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy=strategy)

def build_tee_cfg(tee_path, only_tee=True, specific_tas=None):
    global do_ta_uuid
    global tee_name
    do_ta_uuid = True
    tee = os.path.basename(tee_path)
    tee_name = tee
    ta_paths = []
    if specific_tas is None:
        ta_paths = list(iter_ta_targets(os.path.join(tee_path, "tas")))
    else:
        ta_paths = [Path(ta_path) for ta_path in specific_tas]
    payload = {
        "version": CFG_CACHE_VERSION,
        "kind": "build_tee_cfg",
        "tee_path": Path(tee_path).resolve().as_posix(),
        "tee": tee,
        "only_tee": only_tee,
        "tas": [cfg_ta_cache_payload(ta_path) for ta_path in ta_paths],
    }
    cached = read_pickle_cache("build_tee_cfg", payload)
    if cached is not None:
        log.info(f"build_tee_cfg cache hit: {tee_path}")
        return cached
    ta_cfgs = []
    for ta_path in ta_paths:
        ta_cfgs.append(cfg_ta(ta_path))

    function_counter = Counter()
    api_type_counter = Counter()
    for cfg in ta_cfgs:
        ta_apis = get_apis(cfg)
        function_counter.update([a.func for a in ta_apis])
        api_type_counter.update(set([a.api_type for a in ta_apis]))
    
    for api_type, count in api_type_counter.items():
        print(f'[{tee}] nr tas using {api_type} {count}')

    print(f'[{tee}] analyzing {tee}, nr cfgs: {len(ta_cfgs)}') 
    BBS_OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (BBS_OUT_DIR / f"{tee}_func_count.txt").open('w') as f:
        for k, a in sorted(function_counter.items(), key=lambda x: x[1], reverse=True):
            f.write(f'{k} {a}\n')

    tee_cfg = nx.compose_all(ta_cfgs)
    if only_tee:
        root_name = label(root, no_uuid=True)
    else:
        root_name = label(root, do_tee_name=True)
    tee_cfg.add_node(root_name)
    for ta_cfg in ta_cfgs:
        ta_root_node = get_root_node(ta_cfg)
        tee_cfg.add_edge(root_name, ta_root_node) 
    print(f'size tee cfg: ', len(nx.descendants(tee_cfg, root_name)))
    write_pickle_cache("build_tee_cfg", payload, tee_cfg)
    return tee_cfg 

def analyze_tee(tee_path, specific_tas=None, strategy=None):
    tee = os.path.basename(tee_path)
    if strategy is None:
        strategy = "pure_gain" if tee == "qsee_nongp" else "legacy"
    assert strategy in {"pure_gain", "legacy"}

    tee_cfg = build_tee_cfg(tee_path, only_tee=True, specific_tas=specific_tas)
    #pos = graphviz_layout(tee_cfg, prog="dot", args="-Grankdir=TB")
    #nx.draw(tee_cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    #plt.show() 
    reachable, max_nodes, nr_gp, nr_libc, nr_tee, implemented_apis = generate_graph(
        tee_cfg, todo=tee, strategy=strategy
    )
    plt = gen_plot(reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy=strategy)
    out_path = f'bbs_out/{tee}_reachable.pdf'
    open(f'bbs_out/{tee}_order.txt', 'w+').write('\n'.join(c.func for c in implemented_apis))
    open(f'bbs_out/{tee}.json','w+').write(json.dumps(reachable))
    open(f'bbs_out/{tee}_ranking.json', 'w+').write(
        json.dumps(build_ranking_output(reachable, max_nodes, implemented_apis, strategy), indent=2)
    )
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1) 
    print_info(tee_cfg, reachable, max_nodes, nr_gp, nr_libc, nr_tee, strategy=strategy)
    print(40*"=")
    
def analyze_all():
    global do_ta_uuid
    global do_tee_name
    do_ta_uuid = True
    do_tee_name = True
    tees = ALL_TEES
    tee_cfgs = [] 
    for tee in tees:
        tee_path = f'../{tee}'
        tee_cfgs.append(build_tee_cfg(tee_path, only_tee=False))  
    all_cfg = nx.compose_all(tee_cfgs)
    root_all = label(root, no_uuid=True)
    all_cfg.add_node(root_all)
    for i, tee_cfg in enumerate(tee_cfgs):
        tee_root_node = get_root_node(tee_cfg, tee=tees[i])
        print('size tee_cfg', len(nx.descendants(tee_cfg, tee_root_node)))
        all_cfg.add_edge(root_all, tee_root_node)
        print('size all cfg', len(nx.descendants(all_cfg, root_all)))
    reachable, max_nodes, nr_gp, nr_libc, nr_tee, implemented_apis = generate_graph(all_cfg, todo='all')
    #if all_gp_idx > all_tee_std_idx: 
        #print("bricked!!")
        #exit(-1)
    plt = gen_plot(reachable, max_nodes, nr_gp, nr_libc, nr_tee)
    out_path = f'bbs_out/all_reachable.pdf'
    open(f'bbs_out/all_order.txt', 'w+').write('\n'.join(c.func for c in implemented_apis))
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1) 
    print_info(all_cfg, reachable, max_nodes, nr_gp, nr_libc, nr_tee)
    print(40*"=")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage [path to ta], [path to tee folder], all")
        exit(-1)
    inp_path = sys.argv[1]
    if inp_path.endswith(".ta") or inp_path.endswith(".elf"):
        analyze_ta(sys.argv[1])
    elif inp_path == "all":
        analyze_all()
    elif inp_path == "full":
        for tee in ALL_TEES:
            analyze_tee(f'../{tee}')
        analyze_all()
    elif inp_path == "tee-select":
        all_tas = list(sys.argv[2:])
        tee_path = Path(sys.argv[2]).parent.parent
        analyze_tee(tee_path.as_posix(), specific_tas=all_tas)
    elif Path(inp_path).is_dir():
        log.info(f"analyzing tee: {inp_path.strip('/')}")
        analyze_tee(inp_path.strip('/'))
    else:
        log.error(f"invalid input: {inp_path}")
        exit(-1)
