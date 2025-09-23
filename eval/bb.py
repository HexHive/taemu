import networkx as nx
import matplotlib
import json
import os
import sys
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout
from multiprocessing import Pool, cpu_count

ta_fw = ["TA_CreateEntryPoint", "TA_OpenSessionEntryPoint", "TA_InvokeCommandEntryPoint", "TA_CloseSessionEntryPoint", "TA_DestroyEntryPoint"]

ta_uuid = None
do_ta_uuid = False

def int2hex(nr):
    h = hex(nr)[2:]
    return '0' * (8-len(h)) + h

def label(addr, no_uuid=False):
    global ta_uuid
    if no_uuid:
        return addr
    if do_ta_uuid:
        return f'{ta_uuid}_{addr}'
    else:
        return addr

class Call:
    def __init__(self, json_data):
        self.func = json_data["func"]
        self.is_api = json_data["api"]
        self.api_type = json_data["api_type"]

    def __hash__(self):
        return hash(f'{self.func}_{self.is_api}_{self.api_type}')
    
    def __str__(self):
        return f'{self.func}_{self.is_api}_{self.api_type}'
    
    def __repr__(self):
        return f'{self.func}_{self.is_api}_{self.api_type}'
    
    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

root = '0'*8

def cfg_ta(ta_path):
    global ta_uuid
    cfg = nx.DiGraph()
    ta_dir = os.path.dirname(ta_path)
    ta_name = os.path.basename(ta_path)
    ta_uuid = ta_name[:-3]
    ta_json = json.load(open(ta_path[:-3]+".json"))
    bb_data = json.load(open(os.path.join(ta_dir, 'bbs', 'bb_' + ta_name + '.json')))
    cfg.add_node(label(root))
    for ta_entry in ta_fw:
        ta_entry = ta_entry + "_start"
        ta_entry_addr = ta_json[ta_entry]
        if ta_entry_addr == -1: continue
        cfg.add_node(label(int2hex(ta_entry_addr)))
        cfg.add_edge(label(root), label(int2hex(ta_entry_addr)))
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
            for call in bb["calls"]:
                if not call['api']:
                    fcall_lbl = label(call["func"])
                    if fcall_lbl not in cfg.nodes:
                        cfg.add_node(fcall_lbl)
                    cfg.add_edge(bb_l, fcall_lbl)
                else:
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

def reachable_nodes(cfg, implemented_apis):
    trimmed_cfg = trim_cfg(cfg, implemented_apis)
    return len(nx.descendants(trimmed_cfg, root)) 

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
        with Pool(cpu_count()-1) as pool:
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

def is_std(call):
    return call.api_type == "tee_std"

def is_tee(call):
    return call.api_type == "tee"

def generate_graph(cfg):
    reachable = []
    used_apis = get_apis(cfg)
    max_nodes = reachable_nodes(cfg, used_apis)
    print("nr used apis", len(used_apis))
    print("nr gp apis", len([a for a in used_apis if a.api_type == "gp_api"]))
    print("nr libc apis", len([a for a in used_apis if a.api_type == "libc"]))
    print("nr tee apis", len([a for a in used_apis if a.api_type.startswith("tee")]))
    implemented_apis = []
    i = 0
    reachable.append(reachable_nodes(cfg, implemented_apis))
    i+= 1
    all_gp_idx = 0
    all_libc_idx = 0
    all_tee_std_idx = 0
    all_tee_idx = 0
    while 1:
        max_api = find_best_add(cfg, used_apis, implemented_apis, is_gp)
        if max_api is None: 
            all_gp_idx = i-1
            break
        print("gp", max_api)
        used_apis.remove(max_api)
        implemented_apis.append(max_api)
        reachable.append(reachable_nodes(cfg, implemented_apis))
        i += 1
    while 1:
        max_api = find_best_add(cfg, used_apis, implemented_apis, is_libc)
        if max_api is None: 
            all_libc_idx = i-1
            break
        print("libc", max_api)
        used_apis.remove(max_api)
        implemented_apis.append(max_api)
        reachable.append(reachable_nodes(cfg, implemented_apis))
        i += 1
    while 1:
        max_api = find_best_add(cfg, used_apis, implemented_apis, is_std)
        if max_api is None: 
            all_tee_std_idx = i-1
            break
        print("gp_std", max_api)
        used_apis.remove(max_api)
        implemented_apis.append(max_api)
        reachable.append(reachable_nodes(cfg, implemented_apis))
        i += 1
    while 1:
        max_api = find_best_add(cfg, used_apis, implemented_apis, is_tee)
        if max_api is None: 
            all_tee_idx = i-1
            break
        print("tee", max_api)
        used_apis.remove(max_api)
        implemented_apis.append(max_api)
        reachable.append(reachable_nodes(cfg, implemented_apis))
        i += 1
    print("imlemented apis", len(implemented_apis)) 
    print(reachable)
    return reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx

def get_root_node(ta_cfg):
    for n in ta_cfg.nodes:
        if n.endswith(root):   
            return n

def gen_plot(reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx):
    plt.clf()
    matplotlib.rcParams['mathtext.fontset'] = 'custom'
    matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
    matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
    matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
    matplotlib.rcParams['mathtext.fontset'] = 'stix'
    matplotlib.rcParams['font.family'] = 'STIXGeneral'
    percentages = [r / max_nodes * 100 for r in reachable]
    #plt.gca().set_xticklabels([])
    #plt.gca().tick_params(axis='x', which='both', length=8)
    #plt.gca().tick_params(axis='y', which='both', length=8)
    plt.gca().margins(y=0.05, x=0.005)
    plt.plot(range(len(reachable)), percentages, label="Reachable %")

    if all_gp_idx != 0:
        plt.axvline(all_gp_idx, color="red", linestyle="--", label="GP index")
    if all_tee_std_idx != 0:
        plt.axvline(all_tee_std_idx, color="blue", linestyle="--", label="TEE std index")
    if all_tee_idx != 0:
        plt.axvline(all_tee_idx, color="green", linestyle="--", label="TEE index")
    if all_libc_idx != 0:
        plt.axvline(all_libc_idx, color="orange", linestyle="--", label="libc index")

    plt.tight_layout()
    
    #plt.xlabel("API")
    #plt.ylabel("Reachable (%)")
    #plt.title("Reachable Nodes as % of Max Nodes")
    #plt.legend()
    #plt.grid(True, linestyle="--", alpha=0.6) 
    return plt

def print_info(cfg, reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx):
    print(f'overall reachable bbs: {max_nodes}')
    print(f'nr gp_api funcs: {all_gp_idx}')
    print(f'nr libc funcs: {all_libc_idx - all_gp_idx}')
    print(f'nr tee_std funcs: {all_tee_std_idx - all_libc_idx}')
    print(f'nr tee funcs: {all_tee_idx - all_tee_std_idx}')

def analyze_ta(ta_path):
    cfg = cfg_ta(ta_path)
    print("=== OS interactions: ===")
    for node, data in cfg.nodes(data=True):
        if "svc" in data and len(data["svc"]) > 0:
            # Find all simple paths from start_node to this node
            path = list(nx.shortest_path(cfg, source=root, target=node))       
            print(" -> ".join(path), "svc:", data["svc"])
     
    print(len(nx.descendants(cfg, root)))
    nothing_cfg = trim_cfg(cfg, []) 
    print(len(nx.descendants(nothing_cfg, root)))
    """
    pos = graphviz_layout(cfg, prog="dot", args="-Grankdir=TB")
    nx.draw(cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    plt.show()    
    pos = graphviz_layout(nothing_cfg, prog="dot", args="-Grankdir=TB")
    nx.draw(nothing_cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    plt.show()    
    """
    reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx = generate_graph(cfg)
    print("max_nodes", max_nodes)
    plt = gen_plot(reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx)
    plt.show()
    out_path = f'ta_reach.pdf'
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1) 
    print_info(cfg, reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx)


def analyze_tee(tee_path):
    global do_ta_uuid
    do_ta_uuid = True
    tee = os.path.basename(tee_path)
    ta_cfgs = [] 
    for ta in [ta for ta in os.listdir(os.path.join(tee_path, "tas")) if ta.endswith(".ta")]:
        ta_path = os.path.join(tee_path, 'tas', ta)
        if not os.path.exists(ta_path[:-3]+".json"): continue
        ta_cfgs.append(cfg_ta(ta_path))
    nr_tas_gp_api = 0
    nr_tas_libc = 0
    nr_tas_tee = 0
    for cfg in ta_cfgs:
        ta_apis = get_apis(cfg)
        if len([a for a in ta_apis if a.api_type == "gp_api"]) > 0: nr_tas_gp_api += 1
        if len([a for a in ta_apis if a.api_type == "libc"]) > 0: nr_tas_libc += 1
        if len([a for a in ta_apis if a.api_type.startswith("tee")]) > 0: nr_tas_tee += 1
    print(f'nr tas using gp_api {nr_tas_gp_api}')
    print(f'nr tas using libc {nr_tas_libc}')
    print(f'nr tas using tee {nr_tas_tee}')
    print(f'analyzing {tee}, nr cfgs: {len(ta_cfgs)}')
    tee_cfg = nx.compose_all(ta_cfgs) 
    tee_cfg.add_node(label(root, no_uuid=True))
    for ta_cfg in ta_cfgs:
        ta_root_node = get_root_node(ta_cfg)
        tee_cfg.add_edge(label(root, no_uuid=True), ta_root_node)
    #pos = graphviz_layout(tee_cfg, prog="dot", args="-Grankdir=TB")
    #nx.draw(tee_cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    #plt.show() 
    reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx = generate_graph(tee_cfg)
    plt = gen_plot(reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx)
    out_path = f'{tee}_reachable.pdf'
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1) 
    print_info(cfg, reachable, max_nodes, all_gp_idx, all_libc_idx, all_tee_std_idx, all_tee_idx)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage [path to ta], [path to tee folder], all")
    inp_path = sys.argv[1]
    if inp_path.endswith(".ta"): 
        analyze_ta(sys.argv[1])
    elif inp_path == "all":
        analyze_all()
    else:
        analyze_tee(inp_path.strip('/'))
