import networkx as nx
import json
import os
import sys
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout


ta_fw = ["TA_CreateEntryPoint", "TA_OpenSessionEntryPoint", "TA_InvokeCommandEntryPoint", "TA_CloseSessionEntryPoint", "TA_DestroyEntryPoint"]

ta_uuid = None
do_ta_uuid = False

def int2hex(nr):
    h = hex(nr)[2:]
    return '0' * (8-len(h)) + h

def label(addr):
    global ta_uuid
    if do_ta_uuid:
        return f'{ta_uuid}_{addr}'
    else:
        return addr

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
                    node["api_calls"].append(call)    
        # add intraprocedural edges    
        for bb in nodes:
            bb_l = label(bb['start'])
            for edge in bb["edges"]:
                cfg.add_edge(bb_l, bbname2bbll[edge])
    return cfg    

def analyze_ta(ta_path):
    cfg = cfg_ta(ta_path)
    for node, data in cfg.nodes(data=True):
        if "svc" in data and len(data["svc"]) > 0:
            # Find all simple paths from start_node to this node
            path = list(nx.shortest_path(cfg, source=root, target=node))       
            print(" -> ".join(path), "svc:", data["svc"])
    pos = graphviz_layout(cfg, prog="dot", args="-Grankdir=TB")
    nx.draw(cfg, pos, with_labels=True, node_color="lightblue", arrows=True)
    plt.show()    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage [path to ta], [path to tee folder], all")
    analyze_ta(sys.argv[1])
