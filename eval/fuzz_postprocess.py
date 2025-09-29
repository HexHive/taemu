import threading
import queue
import os
import time
import subprocess
import sys

from bb import build_tee_cfg
from fuzz import fuzz_time

BASE = os.path.join(os.path.dirname(__file__), "..")
tees = ["teegris", "mitee", "beanpod", "t6"]

class bb:
    def __init__(self, start, size):
        self.start = start
        self.size = size

    def __eq__(self, other):
        return self.start == other.start and self.size == other.size
    
    def __hash__(self):
        return hash((self.start, self.size))

def parse_drcov(path):
    bbs_out = []
    raw = open(path, "rb").read()
    ta_base = raw.split(b"timestamp, path\n")[-1]
    for l in ta_base.split(b"\n"):
        if b"emulator/rootfs" in l and b".ta" in l:
            base = l.split(b",")[1]
            base = int(base.decode())
            ta_id = int(l.split(b",")[0])
    nr_bbs = raw.split(b"BB Table: ")[-1]
    nr_bbs = int(nr_bbs.split(b"bbs\n")[0].decode())
    bbs = raw.split(b"bbs\n")[-1]
    for _ in range(nr_bbs):
        start = int.from_bytes(bbs[0:4], "little")
        size = int.from_bytes(bbs[4:6], "little")
        mod_id= int.from_bytes(bbs[6:8], "little")
        if mod_id == ta_id:
            bbs_out.append(bb(start, size))
        bbs = bbs[8:]
    return bbs_out

def parse_cov(drcov_path):
    out = {}
    for cov_file in os.listdir(drcov_path):
        try:
            timestamp = int(cov_file.split("time:")[-1].split(",")[0])  
        except:
            continue
        bbs = parse_drcov(os.path.join(drcov_path, cov_file))
        out[timestamp] = bbs
    return out

out = {}
for tee in tees:
    out[tee] = {
        'nr_tas': 0,
        'max_bbs': 0,
        'fuzz_bbs': 0,
        'crashes': 0,
        'bugs': 0,
        'notimpl': 0
    }
    tas = []
    ta2bbs = {}
    ta2bbs_merged = {}
    for harness in os.listdir(os.path.join(BASE, tee, "harness")):
        ta = None
        harness_path = os.path.join(BASE, tee, "harness", harness)
        print(f'handling {harness_path}')
        for f in os.listdir(harness_path):
            if f.endswith(".ta"):
                ta = f
                tas.append(os.path.realpath(os.path.join(harness_path, f)))
                break
        if ta is None:
            print(f'?????', ta)
            continue
        if not os.path.exists(os.path.join(harness_path, "out", "cov")):
            continue
        ta2bbs[ta] = parse_cov(os.path.join(harness_path, "out", "cov")) 
        unique_bbs = set()
        for timestamp, bbss in ta2bbs[ta].items():
            for bb in bbss:
                unique_bbs.add(bb)
        ta2bbs_merged[ta] = list(unique_bbs)
        if os.path.exists(os.path.join(harness_path, "triage")):
            out[tee]['bugs'] += len(os.listdir(os.path.join(harness_path, "triage")))
            out[tee]['crashes'] += len(os.listdir(os.path.join(harness_path, "triage")))
        if os.path.exists(os.path.join(harness_path, "notimpl")):
            out[tee]['notimpl'] += len(os.listdir(os.path.join(harness_path, "notimpl")))
            out[tee]['crashes'] += len(os.listdir(os.path.join(harness_path, "notimpl")))
    tas = list(set(tas))
    print(f'{tee}, {tas}')
    out[tee]['nr_tas'] = len(tas)
    print(out[tee])
    tee_cfg = build_tee_cfg(tee, only_tee=True, specific_tas=tas)
    #TODO mark root node covered
    for ta, bbs in ta2bbs_merged.items():
        root_ta_node = get_root_ta_node(tee_cfg)
        root_ta_node["covered"] = True
        for node in nx.descendants(tee_cfg, root_ta_node):
            if is_covered(node, bbs):
                node["covered"] = True 
    #TODO count covered blocks vs all 
    
          
