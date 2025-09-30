import threading
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import queue
import os
import time
import subprocess
import sys

from bb import build_tee_cfg
from fuzz import fuzz_time

root = 8*"0"
BASE = os.path.join(os.path.dirname(__file__), "..")
tees = ["teegris", "mitee", "beanpod", "t6"]

class BB:
    def __init__(self, ta, start, size):
        self.start = start
        self.size = size
        self.ta = ta

    def __eq__(self, other):
        return self.start == other.start and self.size == other.size and self.ta == other.ta
    
    def __hash__(self):
        return hash((self.start, self.size, self.ta))

def get_root_ta_node(cfg, ta):
    for n in cfg.nodes:
        if f'{ta[:-3]}_{8*"0"}' in n:
           return n
    return None

def is_covered(node, bbbs):
    if "start" not in node:
        return False
    for bbb in bbbs:
        if bbb.start >= int(node["start"],16) and bbb.start+bbb.size <= int(node["end"],16):
            return True
    return False

def parse_drcov(ta, path):
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
            bbs_out.append(BB(ta, start, size))
        bbs = bbs[8:]
    return bbs_out

def parse_cov(ta, drcov_path):
    out = {}
    for cov_file in os.listdir(drcov_path):
        try:
            timestamp = int(int(cov_file.split("time:")[-1].split(",")[0])/1000)
        except:
            continue
        bbs = parse_drcov(ta, os.path.join(drcov_path, cov_file))
        out[timestamp] = bbs
    return out

def gen_graph(tee, ta2bbs, max_bbs):
    t2bbs = {}
    for ta, data in ta2bbs.items():
        for timestamp, bbs in data.items():
            if timestamp > fuzz_time:
                continue
            if timestamp not in t2bbs:
                t2bbs[timestamp] = list(set(bbs))
            else:
                t2bbs[timestamp] = list(set(t2bbs[timestamp] + bbs)) 
    x = [0]
    y = [0] 
    bball = set()
    for t, bbs in sorted(t2bbs.items(), key=lambda x: x[0]):
        for bb in bbs: bball.add(bb)
        x.append(t)
        y.append(len(bball)) 
    print(tee)
    print("x", x)
    print("y", y)
    x.append(fuzz_time)
    y.append(y[-1])
    matplotlib.rcParams['mathtext.fontset'] = 'custom'
    matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
    matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
    matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
    matplotlib.rcParams['mathtext.fontset'] = 'stix'
    matplotlib.rcParams['font.family'] = 'STIXGeneral'
    plt.clf()
    plt.plot(x,y)
    plt.gca().set_xticklabels([])
    plt.gca().tick_params(axis='x', which='both', length=8)
    plt.gca().tick_params(axis='y', which='both', length=8)
    plt.gca().margins(y=0, x=0.005)
    ax = plt.gca()
    lines = ax.get_lines()
    max_y = max([max(line.get_ydata()) for line in lines])
    plt.ylim(0, max_bbs)
    yticks = [0, int(max_bbs/2), max_bbs]
    ylabels = ['','','']
    ax.set_yticks(yticks)
    ax.set_yticklabels([])
    if fuzz_time == 86400:
        xticks = [0, 36000, 72000]
        ax.set_xticks(xticks)
    plt.tight_layout()
    plt.gcf().subplots_adjust(left=0.115)
    out = f'{BASE}/eval/fuzz_graphs'
    if not os.path.exists(out):
        os.system(f'mkdir -p {out}')
    out_path = os.path.join(out, f'{tee}.pdf')
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1)
    return x,y
 

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
        ta2bbs[ta] = parse_cov(ta, os.path.join(harness_path, "out", "cov")) 
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
    tee_cfg = build_tee_cfg(tee, only_tee=True, specific_tas=tas)
    #print([n for n in nx.descendants(tee_cfg, root)])
    print(len(nx.descendants(tee_cfg, root)), len(set(nx.descendants(tee_cfg, root))))
    out[tee]['max_bbs'] = len(nx.descendants(tee_cfg, root))
    out[tee]['fuzz_bbs'] = sum([len(bbs) for _,bbs in ta2bbs_merged.items()])
    out[tee]['ta2bbs'] = ta2bbs

all_ta2bbs = {}   
all_bbs = 0
all_crashes = 0
all_bugs = 0
all_notimpl = 0
all_tas = 0
for tee in tees: 
    x,y = gen_graph(tee, out[tee]['ta2bbs'], out[tee]['max_bbs'])
    all_ta2bbs = all_ta2bbs | out[tee]['ta2bbs']
    all_bbs += out[tee]['max_bbs']
    all_crashes += out[tee]['crashes']
    all_bugs += out[tee]['bugs']
    all_notimpl += out[tee]['notimpl']
    all_tas += out[tee]['nr_tas']
    print(f'{tee} reached bbs: {max(y)}, max bbs: {out[tee]["max_bbs"]}')
x,y = gen_graph('all', all_ta2bbs, all_bbs)
print(f'all reached bbs: {max(y)}, max bbs: {all_bbs}')

print(f'crashes')
for tee in tees:
    print(f'{tee} nr tas: {out[tee]["nr_tas"]} crashes: {out[tee]["crashes"]}, bugs: {out[tee]["bugs"]}, notimpl: {out[tee]["notimpl"]}')
print(f'all nr tas: {all_tas} crashes: {all_crashes}, bugs: {all_bugs}, notimpl: {all_notimpl}')

