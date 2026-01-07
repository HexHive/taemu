import threading
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import queue
import os
import time
import subprocess
import sys

from graphs.bb import build_tee_cfg
from fuzz import FUZZ_TIME, TEES, FUZZ_CHUNKS, FUZZ_ITERATIONS, COV_DIR, CAMPAIGN_DIR

"""
After a fuzzing campaign, generate the coverage graphs for each TEE + merged
x-axis: time
y-axis: coverage
"""

if "TAEMU_FUZZ_TEE" in os.environ:
    TEES = [os.environ["TAEMU_FUZZ_TEE"]]

root = 8 * "0"
BASE = os.path.join(os.path.dirname(__file__), "..")


class BB:
    def __init__(self, ta, start, size):
        self.start = start
        self.size = size
        self.ta = ta

    def __eq__(self, other):
        return (
            self.start == other.start
            and self.size == other.size
            and self.ta == other.ta
        )

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
        if bbb.start >= int(node["start"], 16) and bbb.start + bbb.size <= int(
            node["end"], 16
        ):
            return True
    return False


def parse_drcov(tee, ta, path):
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
        mod_id = int.from_bytes(bbs[6:8], "little")
        if mod_id == ta_id:
            if tee == "beanpod" or tee == "t6":
                start = base + start
            bbs_out.append(BB(ta, start, size))
        bbs = bbs[8:]
    return bbs_out


def parse_cov(tee, ta, drcov_path):
    out = {}
    for cov_file in os.listdir(drcov_path):
        try:
            timestamp = int(int(cov_file.split("time:")[-1].split(",")[0]) / 1000)
        except:
            continue
        bbs = parse_drcov(tee, ta, os.path.join(drcov_path, cov_file))
        out[timestamp] = bbs
    return out


def parse_cov_seeds(tee, ta, drcov_path_seeds):
    out = {}
    for index in os.listdir(drcov_path_seeds):
        queue_path = os.path.join(drcov_path_seeds, index, "cov")
        for cov_file in os.listdir(queue_path):
            try:
                timestamp = int(int(cov_file.split("time:")[-1].split(",")[0]) / 1000)
            except:
                continue
            bbs = parse_drcov(tee, ta, os.path.join(queue_path, cov_file))
            out[timestamp + 60 * 60 * int(index)] = bbs
    return out


def get_ys(coords, x):
    out = []
    for xc, yc in coords:
        if x in xc:
            out.append(yc[xc.index(x)])
        else:
            out.append(np.interp(x, xc, yc))
    return out


def aggregate(coords):
    y_max = []
    y_min = []
    y_med = []
    x_aggr = []
    all_x = set()
    for x, _ in coords:
        for xx in x:
            all_x.add(xx)
    x_aggr = list(sorted(list(all_x)))
    print(x_aggr)
    for x in x_aggr:
        all_y = get_ys(coords, x)
        y_max.append(max(all_y))
        y_min.append(min(all_y))
        y_med.append(np.median(all_y))
    return y_max, y_min, y_med, x_aggr


def gen_graph(tee, ta2bbs, max_bbs):
    coords = []
    for campaign_iteration in range(0, FUZZ_ITERATIONS):
        t2bbs = {}
        for ta, data in ta2bbs[campaign_iteration].items():
            for timestamp, bbs in data.items():
                if timestamp > FUZZ_TIME:
                    continue
                if timestamp not in t2bbs:
                    t2bbs[timestamp] = list(set(bbs))
                else:
                    t2bbs[timestamp] = list(set(t2bbs[timestamp] + bbs))
        x = [0]
        y = [0]
        bball = set()
        for t, bbs in sorted(t2bbs.items(), key=lambda x: x[0]):
            for bb in bbs:
                bball.add(bb)
            x.append(t)
            y.append(len(bball))
        coords.append((x, y))
    y_max, y_min, y_median, x = aggregate(coords)
    print(tee)
    print("x", x)
    print("y", y)
    x.append(FUZZ_TIME)
    y_max.append(y_max[-1])
    y_min.append(y_min[-1])
    y_median.append(y_median[-1])
    matplotlib.rcParams["mathtext.fontset"] = "custom"
    matplotlib.rcParams["mathtext.rm"] = "Bitstream Vera Sans"
    matplotlib.rcParams["mathtext.it"] = "Bitstream Vera Sans:italic"
    matplotlib.rcParams["mathtext.bf"] = "Bitstream Vera Sans:bold"
    matplotlib.rcParams["mathtext.fontset"] = "stix"
    matplotlib.rcParams["font.family"] = "STIXGeneral"
    plt.clf()
    plt.fill_between(x, y_min, y_max, color="orange", alpha=0.2)
    plt.plot(x, y_median, color="orange")
    plt.plot(x, y_min, linestyle="none")
    plt.plot(x, y_max, linestyle="none")
    # plt.plot(x,y)
    plt.gca().set_xticklabels([])
    plt.gca().tick_params(axis="x", which="both", length=8)
    plt.gca().tick_params(axis="y", which="both", length=8)
    plt.gca().margins(y=0, x=0.005)
    ax = plt.gca()
    plt.ylim(0, max_bbs)
    yticks = [0, int(max_bbs / 2), max_bbs]
    ylabels = ["", "", ""]
    ax.set_yticks(yticks)
    ax.set_yticklabels([])
    if FUZZ_TIME == 86400:
        xticks = [0, 36000, 72000]
        ax.set_xticks(xticks)
    plt.tight_layout()
    plt.gcf().subplots_adjust(left=0.115)
    out = f"{BASE}/eval/fuzz_graphs"
    if not os.path.exists(out):
        os.system(f"mkdir -p {out}")
    out_path = os.path.join(out, f"{tee}.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.1)
    return x, y


out = {}
for tee in TEES:
    out[tee] = {
        "nr_tas": 0,
        "max_bbs": 0,
        "fuzz_bbs": 0,
        "crashes": 0,
        "bugs": 0,
        "notimpl": 0,
    }
    tas = []
    ta2bbs = {}
    ta2bbs_merged = {}
    for harness in os.listdir(os.path.join(BASE, tee, "harness")):
        ta = None
        harness_path = os.path.join(BASE, tee, "harness", harness)
        if os.path.exists(os.path.join(BASE, tee, "harness", harness, "IGNOREME")):
            continue
        print(f"handling {harness_path}")
        for f in os.listdir(harness_path):
            if f.endswith(".ta"):
                ta = f
                tas.append(os.path.realpath(os.path.join(harness_path, f)))
                break
        if ta is None:
            print(f"?????", ta)
            continue
        campaign_out = os.path.join(harness_path, CAMPAIGN_DIR)
        ta2bbs[ta] = {}
        for campaign_iteration in range(0, FUZZ_ITERATIONS):
            print(f"processing {campaign_out} {campaign_iteration}")
            iteration_dir = os.path.join(campaign_out, campaign_iteration)
            if FUZZ_TIME > 60 * 60:
                ta2bbs[ta][campaign_iteration] = parse_cov_seeds(
                    tee, ta, os.path.join(iteration_dir, FUZZ_CHUNKS)
                )
            else:
                ta2bbs[ta][campaign_iteration] = parse_cov(
                    tee, ta, os.path.join(harness_path, "out", "cov")
                )
        unique_bbs = set()
        for campaign_iteration in range(0, FUZZ_ITERATIONS):
            for timestamp, bbss in ta2bbs[ta][campaign_iteration].items():
                for bb in bbss:
                    unique_bbs.add(bb)
        ta2bbs_merged[ta] = list(unique_bbs)
        if os.path.exists(os.path.join(harness_path, "triage")):
            out[tee]["bugs"] += len(os.listdir(os.path.join(harness_path, "triage")))
            out[tee]["crashes"] += len(os.listdir(os.path.join(harness_path, "triage")))
        if os.path.exists(os.path.join(harness_path, "notimpl")):
            out[tee]["notimpl"] += len(
                os.listdir(os.path.join(harness_path, "notimpl"))
            )
            out[tee]["crashes"] += len(
                os.listdir(os.path.join(harness_path, "notimpl"))
            )
    tas = list(set(tas))
    print(f"{tee}, {tas}")
    out[tee]["nr_tas"] = len(tas)
    tee_cfg = build_tee_cfg(tee, only_tee=True, specific_tas=tas)

    def in_cfg(ta, bb, cfg):
        nodes = nx.descendants(cfg, ta[:-3] + "_" + 8 * "0")
        for n in nodes:
            if not "start" in cfg.nodes[n] or not "end" in cfg.nodes[n]:
                continue
            if bb.start >= int(cfg.nodes[n]["start"], 16) and bb.start + bb.size <= int(
                cfg.nodes[n]["end"], 16
            ):
                return True
        return False

    """
    ta2bbs_cfg = {}
    cfg_unique_bbs = set()
    not_ctg_bbs = set()
    for ta, data in ta2bbs.items():
        ta2bbs_cfg[ta] = {}
        for timestamp, bbs in data.items():
            ta2bbs_cfg[ta][timestamp] = []
            for bb in bbs:
                if bb in not_ctg_bbs:
                    continue
                if bb in cfg_unique_bbs:
                    ta2bbs_cfg[ta][timestamp].append(bb)
                else:
                    if in_cfg(ta, bb, tee_cfg): 
                        ta2bbs_cfg[ta][timestamp].append(bb)
                        cfg_unique_bbs.add(bb)
                    else:
                        not_ctg_bbs.add(bb)
    #print([n for n in nx.descendants(tee_cfg, root)])
    print("cfg bbs", len(nx.descendants(tee_cfg, root)), len(cfg_unique_bbs))
    """
    out[tee]["max_bbs"] = len(nx.descendants(tee_cfg, root))
    out[tee]["fuzz_bbs"] = sum([len(bbs) for _, bbs in ta2bbs_merged.items()])
    out[tee]["ta2bbs"] = ta2bbs

all_ta2bbs = {}
all_bbs = 0
all_crashes = 0
all_bugs = 0
all_notimpl = 0
all_tas = 0
for tee in TEES:
    max_bbs = gen_graph(tee, out[tee]["ta2bbs"], out[tee]["max_bbs"])
    out[tee]["bbs"] = max_bbs
    all_ta2bbs = all_ta2bbs | out[tee]["ta2bbs"]
    all_bbs += out[tee]["max_bbs"]
    all_crashes += out[tee]["crashes"]
    all_bugs += out[tee]["bugs"]
    all_notimpl += out[tee]["notimpl"]
    all_tas += out[tee]["nr_tas"]
    print(f'{tee} reached bbs: {max(y)}, max bbs: {out[tee]["max_bbs"]}')
x, y = gen_graph("all", all_ta2bbs, all_bbs)
all_fuzz_bbs = max(y)
print(f"all reached bbs: {max(y)}, max bbs: {all_bbs}")

print(f"crashes")
for tee in TEES:
    print(
        f'{tee} nr tas: {out[tee]["nr_tas"]} crashes: {out[tee]["crashes"]}, bugs: {out[tee]["bugs"]}, notimpl: {out[tee]["notimpl"]}'
    )
print(
    f"all nr tas: {all_tas} crashes: {all_crashes}, bugs: {all_bugs}, notimpl: {all_notimpl}"
)

# print latex macros

# \newcommand{\numdatataskinibi}{31\xspace}


def print_latex(name, num):
    print(f"\\newcommand{{\\{name}}}{{{num}\\xspace}}")


for tee in TEES:
    if tee == "t6":
        tee_name = "tsix"
    else:
        tee_name = tee
    print_latex(f"numfuzztas{tee_name}", out[tee]["nr_tas"])
    print_latex(f"numfuzzcrashes{tee_name}", out[tee]["crashes"])
    print_latex(f"numfuzznotimpl{tee_name}", out[tee]["notimpl"])
    print_latex(f"numfuzzbug{tee_name}", out[tee]["bugs"])
    print_latex(f"numfuzzmaxbb{tee_name}", out[tee]["max_bbs"])
    print_latex(f"numfuzzbb{tee_name}", out[tee]["bbs"])

print_latex(f"numfuzztas", all_tas)
print_latex(f"numfuzzcrashes", all_crashes)
print_latex(f"numfuzznotimpl", all_notimpl)
print_latex(f"numfuzzbug", all_bugs)
print_latex(f"numfuzzmaxbb", all_bbs)
print_latex(f"numfuzzbb", all_fuzz_bbs)
