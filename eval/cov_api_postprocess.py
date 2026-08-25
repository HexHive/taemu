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
from fuzz_postprocess import BB, aggregate, parse_drcov
from cov_api import COV_API_DIR

"""
After a fuzzing campaign, generate the coverage graphs for each TEE + merged
x-axis: time
y-axis: coverage
"""

root = 8 * "0"
BASE = os.path.join(os.path.dirname(__file__), "..")


def gen_graph(tee, ta2bbs, max_bbs):
    coords = []
    for campaign_iteration in range(0, FUZZ_ITERATIONS):
        apis2bbs = {}
        for ta, data in ta2bbs[campaign_iteration].items():
            for nr_apis, bbs in data.items():
                apis2bbs[nr_apis] = list(set(bbs))
        x = [0]
        y = [0]
        bball = set()
        for t, bbs in apis2bbs.items():
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
        xticks = [0, len(x) // 2, x]
        ax.set_xticks(xticks)
    plt.tight_layout()
    plt.gcf().subplots_adjust(left=0.115)
    out = f"{BASE}/eval/api_cov_graphs"
    if not os.path.exists(out):
        os.system(f"mkdir -p {out}")
    out_path = os.path.join(out, f"{tee}.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.1)
    return x, y


campaigns = json.load(open("fuzz_config.json"))

out = {}
for tee in TEES:
    out[tee] = {
        "nr_tas": 0,
        "max_bbs": 0,
        "fuzz_bbs": 0,
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
        cov_api_dir = os.path.join(harness_path, COV_API_DIR)
        ta2bbs[ta] = {}
        unique_bbs = set()
        for campaign in campaigns:
            iteration_dir = os.path.join(harness_path, campaign)
            ta2bbs[ta][campaign] = {}
            for nr_apis in os.listdir(iteration_dir):
                drcov = os.path.join(iteration_dir, nr_apis, "drcov.log")
                bbs = parse_drcov(tee, ta, drcov)
                ta2bbs[ta][campaign][nr_apis] = bbs
                unique_bbs.add(bbs)
        ta2bbs_merged[ta] = list(unique_bbs)

    tas = list(set(tas))
    print(f"{tee}, {tas}")
    out[tee]["nr_tas"] = len(tas)
    tee_cfg = build_tee_cfg(tee, only_tee=True, specific_tas=tas)
    out[tee]["max_bbs"] = len(nx.descendants(tee_cfg, root))
    out[tee]["fuzz_bbs"] = sum([len(bbs) for _, bbs in ta2bbs_merged.items()])
    out[tee]["ta2bbs"] = ta2bbs

all_ta2bbs = {}
all_bbs = 0
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

# print latex macros

# \newcommand{\numdatataskinibi}{31\xspace}


def print_latex(name, num):
    print(f"\\newcommand{{\\{name}}}{{{num}\\xspace}}")


"""
for tee in TEES:
    if tee == "t6": tee_name = "tsix"
    else: tee_name = tee
    print_latex(f"numfuzztas{tee_name}", out[tee]['nr_tas'])
    print_latex(f"numfuzzcrashes{tee_name}", out[tee]['crashes'])
    print_latex(f"numfuzznotimpl{tee_name}", out[tee]['notimpl'])
    print_latex(f"numfuzzbug{tee_name}", out[tee]['bugs'])
    print_latex(f"numfuzzmaxbb{tee_name}", out[tee]['max_bbs'])
    print_latex(f"numfuzzbb{tee_name}", out[tee]['bbs'])

print_latex(f"numfuzztas", all_tas)
print_latex(f"numfuzzcrashes", all_crashes)
print_latex(f"numfuzznotimpl", all_notimpl)
print_latex(f"numfuzzbug", all_bugs)
print_latex(f"numfuzzmaxbb", all_bbs)
print_latex(f"numfuzzbb", all_fuzz_bbs)
"""
