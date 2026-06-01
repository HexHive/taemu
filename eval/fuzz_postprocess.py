# Purpose: Parse fuzzing campaign drcov outputs and produce coverage-over-time
# graphs for qsee_nongp and the merged qsee_nongp dataset.
# Depends on: campaign_out directories from eval/fuzz.py, drcov logs in harness
# coverage directories, eval/graphs CFG helpers, matplotlib, and numpy.
# Input: No CLI arguments; processes qsee_nongp runner/eval-style output only.

from dataclasses import dataclass
import datetime
import json
import logging
from pathlib import Path
import re
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

from bb import build_tee_cfg
from fuzz import FUZZ_TIME, FUZZ_CHUNKS, FUZZ_ITERATIONS, COV_DIR, CAMPAIGN_DIR

import colorama
import sys

log = logging.getLogger("triage")
log.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
# Make log coloured
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

"""
After a fuzzing campaign, generate the coverage graphs for qsee_nongp + merged
x-axis: time
y-axis: coverage
"""

TEES = ["qsee_nongp"]

ROOT_NODE = 8 * "0"
BASE = os.path.join(os.path.dirname(__file__), "..")
THIS_PATH = Path(__file__).resolve().parent

@dataclass(frozen=True, eq=True, unsafe_hash=True)
class BB:
    ta: str
    start: int
    size: int


class BBJSONEncoder(json.JSONEncoder):
    def default(self, value):
        if isinstance(value, BB):
            return {
                "ta": value.ta,
                "start": value.start,
                "size": value.size,
            }
        if isinstance(value, set):
            return sorted(value, key=lambda item: repr(item))
        if isinstance(value, Path):
            return value.as_posix()
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            return float(value)
        if isinstance(value, np.ndarray):
            return value.tolist()
        return super().default(value)


def get_root_ta_node(cfg, ta):
    for n in cfg.nodes:
        if f'{Path(ta).stem}_{8*"0"}' in n:
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


def parse_drcov_uncached(tee, ta, path):
    bbs_out:list[BB] = []
    raw = open(path, "rb").read()
    ta_base = raw.split(b"timestamp, path\n")[-1]
    for l in ta_base.split(b"\n"):
        if b"emulator/rootfs" in l and (b".ta" in l or b".elf" in l):
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
            bbs_out.append(BB(ta=ta, start=start, size=size))
        bbs = bbs[8:]
    return bbs_out


def parse_drcov(tee, ta, path):
    return parse_drcov_uncached(tee, ta, path)


def parse_cov(tee, ta, drcov_path):
    out = {}
    for cov_file in os.listdir(drcov_path):
        try:
            timestamp = int(int(cov_file.split("time:")[-1].split(",")[0]) / 1000)
        except ValueError:
            log.warning("invalid timestamp in %s", cov_file)
            continue
        bbs = parse_drcov(tee, ta, os.path.join(drcov_path, cov_file))
        out[timestamp] = bbs
    return out


# def __parse_drcov_seeds(tee, ta, *cov_files:Path):
#     out = {}
#     for cov_file in cov_files:
#         try:
#             timestamp = int(int(cov_file.name.split("time:")[-1].split(",")[0]) / 1000)
#         except ValueError:
#             log.warning("invalid timestamp in %s", cov_file)
#             continue
#         bbs = parse_drcov(tee, ta, cov_file.as_posix())
#         out[timestamp + 60 * 60 * int(index)] = bbs

def parse_cov_seeds(tee, ta, fuzz_chunks_dir):
    out = {}
    for fuzz_chunk_dir in Path(fuzz_chunks_dir).iterdir():
        cov_dir = fuzz_chunk_dir / "cov"
        if not cov_dir.exists():
            log.warning("no cov directory in %s", fuzz_chunk_dir)
            continue
        if not re.match(r"^\d+$", fuzz_chunk_dir.name):
            log.warning("invalid fuzz chunk directory name: %s", fuzz_chunk_dir)
            continue
        for cov_file in cov_dir.iterdir():
            try:
                timestamp = int(int(cov_file.name.split("time:")[-1].split(",")[0]) / 1000)
            except ValueError:
                continue
            bbs = parse_drcov(tee, ta, cov_file.as_posix())
            out[timestamp + 60 * 60 * int(fuzz_chunk_dir.name)] = bbs
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


TS = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
P = Path("postprocess_out") / TS
P.mkdir(exist_ok=True)

def write_json(relpath:Path, data:dict):
    assert not relpath.is_absolute()
    (P / relpath.parent).mkdir(exist_ok=True, parents=True)
    (P / relpath.with_suffix(".json")).write_text(
        json.dumps(data, indent=2, cls=BBJSONEncoder)
    )

def graph_filename(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name) + TS


def get_ta_max_bbs(cfg, ta):
    ta_root = get_root_ta_node(cfg, ta)
    if ta_root is None:
        print(f"missing CFG root for {ta}")
        return 0
    return len(nx.descendants(cfg, ta_root))


def gen_graph(name, ta2bbs, max_bbs, out_name=None):
    coords = []
    for campaign_iteration in range(0, FUZZ_ITERATIONS):
        t2bbs = {}
        for ta, iterations in ta2bbs.items():
            data = iterations.get(campaign_iteration, {})
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
    print(name)
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
    os.makedirs(out, exist_ok=True)
    if out_name is None:
        out_name = name
    out_path = os.path.join(out, f"{graph_filename(out_name)}.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.1)
    return x, y

def is_valid_harness_dir(harness_path:Path):
    if not harness_path.is_dir():
        log.warning("Harness is not a dir: %s", harness_path)
        return False
    if (harness_path/"IGNOREME").exists() or (harness_path/"IGNORE").exists():
        log.warning("Harness is ignored: %s", harness_path)
        return False
    return True


CALCULATE_TRIAGE = False
CALCULATE_COVERAGE = True
CALCULATE_GRAPHS = True

READ_CHUNKED = True

out = {}
for tee in TEES:
    out[tee] = {
        "fuzz_bbs": 0,
        "ta_max_bbs": {},
    }
    if CALCULATE_TRIAGE:
        out[tee].update({
            "crashes": 0,
            "bugs": 0,
            "notimpl": 0,
        })

    tas_harness = [] 
    tas = []
    for harness in os.listdir(os.path.join(BASE, tee, "harness")):
        ta = None
        harness_path = os.path.join(BASE, tee, "harness", harness)
        if not is_valid_harness_dir(Path(harness_path)):
            continue
        log.info("handling %s", harness_path)
        for f in Path(harness_path).iterdir():
            if not f.is_file():
                continue
            if f.suffix not in [".ta", ".elf"]:
                continue
            ta = f
            break
        
        if ta is None:
            log.error("missing TA in %s", harness_path)
            continue
        tas.append(ta.resolve().as_posix())
        tas_harness.append((harness, ta.as_posix()))
    
    tas = list(set(tas))
    log.info("TEE: %s, TAS: %s", tee, [Path(x).name for x in tas])
    out[tee]["nr_tas"] = len(tas)

    if CALCULATE_GRAPHS:
        if not CALCULATE_COVERAGE:
            raise ValueError("CALCULATE_GRAPHS requires CALCULATE_COVERAGE")
        tee_cfg = build_tee_cfg(os.path.join(BASE, tee), only_tee=True, specific_tas=tas)
        out[tee]["max_bbs"] = len(nx.descendants(tee_cfg, ROOT_NODE))
    else:
        tee_cfg = None

    ta2bbs = {}
    ta2bbs_merged = {}
    for harness, ta in tas_harness:
        harness_path = os.path.join(BASE, tee, "harness", harness)
        campaign_out = Path(harness_path) / CAMPAIGN_DIR

        if CALCULATE_COVERAGE:
            ta2bbs[ta] = {}
            campaign_repetitions = [p for p in campaign_out.iterdir() if p.is_dir()]
            campaign_repetitions.sort(key=lambda x: int(x.name))
            log.info("Located %d campaign repetitions in %s", len(campaign_repetitions), campaign_out)
            if len(campaign_repetitions) < FUZZ_ITERATIONS:
                log.warning("Missing repetitions in %s. got: %s, need: %s", campaign_out, [p.name for p in sorted(campaign_repetitions)], FUZZ_ITERATIONS)
            assert len(campaign_repetitions) > 0, f"No repetitions in {campaign_out}"


            for campaign_out_iter in campaign_repetitions:
                iter_name = campaign_out_iter.name
                log.info("processing repetition %s", campaign_out_iter.relative_to(THIS_PATH))
                if READ_CHUNKED:
                    ta2bbs[ta][iter_name] = parse_cov_seeds(
                        tee, ta, os.path.join(campaign_out_iter, FUZZ_CHUNKS)
                    )
                else:
                    out_cov_dir = Path(harness_path) / "out" / "cov"
                    log.info("Reading cov files from %s", out_cov_dir)
                    ta2bbs[ta][iter_name] = parse_cov(tee, ta, out_cov_dir.as_posix())
            
            unique_bbs = set()
            for campaign_out_iter in campaign_repetitions:
                for timestamp, bbss in ta2bbs[ta][campaign_out_iter.name].items():
                    for bb in bbss:
                        unique_bbs.add(bb)
            ta2bbs_merged[ta] = list(unique_bbs)
        
            write_json(Path(tee) / "ta2bbs" / Path(ta).stem, ta2bbs[ta])

        if CALCULATE_TRIAGE: # Per harness
        
            triage_path = Path(harness_path) / "triage"
            if triage_path.exists():
                num_triage = len([x for x in triage_path.iterdir() if (x.is_dir() and x.name != "stamp")])
                out[tee]["bugs"] += num_triage
                out[tee]["crashes"] += num_triage
        
            notimpl_path = Path(harness_path) / "notimpl"
            if notimpl_path.exists():
                num_notimpl = len([x for x in notimpl_path.iterdir() if (x.is_dir() and x.name != "stamp")])
                out[tee]["notimpl"] += num_notimpl
                out[tee]["crashes"] += num_notimpl
    
        if CALCULATE_COVERAGE:
            max_ta_bbs = get_ta_max_bbs(tee_cfg, ta)
            if max_ta_bbs == 0:
                log.warning("no bbs in %s", ta)
                if CALCULATE_GRAPHS:
                    log.warning("Skipping graph generation.")
                continue
        
            out[tee]["ta_max_bbs"][ta] = max_ta_bbs
            if CALCULATE_GRAPHS:
                log.info("Generating graph for %s", Path(ta).name)
                gen_graph(
                    f"{tee}/{Path(ta).stem}",
                    {ta: ta2bbs[ta]},
                    max_ta_bbs,
                    out_name=f"{TS}_{tee}_{Path(ta).stem}",
                )

    if CALCULATE_COVERAGE:
        out[tee]["ta2bbs"] = ta2bbs
        out[tee]["fuzz_bbs"] = sum([len(bbs) for _, bbs in ta2bbs_merged.items()])
            

all_ta2bbs:dict = {}
all_bbs:int = 0
all_crashes = 0
all_bugs = 0
all_notimpl = 0
all_tas = 0
for tee in TEES:
    x, y = gen_graph(tee, out[tee]["ta2bbs"], out[tee]["max_bbs"])
    out[tee]["bbs"] = max(y)
    all_ta2bbs = all_ta2bbs | out[tee]["ta2bbs"]
    all_bbs += out[tee]["max_bbs"]
    all_crashes += out[tee]["crashes"]
    all_bugs += out[tee]["bugs"]
    all_notimpl += out[tee]["notimpl"]
    all_tas += out[tee]["nr_tas"]
    print(f'{tee} reached bbs: {max(y)}, max bbs: {out[tee]["max_bbs"]}')

write_json(Path("out.json"), {k:v for k, v in out.items() if k != "ta2bbs"})

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


if len(TEES) > 1:
    for tee in TEES:
        if tee == "t6":
            tee_name = "tsix"
        elif tee == "qsee_nongp":
            tee_name = "nongpqsee"
        else:
            tee_name = tee
        print_latex(f"numfuzztas{tee_name}", out[tee]["nr_tas"])
        print_latex(f"numfuzzcrashes{tee_name}", out[tee]["crashes"])
        print_latex(f"numfuzznotimpl{tee_name}", out[tee]["notimpl"])
        print_latex(f"numfuzzbug{tee_name}", out[tee]["bugs"])
        print_latex(f"numfuzzmaxbb{tee_name}", out[tee]["max_bbs"])
        print_latex(f"numfuzzbb{tee_name}", out[tee]["bbs"])

print_latex("numfuzztas", all_tas)
print_latex("numfuzzcrashes", all_crashes)
print_latex("numfuzznotimpl", all_notimpl)
print_latex("numfuzzbug", all_bugs)
print_latex("numfuzzmaxbb", all_bbs)
print_latex("numfuzzbb", all_fuzz_bbs)
