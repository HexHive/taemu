# Purpose: Parse fuzzing campaign drcov outputs and produce coverage-over-time
# graphs for each TEE and merged datasets.
# Depends on: campaign_out directories from eval/fuzz.py, drcov logs in harness
# coverage directories, eval/graphs CFG helpers, matplotlib, and numpy.
# Input: No CLI arguments; optional TAEMU_FUZZ_TEE restricts discovered TEEs.

import argparse
import datetime
import json
import logging
from pathlib import Path
import sys
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import os

from bb import build_tee_cfg
from fuzz import FUZZ_TIME, TEES, FUZZ_CHUNKS, FUZZ_ITERATIONS, COV_DIR, CAMPAIGN_DIR

FUZZ_ITERATIONS = 4
PARSE_CHUNKED = True
FUZZ_TIME = 86400





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


def bb_to_json(bb):
    return {
        "ta": bb.ta,
        "start": hex(bb.start),
        "end": hex(bb.start + bb.size),
        "size": bb.size,
    }


def bb_from_json(data):
    start = data["start"]
    if isinstance(start, str):
        start = int(start, 16)
    return BB(data["ta"], start, int(data["size"]))


def get_root_ta_node(cfg, ta):
    for n in cfg.nodes:
        if f"{Path(ta).stem}_{8 * '0'}" in n:
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
    bbs_out = []
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
            bbs_out.append(BB(ta, start, size))
        bbs = bbs[8:]
    return bbs_out


def parse_drcov(tee, ta, path):
    return parse_drcov_uncached(tee, ta, path)


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


def graph_filename(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


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
    out_path = os.path.join(out, f"{TIMESTAMP}_{graph_filename(out_name)}.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.1)
    return x, y


def print_latex(name, num):
    print(f"\\newcommand{{\\{name}}}{{{num}\\xspace}}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Postprocess fuzzing drcov outputs into coverage reports and graphs."
    )
    parser.add_argument(
        "--no-graphs",
        action="store_true",
        help="skip per-TA, per-TEE, and combined graph generation",
    )
    parser.add_argument(
        "--reuse-json-dir",
        type=Path,
        help="reuse compatible per-TA JSON files from a previous fuzz_postprocess run",
    )
    return parser.parse_args(argv)


TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def make_run_dir(base=BASE):
    out_dir = Path(base) / "eval" / "fuzz_postprocess" / TIMESTAMP
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def iter_harnesses(tee):
    harness_root = Path(BASE) / tee / "harness"
    for harness_path in sorted(harness_root.iterdir()):
        if not harness_path.is_dir():
            print("Harness is not a dir")
            continue
        if (harness_path / "IGNOREME").exists() or (harness_path / "IGNORE").exists():
            print("Harness is ignored")
            continue
        yield harness_path


def find_harness_ta(harness_path):
    for child in sorted(harness_path.iterdir()):
        if child.name.endswith(".ta") or child.name.endswith(".elf"):
            return child.name, child.resolve().as_posix()
    return None


def parse_harness_coverage(tee, ta, harness_path):
    harness_path = Path(harness_path)
    campaign_out = harness_path / CAMPAIGN_DIR
    out = {}
    for campaign_iteration in range(0, FUZZ_ITERATIONS):
        print(f"processing {campaign_out} {campaign_iteration}")
        iteration_dir = campaign_out / f"{campaign_iteration}"
        if PARSE_CHUNKED:
            out[campaign_iteration] = parse_cov_seeds(
                tee, ta, (iteration_dir / FUZZ_CHUNKS).as_posix()
            )
        else:
            out[campaign_iteration] = parse_cov(
                tee, ta, (harness_path / "out" / "cov").as_posix()
            )
    return out


def parse_harness_crash_counts(harness_path):
    harness_path = Path(harness_path)
    counts = {"crashes": 0, "bugs": 0, "notimpl": 0}

    triage_path = harness_path / "triage"
    if triage_path.exists():
        bugs = len(
            [x for x in triage_path.iterdir() if x.is_dir() and x.name != "stamp"]
        )
        counts["bugs"] += bugs
        counts["crashes"] += bugs

    notimpl_path = harness_path / "notimpl"
    if notimpl_path.exists():
        notimpl = len(
            [x for x in notimpl_path.iterdir() if x.is_dir() and x.name != "stamp"]
        )
        counts["notimpl"] += notimpl
        counts["crashes"] += notimpl

    return counts


def add_counts(target, counts):
    for key in ("crashes", "bugs", "notimpl"):
        target[key] += counts[key]


def covered_bbs(iterations):
    unique_bbs = set()
    for data in iterations.values():
        for timestamp, bbss in data.items():
            if timestamp > FUZZ_TIME:
                log.warning(f"skipping timestamp {timestamp} > {FUZZ_TIME}")
                continue
            unique_bbs.update(bbss)
    return unique_bbs


def coverage_summary(reached_bbs, max_bbs):
    reached = reached_bbs if isinstance(reached_bbs, int) else len(reached_bbs)
    return {
        "reached_bbs": reached,
        "max_bbs": max_bbs,
        "coverage_pct": (100.0 * reached / max_bbs) if max_bbs else 0.0,
    }


def ta_report_filename(tee, ta):
    return f"{graph_filename(f'{tee}_{Path(ta).stem}')}.json"


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def load_ta_report(path, tee=None, ta=None):
    path = Path(path)
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ignoring invalid reuse report {path}: {exc}")
        return None
    required = {"tee", "ta", "fuzz_time", "fuzz_iterations", "basic_blocks"}
    if not required <= set(report):
        print(f"ignoring incompatible reuse report {path}: missing keys")
        return None
    if tee is not None and report["tee"] != tee:
        print(f"ignoring incompatible reuse report {path}: tee mismatch")
        return None
    if ta is not None and report["ta"] != ta:
        print(f"ignoring incompatible reuse report {path}: ta mismatch")
        return None
    if report["fuzz_time"] != FUZZ_TIME or report["fuzz_iterations"] != FUZZ_ITERATIONS:
        print(f"ignoring incompatible reuse report {path}: fuzz config mismatch")
        return None
    return report


def report_to_bbs(report):
    return {bb_from_json(bb) for bb in report["basic_blocks"]}


def bbs_to_synthetic_iterations(bbs):
    return {
        campaign_iteration: {0: list(bbs)}
        for campaign_iteration in range(0, FUZZ_ITERATIONS)
    }


def build_ta_report(tee, ta, reached_bbs, max_bbs, reused_from=None):
    report = {
        "tee": tee,
        "ta": ta,
        "fuzz_time": FUZZ_TIME,
        "fuzz_iterations": FUZZ_ITERATIONS,
        "basic_blocks": [
            bb_to_json(bb)
            for bb in sorted(reached_bbs, key=lambda bb: (bb.ta, bb.start, bb.size))
        ],
    }
    report.update(coverage_summary(reached_bbs, max_bbs))
    if reused_from is not None:
        report["reused_from"] = str(reused_from)
    return report


def build_aggregate_report(name, nr_tas, reached_bbs, max_bbs, counts=None, tas=None):
    report = {
        "tee": name,
        "nr_tas": nr_tas,
    }
    report.update(coverage_summary(reached_bbs, max_bbs))
    if counts is not None:
        report.update(counts)
    if tas is not None:
        report["tas"] = tas
    return report


def tee_latex_name(tee):
    if tee == "t6":
        return "tsix"
    return tee


def postprocess_tee(tee, args, run_dir):
    out = {
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
    ta_report_paths = {}

    for harness_path in iter_harnesses(tee):
        print(f"handling {harness_path}")
        ta_info = find_harness_ta(harness_path)
        if ta_info is None:
            print("????? None")
            continue
        ta, real_ta_path = ta_info
        tas.append(real_ta_path)
        add_counts(out, parse_harness_crash_counts(harness_path))

        reuse_path = None
        reuse_report = None
        if args.reuse_json_dir is not None:
            reuse_path = args.reuse_json_dir / ta_report_filename(tee, ta)
            reuse_report = load_ta_report(reuse_path, tee=tee, ta=ta)

        if reuse_report is not None:
            reached = report_to_bbs(reuse_report)
            ta2bbs[ta] = bbs_to_synthetic_iterations(reached)
            print(f"reusing coverage {reuse_path}")
            if not args.no_graphs:
                print(
                    "warning: reused coverage has no timestamp data; "
                    f"graph for {tee}/{Path(ta).stem} will use the final BB set"
                )
        else:
            ta2bbs[ta] = parse_harness_coverage(tee, ta, harness_path)
            reached = covered_bbs(ta2bbs[ta])
        ta2bbs_merged[ta] = reached

    tas = list(set(tas))
    print(f"{tee}, {tas}")
    out["nr_tas"] = len(tas)
    tee_cfg = build_tee_cfg(os.path.join(BASE, tee), only_tee=True, specific_tas=tas)
    out["max_bbs"] = len(nx.descendants(tee_cfg, root))
    out["fuzz_bbs"] = sum(len(bbs) for bbs in ta2bbs_merged.values())
    out["ta2bbs"] = ta2bbs
    out["ta_max_bbs"] = {}

    tee_reached_bbs = set()
    for ta in sorted(ta2bbs):
        max_ta_bbs = get_ta_max_bbs(tee_cfg, ta)
        out["ta_max_bbs"][ta] = max_ta_bbs
        reached = ta2bbs_merged[ta]
        tee_reached_bbs.update(reached)
        report_path = run_dir / ta_report_filename(tee, ta)
        reuse_path = None
        if args.reuse_json_dir is not None:
            candidate = args.reuse_json_dir / ta_report_filename(tee, ta)
            if load_ta_report(candidate, tee=tee, ta=ta) is not None:
                reuse_path = candidate
        report = build_ta_report(tee, ta, reached, max_ta_bbs, reused_from=reuse_path)
        write_json(report_path, report)
        ta_report_paths[ta] = report_path.name
        print(
            f"coverage ta {tee}/{Path(ta).stem}: "
            f"{report['reached_bbs']}/{report['max_bbs']} bbs "
            f"({report['coverage_pct']:.2f}%)"
        )
        if max_ta_bbs == 0:
            log.warning(f"max_ta_bbs is 0 for {tee}/{Path(ta).stem}")
        if max_ta_bbs != 0 and not args.no_graphs:
            gen_graph(
                f"{tee}/{Path(ta).stem}",
                {ta: ta2bbs[ta]},
                max_ta_bbs,
                out_name=f"{TIMESTAMP}_{tee}_{Path(ta).stem}",
            )

    out["bbs"] = len(tee_reached_bbs)
    tee_report = build_aggregate_report(
        tee,
        out["nr_tas"],
        tee_reached_bbs,
        out["max_bbs"],
        counts={key: out[key] for key in ("crashes", "bugs", "notimpl")},
        tas=ta_report_paths,
    )
    write_json(run_dir / f"{graph_filename(tee)}.json", tee_report)
    if not args.no_graphs:
        gen_graph(tee, ta2bbs, out["max_bbs"])
    print(f"{tee} reached bbs: {out['bbs']}, max bbs: {out['max_bbs']}")
    return out, tee_reached_bbs


def main(argv=None):
    args = parse_args(argv)
    run_dir = make_run_dir()
    print(f"writing fuzz postprocess JSON to {run_dir}")

    out = {}
    all_ta2bbs = {}
    all_fuzz_bbs = 0
    all_bbs = 0
    all_crashes = 0
    all_bugs = 0
    all_notimpl = 0
    all_tas = 0

    for tee in TEES:
        tee_out, tee_reached_bbs = postprocess_tee(tee, args, run_dir)
        out[tee] = tee_out
        all_ta2bbs = all_ta2bbs | tee_out["ta2bbs"]
        all_fuzz_bbs += len(tee_reached_bbs)
        all_bbs += tee_out["max_bbs"]
        all_crashes += tee_out["crashes"]
        all_bugs += tee_out["bugs"]
        all_notimpl += tee_out["notimpl"]
        all_tas += tee_out["nr_tas"]

    if not args.no_graphs:
        gen_graph("all", all_ta2bbs, all_bbs)
    write_json(
        run_dir / "all.json",
        build_aggregate_report(
            "all",
            all_tas,
            all_fuzz_bbs,
            all_bbs,
            counts={
                "crashes": all_crashes,
                "bugs": all_bugs,
                "notimpl": all_notimpl,
            },
        ),
    )
    print(f"all reached bbs: {all_fuzz_bbs}, max bbs: {all_bbs}")

    print("crashes")
    for tee in TEES:
        print(
            f"{tee} nr tas: {out[tee]['nr_tas']} crashes: {out[tee]['crashes']}, bugs: {out[tee]['bugs']}, notimpl: {out[tee]['notimpl']}"
        )
    print(
        f"all nr tas: {all_tas} crashes: {all_crashes}, bugs: {all_bugs}, notimpl: {all_notimpl}"
    )

    for tee in TEES:
        tee_name = tee_latex_name(tee)
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


if __name__ == "__main__":
    main()
