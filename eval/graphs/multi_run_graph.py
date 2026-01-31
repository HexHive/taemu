import argparse
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import os
import json
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode, parse_drcov

def get_org_data(tee, path):
    for f in os.listdir(path):
        print(f)
        if f.lower() == f'org_{tee}.json':
            return json.load(open(os.path.join(path, f)))
    print(f'not found {tee}, {path}')
    raise Exception

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

def plot_org(data, tee):
    coords = []
    for d in data:
        coords.append((d['x'], d['y']))

    y_max, y_min, y_median, x = aggregate(coords) 
    print(y_max)
    print(y_min)
    print(y_median)
    print(x)
    matplotlib.rcParams['mathtext.fontset'] = 'custom'
    matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
    matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
    matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
    matplotlib.rcParams['mathtext.fontset'] = 'stix'
    matplotlib.rcParams['font.family'] = 'STIXGeneral'
    plt.clf()
    plt.fill_between(x, y_min, y_max, color='orange', alpha=0.2)
    plt.plot(x, y_median, color='orange')
    plt.plot(x, y_min, linestyle='none')
    plt.plot(x, y_max, linestyle='none')
    plt.gca().set_xticklabels([])
    plt.gca().tick_params(axis='x', which='both', length=8)
    plt.gca().tick_params(axis='y', which='both', length=8)
    plt.gca().margins(y=0, x=0.005)
    yticks = [0, 50, 100]
    ylabels = ['','','']
    ax = plt.gca()
    ax.set_yticks(yticks)
    ax.set_yticklabels([])
    plt.tight_layout()
    xticks = [0, 12, 24]
    ax.set_xticks(xticks)
    if not os.path.exists(os.path.join(os.path.dirname(__file__), "multi_graph_out")):
        os.makedirs(os.path.join(os.path.dirname(__file__), "multi_graph_out"))
    plt.savefig(os.path.join(os.path.dirname(__file__), "multi_graph_out", f'org_{tee}.pdf'), format="pdf",bbox_inches='tight', pad_inches=0.1)

def main(fuzz_mode, path, teess):
    tees = ['mitee', 'teegris', 'qsee', 'beanpod', 'kinibi']
    if teess is not None:
        tees = teess
    if fuzz_mode == FuzzMode.ALL or fuzz_mode == FuzzMode.ORG:
        for tee in tees:
            data = []
            for out_dir in os.listdir(path):
                data.append(get_org_data(tee, os.path.join(path, out_dir, 'rawinfo')))
            plot_org(data, tee)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fuzz_mode",
        choices=[mode.value for mode in FuzzMode],
        default=FuzzMode.ALL.value,
    )
    parser.add_argument("--tees", nargs="+", default=None, help="Filter by TEEs")
    parser.add_argument("--path", type=str)
    
    args = parser.parse_args()

    main(
        fuzz_mode=FuzzMode(args.fuzz_mode),
        path=args.path,
        teess=args.tees
    )