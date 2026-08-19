# Figures 4 and 5

Turns a finished campaign into the two coverage figures of the paper.
`ae/experiments/stage_figures.py` drives all of this — **a reviewer runs
`./ae.sh e1_automatic_df_detection` and never calls anything here directly.**
The notes below are for re-running or extending the figures by hand, inside the
controller container (`cd ae && ./ae.sh shell`).

| file | what it is |
|---|---|
| `main.py` | the entry point: collects coverage, builds both figures |
| `collect_cov.py` | replays queue seeds to produce `.cov` files, and links coverage to the harness and TA it came from |
| `bb.py` | reads `<tee>/tas/bbs/bb_*.ta.json` (from `ghidra/`), builds the TA's CFG and computes the blocks reachable from `TA_InvokeCommandEntryPoint` — the denominator of Figure 4 |
| `graphing.py` | the matplotlib code, and the `rawinfo/` / `df_rawinfo/` caches of the aggregated data |
| `common.py` | drcov parsing, harness/TA discovery, the docker pool |
| `bk_suspicious_inputs_covs.sh` | collects `*/harness/*/out/cov/run:id:*.cov` into one directory, which `main.py` takes as `--ss_cov_rdir` |

## What the two figures are

* **Figure 4** accumulates the drcov coverage of the Exploration queue seeds
  over campaign time, normalised by the reachable basic blocks of each TA.
* **Figure 5** splits the basic blocks discovered per snapshot during
  Fetch-Anchored Fuzzing into the four categories of the paper. It is built on
  top of Figure 4's data, so `--fuzz_mode DF` is always run as `ALL`.

## Running it by hand

```sh
# 1. collect the coverage of the deduplicated Exploration inputs
./bk_suspicious_inputs_covs.sh /srv /tmp/ss_cov
#    -> /tmp/ss_cov/suspicious_inputs_covs

# 2. build the figures
python3 main.py --path /srv \
                --ss_cov_rdir /tmp/ss_cov/suspicious_inputs_covs \
                --out_dir /tmp/figures \
                --regen_coverage
```

`--regen_coverage` replays the queue seeds to produce the `.cov` files and is
needed on the first run; drop it afterwards. Other flags:

| flag | |
|---|---|
| `--fuzz_mode {ORG,DF,ALL}` | Figure 4 only, Figure 5 only, or both (default) |
| `--tees mitee qsee …` | restrict to some TEEs |
| `--tas ae_e1` | restrict to some harnesses — this is how the stage keeps the figure to the campaign just run |
| `--out_dir DIR` | where figures and the `rawinfo/` caches go (default: this directory) |
| `--max_timestamps N` | length of Figure 4's x-axis in seconds (paper: 86400) |
| `--show_rate` | plot coverage as a percentage instead of a basic-block count |
| `--org_group_field tee` | group Figure 4 by TEE instead of by TA |

The CFGs this needs (`<tee>/tas/bbs/`) ship with the artifact; `ghidra/` is
only needed to regenerate them.
