# Oversharing — Artifact Appendix (NDSS 2027)

*Oversharing: Exposing Double Fetch Vulnerabilities in Trusted Applications*

This directory contains the artifact evaluation harness for the paper. Every
experiment runs inside docker, sizes itself to the machine it runs on, and
writes the corresponding table or figure of the paper to `ae/results/`.

---

## 1. Artifact overview

The artifact consists of

| component | what it is |
|---|---|
| `emulator/` | **ScHMuzz**, built on TÄMU/Qiling/Unicorn + AFL++: emulates GlobalPlatform TAs, records shared-memory accesses (Exploration), fuzzes the value of a second fetch from a restored snapshot (Fetch-Anchored Fuzzing) and validates crashes (Distillation) |
| `swarm/` | the campaign orchestrator that runs one emulator container per fuzzing job |
| `eval/` | deduplication, annotation, statistics and plotting of a campaign |
| `<tee>/tas/` | the TA corpus per TEE (TEEGris, QSEE, Kinibi, MiTEE, Beanpod, plus OP-TEE Rust TAs and T6/TrustedCore) |
| `<tee>/harness/` | one fuzzing harness per TA that operates on shared memory, **plus the campaign data of the paper** (recorded fetches, snapshots, crashes) |
| `<tee>/pocs/` | on-device proof-of-concept apps for the vulnerabilities (Section V) |
| `optee_shm_patch/` | the opt-in shared-memory mitigation for OP-TEE and its benchmark (Section VII) |
| `ghidra/` | headless Ghidra scripts that produce the per-TA basic-block CFGs used for the coverage figures |
| `ae/` | **this artifact-evaluation harness** |

## 2. Claims and where they are checked

The first four experiments are the pipeline of Section III and have to run in
order: Exploration produces the snapshots that Fetch-Anchored Fuzzing needs,
which produces the crashes that Distillation filters, and Table I is the
summary of that campaign.

Runtimes are for the default budgets on a commodity desktop (8 cores, 16 GB
RAM, `AE_JOBS=6`); they shrink on a bigger machine, see §7.

| # | Paper claim | Experiment | Runtime |
|---|---|---|---|
| C1–C4, C8 | The pipeline of Section III: Exploration finds overlapped fetches in binary-only TAs (III-A), Fetch-Anchored Fuzzing turns them into crashes (III-B), Distillation keeps the ones that need the race (III-C) — summarised in **Table I** and **Figures 4 and 5** | `e1_automatic_df_detection` | ~8 h |
| C5 | **Table II: six 0-day TOCTTOU vulnerabilities in five TAs**, reproduced by racing the TA with the PoC of each vulnerability | `e2_vulns` | ~15 min |
| C6 | Table IV: TAs written in Rust are affected as well (Sec. VI) | `e3_rust` | ~40 min |
| C7 | Table V: only ~11 % of fuzzing iterations execute a double fetch (Sec. VIII-c) | `e4_reshaping` | ~1 min |
| C9 | Section VII: a 140-LoC opt-in mitigation for OP-TEE that closes the double fetch and is cheap when opted in | **not an experiment**, see §6 | — |
| — | Table III: zero-copy shared memory on COTS phones (Section V) | **not reproducible without the phones**, see §6 | — |

`./ae.sh all` runs all of it, in this order, in about 8 h. `AE_SCALE=quick`
cuts it to roughly an hour on five TAs when you only want to see the machinery
work.

## 3. Requirements

On the host, only docker and bash:

| requirement | why |
|---|---|
| Linux, x86-64 | the emulator images are amd64 |
| Docker Engine >= 23 with BuildKit | the Dockerfiles use `RUN --mount=type=cache` and `COPY --link` |
| `docker compose` v2 plugin | starts the redis container the recorder streams to |
| membership in the `docker` group | the controller is given `/var/run/docker.sock` to start emulator containers |
| bash, coreutils (`nproc`, `awk`, `/proc/meminfo`) | `ae.sh` and the pool sizing |
| network access during `./ae.sh setup` | pulls `ubuntu:jammy`, `aflplusplus/aflplusplus:v4.32c`, PyPI, rustup, `download.docker.com` |
| ~15 GB disk | 3.8 GB images, ~4 GB TA corpus and campaign data, ~300 MB produced |
| >= 8 cores, >= 16 GB RAM | one emulator per core, ~85 MB each (see 7.) |

No Python, matplotlib, Rust or Ghidra on the host - everything runs in the two
images that `./ae.sh setup` builds:

* `ta_emu_ae` (from `../Dockerfile`): Ubuntu 22.04, Python 3.10.12, Qiling
  pinned at `56dd77b` plus `emulator/qiling.diff`, Unicorn, AFL++ 4.32c with the
  unicornafl bindings, pwntools 4.15.0 and the rest of
  `emulator/requirements.txt`, Rust (for `swarm/`)
* `ta_emu_ae_ctl` (from `ae/Dockerfile`): the same plus the docker client and
  compose plugin, matplotlib 3.10.8, numpy, networkx, tqdm, aiofiles, cachetools,
  loguru, tenacity, pandas, jq, bc, pv
* `redis:7-alpine`, started by `docker-compose.redis.yml`

Optional, for parts that are not self-contained:

* a **built** OP-TEE QEMU-v8 tree (~31 GB, hours to build) plus `pexpect` -
  only to rebuild or re-measure the Section VII mitigation, outside this
  harness; see `optee_shm_patch/benchmark/README.md`. No experiment needs it.
* Android NDK and a rooted phone from Table III - to run the PoCs on a device
  (Section V); the artifact runs them against the emulator instead
* Ghidra (`ghidra/`) - only needed to regenerate the per-TA CFGs used by
  Figure 4; they ship in `<tee>/tas/bbs/`

## 4. Getting started (~20 min)

```sh
cd ae
./ae.sh setup          # builds both images, starts redis, runs the self-test
```

The self-test (`e0_selftest`) emulates the MiTEE SoterApp TA, replays an
Exploration seed, restores the snapshot of the double fetch of Listing 3,
injects the crashing value and lets Distillation confirm that the crash needs
the race. It must end with `all checks passed`.

```sh
./ae.sh list                 # all experiments, and the budgets picked for this machine
./ae.sh e2_vulns             # the central "reproduced" experiment (Table II), ~15 min
./ae.sh all                  # everything, in order, all 30 TAs, ~8 h
AE_SCALE=quick ./ae.sh all   # the same on five TAs with short budgets, ~1 h
./ae.sh report               # summary of everything that was run
```

The defaults in `ae/config.env` need no tuning: `AE_JOBS` is derived from the
machine's cores and free memory at every invocation, and the time budgets are
sized so that the full run covers all 30 TAs of Table I within a day on a
commodity desktop (§7).

`e1_automatic_df_detection` is one campaign in five stages; individual stages
can be re-run without repeating the ones before them:

```sh
./ae.sh e1_automatic_df_detection                        # the whole pipeline
./ae.sh e1_automatic_df_detection --from faf             # continue an existing campaign
./ae.sh e1_automatic_df_detection --only table1 figures  # only re-render the output
./ae.sh e1_automatic_df_detection --time 3600 --harnesses mitee/harness/88ce_fuzz
```

Results, tables (`.txt`, `.csv`, `.tex`) and figures (`.pdf`, `.png`) are
written to `ae/results/<experiment>/`; the pipeline's stages write to
`ae/results/e1_automatic_df_detection/<n>_<stage>/`, with Table I and the two
figures copied up into the experiment's own directory.

## 5. Experiments

Each experiment prints its table and ends with an explicit list of checks —
`[ok]` or `[--]` per check, nothing else. Anything advisory (a TA whose data is
pruned, harnesses excluded from a count, a TA whose data is missing) is not printed
but recorded in `ae/results/<experiment>/notes.log` and in the `notes` field of
`result.json`, next to the numbers it qualifies.

### `e1_automatic_df_detection` — Section III, Table I, Figures 4 and 5

The pipeline of the paper, as one experiment, because each stage consumes what
the previous one produced. `--only <stage>...` runs a subset and `--from
<stage>` continues from one; the stage scripts are `ae/experiments/stage_*.py`
and each writes its own tables, logs and `result.json` to
`ae/results/e1_automatic_df_detection/<n>_<stage>/`.

#### Stage 1 — Exploration

Fuzzes each TA of `$AE_SUBSET` with `emulator/fuzz.sh` while tracing accesses to
the memref buffers, deduplicates the recordings (`eval/deduplicate.py`,
coverage mode), annotates the overlapped fetches (`eval/annotate_fetches.py`)
and reports how many snapshots each TA yields.

Working copies are created as `<tee>/harness/ae_e2_<name>` — the campaign data
shipped with the artifact is never modified.

```sh
./ae.sh e1_automatic_df_detection                       # all 30 TAs, 30 min each
./ae.sh e1_automatic_df_detection --time 3600           # longer budget
AE_SCALE=quick ./ae.sh e1_automatic_df_detection        # five TAs, 5 min each
./ae.sh e1_automatic_df_detection --harnesses mitee/harness/88ce_fuzz qsee/harness/3d08_fuzz
```

`all` — the default `AE_SUBSET` — selects **27 harnesses covering the 30 TAs of
Table I**; the three Kinibi TAs are fuzzed through their Beanpod harnesses and
count for both TEEs. The stage prints the resulting TA count and an estimate of
the wall clock before it starts, e.g. 27 harnesses at 30 min each with
`AE_JOBS=6` is ~3 h of fuzzing plus deduplication.

#### Stage 2 — Fetch-Anchored Fuzzing

Restores each snapshot and fuzzes the value read at the second fetch
(`emulator/df_fuzz.sh`), for up to `AE_FAF_MAX_SNAPSHOTS` snapshots per TA.

The budget matters: with the paper's 900 s per snapshot, Fetch-Anchored Fuzzing
rediscovers the crashes of the SoterApp and Mlipay vulnerabilities from scratch;
with a much shorter budget a snapshot is restored and fuzzed but usually stays
crash-free (the paper found crashes in 330 of 17,232 snapshots). The stage
therefore asserts only that snapshots are restored and fuzzed, and reports the
crashes it finds.

#### Stage 3 — Distillation

Replays every crash with the crashing value already in place
(`emulator/df_validate.sh` via `eval/df_validate.py`) and reports which crashes
survive only *with* the race, i.e. which are real double-fetch vulnerabilities.

#### Stage 4 — Table I

Summarises the campaign the three stages just produced with the artifact's own
`statistics.sh` and prints it next to the paper's Table I. Run standalone,
`ae/experiments/stage_table1.py --source campaign` does the same for the
campaign data shipped with the artifact — an inventory of files on disk, not a
re-run, so the AE budget does not influence it; §9 explains why some of its
columns deviate from the paper.

Only one column of Table I cannot be derived from the repository: `# TAs`, the
number of GlobalPlatform-compliant TAs. The corpus in `<tee>/tas` is a superset
(113 TA files, 73 of them with emulator metadata, versus 66 in the paper) and no
property of the binaries separates them — Kinibi TAs have no metadata at all
because they run on the Beanpod runtime. List them once in
`ae/data/dataset.json`:

```sh
python3 ae/tools/make_dataset_skeleton.py > ae/data/dataset.json   # candidates
$EDITOR ae/data/dataset.json                                       # prune
```

The stage then uses that list for `# TAs` and checks every entry is present; until then
it counts the corpus and says so. `# TAs w/o Local Copy` needs no such list: it
is the set of TAs that have a harness, which already matches the paper (9/3/3/10/5).

#### Stage 5 — Figures 4 and 5

Figure 4 accumulates the drcov coverage of the Exploration queue seeds
(`<harness>/out/cov`) over campaign time and normalises it by the basic blocks
reachable from `TA_InvokeCommandEntryPoint` in the TA's CFG
(`<tee>/tas/bbs/bb_*.json`, produced by `ghidra/analyze-bbs.sh`).
Figure 5 splits the basic blocks discovered per snapshot during Fetch-Anchored
Fuzzing into the four categories of the paper; it needs coverage for the FAF
queue, which the stage produces by replaying the queue entries.

### `e2_vulns` — Table II *(main experiment)*

Runs the **proof-of-concept client of each vulnerability against the emulator**.
Built with `-DEMULATE` the PoC does not talk to a TEE driver but to the
emulator, which serves the GlobalPlatform client protocol on TCP port 1337 and
backs every `memref` with real System V shared memory
(`emulator/emulate/ta_mgr.py:start_interactive`, started by `emulator/run.sh`).
The PoC opens a session, spawns the thread that keeps modifying the shared
buffer and invokes the vulnerable command — it races the TA exactly as it does
on a phone (Listing 2). When it wins the race the TA corrupts memory and the
emulator reports the violation; that is what the experiment checks.

Winning the race is probabilistic, so each PoC is run over and over until the TA
crashes, with a fresh emulator per run so that no state from a previous one can
be mistaken for a crash. `--attempts N` caps that if you want the experiment to
end even when a PoC never hits.

```sh
./ae.sh e2_vulns                        # PoCs against the emulator, until they crash
./ae.sh e2_vulns --attempts 20          # give up after 20 runs of a PoC
./ae.sh e2_vulns --replay               # instead replay the crashing input that
                                        # Fetch-Anchored Fuzzing found (needs the
                                        # campaign data, see §9)
```

The "reproduced on device" column is quoted from the paper (Section V) because
it needs the rooted phones of Table III.

All six reproduce this way, in each case by racing the very field that
Exploration recorded as double-fetched — for FbSkmR and ifaa-key, for instance,
the offset the PoC writes is exactly the offset of the recorded second fetch.
How many runs a PoC needs varies from one execution of the experiment to the
next (1-13 in ours); the table reports the number it took this time.

### `e3_rust` — Table IV

Runs Exploration on the OP-TEE Rust TAs in `optee/harness/` and counts the
detected double fetches per TA.

### `e4_reshaping` — Table V

Compares the total number of Exploration executions with the number of
executions that actually reach a double fetch (`eval/reshaping_cmp.py
--print-numbers`), i.e. the share of the budget a reshaping-based fuzzer would
waste.

### Helper

`ae/experiments/_probe_vulns.py` replays *every* replayable crash of a set of
harnesses and prints the observed crash type and the Distillation verdict. It is
how `ae/data/vulns.json` (the crash pinned to each Table II vulnerability) was
put together, and it is the tool to use after a fresh campaign.

## 6. What cannot be reproduced by a reviewer

* **Table III / Section V (on-device)** — reproducing the TOCTTOU
  vulnerabilities on real phones needs the twelve rooted devices of Table III
  and vendor firmware. The proof-of-concept apps are shipped in
  `<tee>/pocs/<vuln>/` (build with `ANDROID_NDK=… make phone`, deploy with
  `adb push`), and Listing 2 of the paper shows the racing app.
* **The full campaign** — the paper's numbers come from 5 × 24 h of Exploration
  per TA and 15 min of Fetch-Anchored Fuzzing for each of 17,232 snapshots
  (4,330 CPU-hours). `AE_SCALE=paper` runs those budgets.
* **Section VII (the mitigation)** — not an experiment of this evaluation. The
  patch is `optee_shm_patch/optee_os.patch` (140 lines) and everything that
  substantiates the section lives beside it in `optee_shm_patch/benchmark/`:
  the two probe commands that show the mitigation stops double fetches
  (0 of 100,000 raced double fetches without the opt-in, ~40 % with it), the
  latency sweeps, the measured results and the plot, and a `build.sh` +
  `harness/driver.py` that rebuild and re-measure all of it from a built OP-TEE
  QEMU-v8 tree in about 30 s. That tree is ~31 GB and hours of compiling, which
  is why this is documented rather than run. See
  `optee_shm_patch/benchmark/README.md`.

## 7. Scaling

Nothing here has to be set: the defaults size themselves to the machine at
every invocation and already cover all 30 TAs of Table I within a day on a
commodity desktop. `./ae.sh list` prints what they resolved to.

| variable | default | `AE_SCALE=quick` | paper |
|---|---|---|---|
| `AE_JOBS` | auto: min(cores − 2, free RAM ÷ 512 MB) | auto | 56 |
| `AE_MEM_PER_JOB_MB` | 512 (an emulator measures ~85 MB) | — | — |
| `AE_RESERVE_MB` | 2048 left for host, docker, controller | — | — |
| `AE_SUBSET` | `all` — 27 harnesses, the 30 TAs of Table I | the 5 TAs behind Table II | `all` |
| `AE_EXPLORE_TIME` | 1800 s per TA | 300 s | 86,400 s |
| `AE_EXPLORE_REPS` | 1 | 1 | 5 |
| `AE_FAF_TIME` | 900 s per snapshot | 900 s | 900 s |
| `AE_FAF_MAX_SNAPSHOTS` | 4 per TA | 6 | all |
| `AE_DEDUP_LIMIT` | 0 = every recording | 150 per TA | 0 |

Anything set in the environment wins over the `AE_SCALE` preset, so
`AE_SCALE=quick AE_SUBSET=all ./ae.sh e1_automatic_df_detection` does what it says.

### What `./ae.sh all` costs

`AE_JOBS` is the only thing that decides wall clock: the pipeline runs the
harnesses in waves of `AE_JOBS` emulator containers, one core each. A commodity
desktop (8 cores, 16 GB RAM) gets `AE_JOBS=6` — `min(8-2, (16 GB - 2 GB)/512
MB)` — which is what the estimates below assume. Twelve cores get 10, and E1/E2
finish in roughly half the time.

```sh
cd ae && ./ae.sh setup
nohup ./ae.sh all > ae_full_run.log 2>&1 &
```

| experiment | work | ~wall clock at `AE_JOBS=6` |
|---|---|---|
| `e1_automatic_df_detection` | | **~8 h** |
| &nbsp;&nbsp;stage 1, exploration | 27 harnesses x 30 min, 5 waves + dedup | ~3 h |
| &nbsp;&nbsp;stage 2, FAF | 27 x 4 snapshots x 15 min, 18 waves | ~4.5 h |
| &nbsp;&nbsp;stage 3, distillation | every crash found above | minutes |
| &nbsp;&nbsp;stage 4, Table I | Table I of that campaign | seconds |
| &nbsp;&nbsp;stage 5, figures | CFGs + coverage replays (~1 s each) | ~30 min |
| `e2_vulns` | six PoCs raced against the emulator | ~15 min |
| `e3_rust` | 5 Rust TAs x 30 min | ~40 min |
| `e4_reshaping` | Table V from the campaign state | seconds |
| **total** | | **~9 h** |

Needs ~15 GB of disk: 3.8 GB of docker images, ~4 GB of TA corpus and campaign
data, and ~300 MB produced by the run itself.

Two smaller options:

```sh
./ae.sh setup && ./ae.sh e2_vulns      # kick the tires, ~25 min, Table II
AE_SCALE=quick ./ae.sh all             # five TAs, short budgets, ~1 h
```

### What the scaled-down run does and does not show

Preserved in full:

* the **dataset** of Table I (all 66 GlobalPlatform TAs, all 30 that operate on
  shared memory, verified against `ae/data/dataset.json`),
* all **five TEEs**, each fuzzed with the same emulator and harnesses as the paper,
* the **three stages** end to end on every one of those 30 TAs, producing Table I
  of the run, Figures 4 and 5,
* **Table II**: all six vulnerabilities, reproduced by racing each TA with its
  proof-of-concept client - this is independent of the fuzzing budget,
* **Table IV**: which Rust TAs contain double fetches,
* **Section VII**: the size of the mitigation and its measured overhead.

Reduced: the paper explores each TA for 5 x 24 h and fuzzes each of its 17,232
snapshots for 15 min (4,330 CPU-hours). The default run spends 30 min per TA and
fuzzes 4 snapshots per TA, so the absolute counts in Table I (overlapped
fetches, snapshots, crashes) are correspondingly smaller; the columns are
reported next to the paper's numbers. Raising `AE_EXPLORE_TIME`,
`AE_EXPLORE_REPS` and `AE_FAF_MAX_SNAPSHOTS` scales the run continuously up to
`AE_SCALE=paper`.

## 8. Cleaning up

```sh
./ae.sh clean                                    # results + working harnesses + emu_* containers
docker compose -f ../docker-compose.redis.yml down
docker rmi ta_emu_ae ta_emu_ae_ctl
```

`./ae.sh clean` removes `ae/results/` and the `*/harness/ae_e*_*` working
copies. The campaign data of the paper (`*/harness/<name>/`) is never touched by
any experiment.

## 9. Notes on the campaign data shipped with the artifact

`ae/experiments/stage_table1.py --source campaign` compares the campaign state
in this repository against Table I and
prints every deviation. The tree that is shipped is a **pruned** state of the
campaign: `eval/deduplicate.py --enable-del` removes redundant Exploration seeds
(and their `.meta` records) once a campaign is finished, and the recordings of
some TAs were not kept. As a consequence the raw `# Overl. Fetches` column and
the number of TAs with overlapped fetches are lower than in the paper. Re-running
`e1_automatic_df_detection` produces fresh, self-consistent numbers for the TAs
it covers.

A concrete symptom: `# Overl. Fetches merged` can exceed `# Overl. Fetches` on
the shipped tree, because `df_fuzz/<seed>_<reghash>/` directories survive while
the recordings they were derived from were deleted (`mitee/harness/86f6_fuzz`
alone has 13,149 snapshot directories and no `.meta` files left). Stage 4 lists
every harness in that state instead of silently printing the impossible ratio.
