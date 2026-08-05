# Oversharing — Artifact Appendix (NDSS 2027)

*Oversharing: Exposing Double Fetch Vulnerabilities in Trusted Applications*

This directory contains the artifact evaluation harness for the paper. Every
experiment runs inside docker, is scaled down to fit an evaluation session, and
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

| # | Paper claim | Experiment | Runtime (default) |
|---|---|---|---|
| C2 | Exploration finds overlapped fetches from shared memory in binary-only TAs (Sec. III-A) | `e1_exploration` | ~10 min |
| C3 | Fetch-Anchored Fuzzing turns overlapped fetches into crashes (Sec. III-B) | `e2_faf` | ~45 min |
| C4 | Distillation keeps only crashes that require the shared-memory race (Sec. III-C) | `e3_distillation` | ~10 min |
| C1 | Table I: TAs, overlapped fetches, snapshots, crashes, distilled crashes | `e4_table1` | ~1 min |
| C5 | **Table II: six 0-day TOCTTOU vulnerabilities in five TAs**, reproduced by racing the TA with the PoC of each vulnerability | `e5_vulns` | ~15 min |
| C6 | Table IV: TAs written in Rust are affected as well (Sec. VI) | `e6_rust` | ~10 min |
| C7 | Table V: only ~11 % of fuzzing iterations execute a double fetch (Sec. VIII-c) | `e7_reshaping` | ~1 min |
| C8 | Figures 4 and 5: coverage of Exploration and of Fetch-Anchored Fuzzing | `e8_figures` | ~2 min |
| C9 | Section VII: a 140-LoC opt-in mitigation for OP-TEE, cheap when opted in | `e9_mitigation` | ~1 min |
| — | Table III: zero-copy shared memory on COTS phones (Section V) | **not reproducible without the phones**, see §6 | — |

## 3. Requirements

* Linux, x86-64, docker (with permission to use `/var/run/docker.sock`)
* ≥ 8 cores, ≥ 16 GB RAM recommended (the default scale assumes 12 cores)
* ~15 GB free disk space for the images, plus the ~3.5 GB of the repository
* Network access for the initial image build only

Nothing is installed on the host: `ae.sh` builds two images and runs everything
in containers.

* `ta_emu_ae` — the emulator (Qiling + Unicorn + AFL++), one container per TA
* `ta_emu_ae_ctl` — the controller (docker client, `eval/`, plotting stack),
  which starts the emulator containers as siblings through the docker socket

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
./ae.sh list           # all experiments
./ae.sh e5_vulns       # the central "reproduced" experiment (Table II)
./ae.sh all            # everything, scaled down, in order
./ae.sh report         # summary of everything that was run
```

The pipeline of Section III, run explicitly:

```sh
./ae.sh e1_exploration               # Stage 1: overlapped fetches -> snapshots
./ae.sh e2_faf --from exploration    # Stage 2: fuzz the second fetch -> crashes
./ae.sh e3_distillation --from faf   # Stage 3: keep the shared-memory crashes
./ae.sh e4_table1 --source ae        # Table I for the campaign you just ran
```

Results, tables (`.txt`, `.csv`, `.tex`) and figures (`.pdf`, `.png`) are
written to `ae/results/<experiment>/`.

## 5. Experiments

Each experiment prints its table and ends with an explicit list of checks.

### `e1_exploration` — Stage 1

Fuzzes each TA of `$AE_SUBSET` with `emulator/fuzz.sh` while tracing accesses to
the memref buffers, deduplicates the recordings (`eval/deduplicate.py`,
coverage mode), annotates the overlapped fetches (`eval/annotate_fetches.py`)
and reports how many snapshots each TA yields.

Working copies are created as `<tee>/harness/ae_e2_<name>` — the campaign data
shipped with the artifact is never modified.

```sh
./ae.sh e1_exploration                          # $AE_SUBSET, AE_EXPLORE_TIME each
AE_EXPLORE_TIME=1800 ./ae.sh e1_exploration     # longer budget
./ae.sh e1_exploration --harnesses all          # every TA the paper harnessed
./ae.sh e1_exploration --harnesses mitee/harness/88ce_fuzz qsee/harness/3d08_fuzz
```

`all` (also `AE_SUBSET=all`, and accepted by `e2_faf`/`e3_distillation`) selects
**27 harnesses covering the 30 TAs of Table I** — the three Kinibi TAs are fuzzed
through their Beanpod harnesses and count for both TEEs. E1 prints the resulting
TA count and an estimate of the wall clock before it starts, e.g. 27 harnesses at
one hour each with `AE_JOBS=10` is ~3 h of fuzzing plus deduplication.

### `e2_faf` — Stage 2

Restores each snapshot and fuzzes the value read at the second fetch
(`emulator/df_fuzz.sh`). `--from exploration` uses the snapshots produced by E1;
`--from campaign` (the default) uses the snapshots of the paper's campaign.

```sh
./ae.sh e2_faf --from exploration --time 900 --max-snapshots 6
```

The budget matters: with the paper's 900 s per snapshot, Fetch-Anchored Fuzzing
rediscovers the crashes of the SoterApp and Mlipay vulnerabilities from scratch;
with a much shorter budget a snapshot is restored and fuzzed but usually stays
crash-free (the paper found crashes in 330 of 17,232 snapshots). E3 therefore
asserts only that snapshots are restored and fuzzed, and reports the crashes it
finds.

### `e3_distillation` — Stage 3

Replays every crash with the crashing value already in place
(`emulator/df_validate.sh` via `eval/df_validate.py`) and reports which crashes
survive only *with* the race, i.e. which are real double-fetch vulnerabilities.
`--from faf` uses the crashes of E2, `--from campaign` those of the paper.

### `e4_table1` — Table I

Summarises a campaign with the artifact's own `statistics.sh` and prints it next
to the paper's Table I.

* `--source ae` — the campaign produced by E1-E3 in this evaluation.
* `--source campaign` (default) — the campaign data shipped with the artifact.
  This is an inventory of files on disk, not a re-run, so the AE budget does not
  influence it; §9 explains why some of its columns deviate from the paper.

`--annotate` recomputes the overlapped-fetch flags of all recordings first
(`eval/annotate_fetches.py --dirs both`).

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

E4 then uses that list for `# TAs` and checks every entry is present; until then
it counts the corpus and says so. `# TAs w/o Local Copy` needs no such list: it
is the set of TAs that have a harness, which already matches the paper (9/3/3/10/5).

### `e5_vulns` — Table II *(main experiment)*

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
./ae.sh e5_vulns                        # PoCs against the emulator, until they crash
./ae.sh e5_vulns --attempts 20          # give up after 20 runs of a PoC
./ae.sh e5_vulns --replay               # instead replay the crashing input that
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

### `e6_rust` — Table IV

Runs Exploration on the OP-TEE Rust TAs in `optee/harness/` and counts the
detected double fetches per TA.

### `e7_reshaping` — Table V

Compares the total number of Exploration executions with the number of
executions that actually reach a double fetch (`eval/reshaping_cmp.py
--print-numbers`), i.e. the share of the budget a reshaping-based fuzzer would
waste.

### `e8_figures` — Figures 4 and 5

Figure 4 accumulates the drcov coverage of the Exploration queue seeds
(`<harness>/out/cov`) over campaign time and normalises it by the basic blocks
reachable from `TA_InvokeCommandEntryPoint` in the TA's CFG
(`<tee>/tas/bbs/bb_*.json`, produced by `ghidra/analyze-bbs.sh`).
Figure 5 splits the basic blocks discovered per snapshot during Fetch-Anchored
Fuzzing into the four categories of the paper; it needs coverage for the FAF
queue, which `--regen-faf-cov` produces by replaying the queue entries.

### Helper

`ae/experiments/_probe_vulns.py` replays *every* replayable crash of a set of
harnesses and prints the observed crash type and the Distillation verdict. It is
how `ae/data/vulns.json` (the crash pinned to each Table II vulnerability) was
put together, and it is the tool to use after a fresh campaign.

### `e9_mitigation` — Section VII

Reports the size of `optee_shm_patch/optee_os.patch` (paper: 140 LoC), applies
it to an OP-TEE tree if `$OPTEE_DIR` points at one, and regenerates the
performance tables and the overhead plot from the benchmark measurements
(`optee_shm_patch/benchmark/harness/analyze.py`). Re-running the benchmark
itself needs a built OP-TEE QEMU-v8 tree, which is not part of the artifact;
`optee_shm_patch/benchmark/README.md` documents the procedure.

## 6. What cannot be reproduced by a reviewer

* **Table III / Section V (on-device)** — reproducing the TOCTTOU
  vulnerabilities on real phones needs the twelve rooted devices of Table III
  and vendor firmware. The proof-of-concept apps are shipped in
  `<tee>/pocs/<vuln>/` (build with `ANDROID_NDK=… make phone`, deploy with
  `adb push`), and Listing 2 of the paper shows the racing app.
* **The full campaign** — the paper's numbers come from 5 × 24 h of Exploration
  per TA and 15 min of Fetch-Anchored Fuzzing for each of 17,232 snapshots
  (4,330 CPU-hours). `AE_SCALE=paper` runs those budgets.

## 7. Scaling

`ae/config.env` (all values can be overridden in the environment):

| variable | default | paper |
|---|---|---|
| `AE_JOBS` | cores − 2 | 56 |
| `AE_EXPLORE_TIME` | 300 s per TA | 86,400 s |
| `AE_EXPLORE_REPS` | 1 | 5 |
| `AE_FAF_TIME` | 900 s per snapshot | 900 s |
| `AE_FAF_MAX_SNAPSHOTS` | 6 per TA | all |
| `AE_DEDUP_LIMIT` | 150 recordings per TA | all (0 = no limit) |
| `AE_SUBSET` | the five TAs behind Table II | `all` (30 TAs) |

`AE_SCALE=paper ./ae.sh all` restores the paper's budgets (weeks of CPU time).

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

`e4_table1 --source campaign` compares the campaign state in this repository against Table I and
prints every deviation. The tree that is shipped is a **pruned** state of the
campaign: `eval/deduplicate.py --enable-del` removes redundant Exploration seeds
(and their `.meta` records) once a campaign is finished, and the recordings of
some TAs were not kept. As a consequence the raw `# Overl. Fetches` column and
the number of TAs with overlapped fetches are lower than in the paper. Re-running
`e1_exploration` (followed by `e2_faf`, `e3_distillation` and
`e4_table1 --source ae`) produces fresh, self-consistent numbers for the TAs it
covers.

A concrete symptom: `# Overl. Fetches merged` can exceed `# Overl. Fetches` on
the shipped tree, because `df_fuzz/<seed>_<reghash>/` directories survive while
the recordings they were derived from were deleted (`mitee/harness/86f6_fuzz`
alone has 13,149 snapshot directories and no `.meta` files left). E4 lists every
harness in that state instead of silently printing the impossible ratio.
