# Oversharing: Exposing Double Fetch Vulnerabilities in Trusted Applications

Artifact for the NDSS 2027 paper. It contains **ScHMuzz** (the three-stage
fuzzer: Exploration, Fetch-Anchored Fuzzing, Distillation), the TA corpus of
the ecosystem-wide study, the proof-of-concept apps for the six discovered
vulnerabilities, and the opt-in shared-memory mitigation for OP-TEE.

Every experiment runs inside docker, sizes itself to the machine it runs on,
and writes the corresponding table or figure of the paper to `ae/results/`.

```sh
cd ae
./ae.sh setup      # build the docker images and start redis (~20 min)
./ae.sh list       # the experiments and which claim each one checks
./ae.sh all        # run everything, scaled down (tables + figures in ae/results/)
```

---

## 1. What is in this repository

**Everything in this repository is part of the artifact.** Nothing here is
left over from a previous run: a fresh checkout contains no experiment output
at all. Every path that an experiment *creates* is listed in §1.2 and in
`.gitignore`, and `./ae.sh clean` removes exactly those paths and nothing else.

### 1.1 Directory map

| path | what it is |
|---|---|
| `ae/` | **the artifact-evaluation harness** — `ae.sh`, the experiment drivers, the reference numbers of the paper's tables, the prebuilt on-device PoCs |
| `emulator/` | **ScHMuzz**, built on Qiling/Unicorn + AFL++: emulates GlobalPlatform TAs, records shared-memory accesses (Exploration), fuzzes the value of a second fetch from a restored snapshot (Fetch-Anchored Fuzzing) and validates crashes (Distillation) |
| `eval/` | deduplication, annotation and plotting of a campaign; `eval/graphs/` produces Figures 4 and 5 |
| `ghidra/` | headless Ghidra scripts that produce the per-TA basic-block CFGs in `<tee>/tas/bbs/`, which Figure 4 normalises by |
| `optee_shm_patch/` | the opt-in shared-memory mitigation for OP-TEE (Section VII), as patches against `optee_os` and `optee_examples` |
| `appendix/` | LaTeX source of the artifact appendix submitted with the paper |
| `statistics.sh` | counts the on-disk state of a campaign; this is what produces Table I |
| `Dockerfile`, `.dockerignore` | the emulator image (`ta_emu_ae`); `ae/Dockerfile` builds the controller image on top of it |
| `docker-compose.redis.yml` | the redis container the recorder streams shared-memory accesses to |
| `unicornafl.py` | drop-in replacement for the AFL++ unicornafl python binding, copied into the image |
| `LICENSE`, `NOTICE` | MIT for our code; `NOTICE` lists the third-party material it does **not** cover (§10) |

and one directory per TEE — `beanpod/`, `mitee/`, `qsee/`, `teegris/` for the
five TEEs of Table I, `optee/` for the Rust TAs of Table IV:

| path | what it is |
|---|---|
| `<tee>/README.md` | the firmware image the TAs were extracted from, and the phone it came off |
| `<tee>/tas/*.ta` | the TA corpus: exactly the 66 GlobalPlatform TAs of Table I (`optee/tas` holds the Rust TAs of Table IV). Proprietary vendor binaries — see `NOTICE` |
| `<tee>/tas/*.json` | entry-point offsets the emulator needs to invoke a TA, recovered with `ghidra/` |
| `<tee>/tas/bbs/bb_*.ta.json` | the basic-block CFG of a TA, produced by `ghidra/analyze-bbs.sh`. Figure 4 normalises coverage by the blocks reachable from `TA_InvokeCommandEntryPoint` |
| `<tee>/harness/<name>/` | one fuzzing harness per TA that operates on shared memory: `harness.py` (the callback that places the fuzzer's input into the memref parameters) and a symlink to the TA it targets. 27 harnesses cover the 30 TAs of Table I |
| `<tee>/pocs/<name>/` | the nine proof-of-concept clients (Section V). Six reproduce Table II against the emulator; three more are the zero-copy probes of Table III. Built with `-DEMULATE` they talk to the emulator, otherwise to a phone |

Kinibi TAs run on the Beanpod runtime, so their binaries and harnesses live
under `beanpod/`; they count for both TEEs in Table I. That is why there are
four TEE directories for the five TEEs of the table.

### 1.2 What a run produces

None of this is in the repository; all of it is recreated by `./ae.sh all` and
removed by `./ae.sh clean`.

| path | written by |
|---|---|
| `ae/results/<experiment>/` | every experiment — tables (`.txt`, `.csv`, `.tex`), figures (`.pdf`, `.png`), `result.json`, `notes.log` |
| `<tee>/harness/ae_e1_<name>/` | Exploration, as a working copy of `<tee>/harness/<name>/`. The harnesses of the artifact are never written to |
| `<tee>/harness/*/in/` | recorded shared-memory accesses and the AFL seeds that produced them |
| `<tee>/harness/*/out/` | AFL++ state and drcov coverage |
| `<tee>/harness/*/df_fuzz/` | one directory per snapshot handed to Fetch-Anchored Fuzzing, with its own AFL++ state and crashes |
| `<tee>/harness/*/record_meta/`, `logs/` | the recorder's bookkeeping |
| `emulator/rootfs/*.ta`, `*.json` | `fuzz.sh` copies the TA under test here before running it. The loader stubs already in `emulator/rootfs/` (`ld.so.1`, `lib64/`, `rom/`) *are* part of the artifact |
| `<tee>/pocs/*/{obj,libs,poc}` | compiling a PoC |
| `**/__pycache__/` | python |

---

## 2. Claims and where they are checked

The first experiment is the pipeline of Section III and runs its stages in
order: Exploration produces the snapshots that Fetch-Anchored Fuzzing needs,
which produces the crashes that Distillation filters, and Table I is the
summary of that campaign.

Runtimes are for the default budgets on a commodity desktop (8 cores, 16 GB
RAM, `AE_JOBS=6`); they shrink on a bigger machine, see §7.

| # | Paper claim | Experiment | Runtime |
|---|---|---|---|
| C1–C4, C8 | The pipeline of Section III: Exploration finds overlapped fetches in binary-only TAs (III-A), Fetch-Anchored Fuzzing turns them into crashes (III-B), Distillation keeps the ones that need the race (III-C) — summarised in **Table I** and **Figures 4 and 5** | `e1_automatic_df_detection` | ~8 h |
| C5 | **Table II: six 0-day TOCTTOU vulnerabilities in five TAs**, reproduced by racing the TA with the PoC of each vulnerability | `e2_vulns` | ~15 min |
| C6 | Table IV: TAs written in Rust are affected as well (Section VI) | `e3_rust` | ~40 min |
| C9 | Section VII: a 140-LoC opt-in mitigation for OP-TEE that closes the double fetch | **not an experiment**, see §6 | — |
| — | Table III: zero-copy shared memory on COTS phones (Section V) | **not reproducible without the phones**, see §6 | — |

`./ae.sh all` runs all of it, in this order, in about 9 h. `AE_SCALE=quick`
cuts it to roughly an hour on five TAs when you only want to see the machinery
work.

---

## 3. Requirements

On the host, only docker and bash:

| requirement | why |
|---|---|
| Linux, x86-64 | the emulator images are amd64 |
| Docker Engine >= 23 with BuildKit | the Dockerfiles use `RUN --mount=type=cache` and `COPY --link` |
| `docker compose` v2 plugin | starts the redis container the recorder streams to; `docker-compose` v1 works too |
| membership in the `docker` group | the controller is given `/var/run/docker.sock` to start emulator containers |
| bash, coreutils (`nproc`, `awk`, `/proc/meminfo`) | `ae.sh` and the pool sizing |
| network access during `./ae.sh setup` | pulls `ubuntu:jammy`, `aflplusplus/aflplusplus:v4.32c`, `redis:7-alpine`, PyPI, `download.docker.com` |
| ~8 GB disk | 3.8 GB images, 320 MB repository, ~300 MB produced by a run |
| >= 8 cores, >= 16 GB RAM | one emulator per core, ~85 MB each (see §7) |

No Python, matplotlib or Ghidra on the host — everything runs in the two images
that `./ae.sh setup` builds:

* `ta_emu_ae` (from `./Dockerfile`): Ubuntu 22.04, Python 3.10.12, Qiling
  pinned at `56dd77b` plus `emulator/qiling.diff`, Unicorn, AFL++ 4.32c with
  the unicornafl bindings, pwntools 4.15.0 and the rest of
  `emulator/requirements.txt`
* `ta_emu_ae_ctl` (from `ae/Dockerfile`): the same plus the docker client and
  compose plugin, matplotlib 3.10.8, numpy, networkx, tqdm, aiofiles,
  cachetools, loguru, tenacity, pandas, jq, bc, pv
* `redis:7-alpine`, started by `docker-compose.redis.yml`

Optional, for the two parts that are not self-contained:

* a rooted Android phone and `adb` — to run the PoCs on a device (Section V,
  `ae/ae_ondevice.sh`). The PoCs ship prebuilt for arm64 in
  `ae/prebuilt/ondevice/`, so the Android NDK is only needed to rebuild them.
  Without a phone the artifact runs them against the emulator instead.
* Ghidra (`ghidra/`) — only needed to regenerate the per-TA CFGs used by
  Figure 4; they ship in `<tee>/tas/bbs/`.

---

## 4. Getting started (~20 min)

```sh
cd ae
./ae.sh setup          # builds both images and starts redis
```

Nothing beyond docker has to be installed: redis is the `redis:7-alpine`
container of `../docker-compose.redis.yml`, not a host service. `setup` starts
it with compose and, should compose be unusable, falls back to a plain
`docker run`, so a missing compose plugin is not fatal. If it still stops at
`could not start redis`, run the command it prints by hand — the error is
docker's, and the two usual ones are a compose plugin that is missing (Ubuntu's
`docker.io` package does not pull it in) and a port 6379 already taken by a
host redis:

```sh
docker compose -f ../docker-compose.redis.yml up -d redis   # the failing command
docker compose version                             # must print v2.x
sudo apt-get install docker-compose-plugin         # if it does not
ss -ltnp | grep 6379                               # who else holds the port
AE_REDIS_PORT=6380 ./ae.sh setup                   # or move ours out of the way
```

On **WSL** we recommend Docker Engine installed *inside* the distribution
(`docs.docker.com/engine/install/ubuntu`) over Docker Desktop's WSL
integration: the experiments run their containers with `--network host` and
reach redis over the loopback, which Docker Desktop only supports with its
host-networking feature enabled. `sudo service docker start` after every WSL
restart, since WSL has no systemd by default. Note too that a Windows service
holding port 6379 blocks the publish from inside WSL — `AE_REDIS_PORT=6380`
moves ours out of the way.

`setup` ends by opening a socket to redis *from inside an emulator container*,
not just from the host, and says so:

```
[ok] redis is reachable from the emulator containers
```

That is the property the experiments depend on, and the one Docker Desktop's
WSL integration does not give you by default. If the check fails, `setup` stops
there rather than letting an experiment run for an hour and fail at its first
memory record.

```sh
./ae.sh list                 # all experiments, and the budgets picked for this machine
./ae.sh e2_vulns             # the central "reproduced" experiment (Table II), ~15 min
./ae.sh all                  # everything, in order, all 30 TAs, ~9 h
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

---

## 5. Experiments

Each experiment prints its table and ends with an explicit list of checks —
`[ok]` or `[--]` per check, nothing else. Anything advisory (a TA whose data is
pruned, harnesses excluded from a count, a TA whose data is missing) is not
printed but recorded in `ae/results/<experiment>/notes.log` and in the `notes`
field of `result.json`, next to the numbers it qualifies.

### `e1_automatic_df_detection` — Section III, Table I, Figures 4 and 5

The pipeline of the paper, as one experiment, because each stage consumes what
the previous one produced. `--only <stage>...` runs a subset and `--from
<stage>` continues from one; the stage scripts are `ae/experiments/stage_*.py`
and each writes its own tables, logs and `result.json` to
`ae/results/e1_automatic_df_detection/<n>_<stage>/`.

#### Stage 1 — Exploration

Fuzzes each TA of `$AE_SUBSET` with `emulator/fuzz.sh` while tracing accesses
to the memref buffers, deduplicates the recordings (`eval/deduplicate.py`,
coverage mode), annotates the overlapped fetches (`eval/annotate_fetches.py`)
and reports how many snapshots each TA yields.

Working copies are created as `<tee>/harness/ae_e1_<name>` — the harnesses of
the artifact are never written to.

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
rediscovers the crashes of the SoterApp and Mlipay vulnerabilities from
scratch; with a much shorter budget a snapshot is restored and fuzzed but
usually stays crash-free (the paper found crashes in 330 of 17,232 snapshots).
The stage therefore asserts only that snapshots are restored and fuzzed, and
reports the crashes it finds.

#### Stage 3 — Distillation

Replays every crash with the crashing value already in place
(`emulator/df_validate.sh` via `eval/df_validate.py`) and reports which crashes
survive only *with* the race, i.e. which are real double-fetch vulnerabilities.

#### Stage 4 — Table I

Summarises the campaign the three stages just produced, with the artifact's own
`statistics.sh`, and prints it next to the paper's Table I.

`# TAs` and `# TAs w/o Local Copy` are properties of the dataset, not of the
run: they come from `ae/data/dataset.json`, which lists the 66
GlobalPlatform-compliant TAs of Section IV-A and the 30 of them that operate
directly on shared memory. The stage checks that every listed TA is present in
`<tee>/tas` (it is: 33 TEEGris, 4 QSEE, 6 Kinibi, 12 MiTEE, 11 Beanpod) and
that the harnesses present match the 30 shm TAs. The remaining columns are
measured from the campaign.

`ae/experiments/stage_table1.py --source campaign` runs the same summary over
harnesses fuzzed in place rather than over the `ae_e1_*` working copies. On an
untouched checkout that finds nothing, because no campaign data ships with the
artifact.

#### Stage 5 — Figures 4 and 5

Figure 4 accumulates the drcov coverage of the Exploration queue seeds
(`<harness>/out/cov`) over campaign time and normalises it by the basic blocks
reachable from `TA_InvokeCommandEntryPoint` in the TA's CFG
(`<tee>/tas/bbs/bb_*.json`, produced by `ghidra/analyze-bbs.sh`).
Figure 5 splits the basic blocks discovered per snapshot during Fetch-Anchored
Fuzzing into the four categories of the paper; it needs coverage for the FAF
queue, which the stage produces by replaying the queue entries.

### `e2_vulns` — Table II *(main experiment)*

Runs the **proof-of-concept client of each vulnerability against the
emulator**. Built with `-DEMULATE` the PoC does not talk to a TEE driver but to
the emulator, which serves the GlobalPlatform client protocol on TCP port 1337
and backs every `memref` with real System V shared memory
(`emulator/emulate/ta_mgr.py:start_interactive`, started by
`emulator/run.sh`). The PoC opens a session, spawns the thread that keeps
modifying the shared buffer and invokes the vulnerable command — it races the
TA exactly as it does on a phone (Listing 2). When it wins the race the TA
corrupts memory and the emulator reports the violation; that is what the
experiment checks.

Winning the race is probabilistic, so each PoC is run over and over until the
TA crashes, with a fresh emulator per run so that no state from a previous one
can be mistaken for a crash. `--attempts N` caps that if you want the
experiment to end even when a PoC never hits.

```sh
./ae.sh e2_vulns                        # PoCs against the emulator, until they crash
./ae.sh e2_vulns --attempts 20          # give up after 20 runs of a PoC
./ae.sh e2_vulns --replay               # instead replay the crashing input that
                                        # Fetch-Anchored Fuzzing found (needs a
                                        # campaign you produced yourself, see §9)
```

The "reproduced on device" column is quoted from the paper (Section V) because
it needs the rooted phones of Table III.

All six reproduce this way, in each case by racing the very field that
Exploration recorded as double-fetched — for FbSkmR and ifaa-key, for instance,
the offset the PoC writes is exactly the offset of the recorded second fetch.
How many runs a PoC needs varies from one execution of the experiment to the
next (1–13 in ours); the table reports the number it took this time.

The six PoCs and the TAs they race are pinned in `ae/data/vulns.json`.

### `e3_rust` — Table IV

Runs Exploration on the OP-TEE Rust TAs in `optee/harness/` and counts the
detected double fetches per TA. These TAs are open source; `NOTICE` names the
upstream projects.

### Helper

`ae/experiments/_probe_vulns.py` replays *every* replayable crash of a set of
harnesses and prints the observed crash type and the Distillation verdict. It
is how `ae/data/vulns.json` was put together, and it is the tool to use after a
fresh campaign.

---

## 6. What cannot be reproduced by a reviewer

* **Table III / Section V (on-device)** — reproducing the TOCTTOU
  vulnerabilities on real phones needs the twelve rooted devices of Table III
  and their vendor firmware. `ae/ae_ondevice.sh` does as much of it as the
  hardware at hand allows: for every phone connected over adb it identifies the
  TEE, builds the proof-of-concept clients that target it (`<tee>/pocs/<vuln>/`),
  runs them and classifies the outcome as `no TA` (that TA is not installed on
  this phone), `reached` (the TA processed a memref that a second thread
  rewrote for the whole call) or `CRASHED` (the double fetch was exploited). It
  is the one part of the artifact that does *not* run in docker — it needs USB
  access to the phones. The PoCs are shipped prebuilt for arm64 in
  `ae/prebuilt/ondevice/`, so no Android NDK is needed:

  ```sh
  ae/ae_ondevice.sh                                       # every device
  ae/ae_ondevice.sh R58N349AKNY                           # one of them
  AE_ONDEVICE_RUNS=20 ae/ae_ondevice.sh                   # give up after 20

  # rebuild from source instead of using the shipped binaries
  AE_ONDEVICE_BUILD=1 ANDROID_NDK=~/opt/android-ndk-r26d ae/ae_ondevice.sh
  ```

  How a double fetch is *observed* differs per TEE, because it depends on what
  the TA makes visible — Appendix A of the paper works this out per TEE and the
  script implements exactly those signals:

  | TEE | PoC | signal |
  |---|---|---|
  | Kinibi | `beanpod/pocs/df1e_test` | the TA logs its first fetch (`cmd : 0x…`) and then the branch it took on the second one, and its log goes to the kernel log (Listing 7). `cmd : 0x1009` followed by `paytrigger_ta_get_hmackey_c` is only possible if the value changed in between |
  | QSEE | `qsee/pocs/a985_test` | the TA returns −5 when both fetches agree and −24 (`0xffffffe8`) only when they disagree (Listing 6) |
  | TEEGris | `teegris/pocs/s10_5345_SECFR` | a third thread watches the registered buffer; a change while `TEEC_InvokeCommand` is still blocked means the TA writes into normal-world memory. The paper establishes TEEGris from an on-device *crash* of a Table II TA instead — which needs a phone that ships that TA |

  It prints Table III, one line per phone; the per-run logs are in
  `ae/results/ondevice/`. On the three devices this was developed against:

  ```
  TEE       MODEL                    ZERO-COPY SHM
  -----------------------------------------------------
  Kinibi    TECNO Mobile LH8n        yes
  TEEGris   samsung SM-G973F         yes
  QSEE      OnePlus CPH2609          yes
  ```

  which is claim C5 for Kinibi, QSEE and TEEGris. Winning the race is
  probabilistic, so a PoC is retried until it lands; `AE_ONDEVICE_RUNS=<n>`
  caps that. A TA that is not installed is not retried. The Table II
  vulnerabilities need the phone to ship the vulnerable TA, which none of these
  three does. Listing 2 of the paper shows the racing app.

  Note that this depends on the exact handset, not just the TEE: a OnePlus
  CPH2621 running the same QSEE does not ship the `A985D3EB…` TA and reports
  `no TA`, while the CPH2609 above does.

* **The full campaign** — the paper's numbers come from 5 × 24 h of Exploration
  per TA and 15 min of Fetch-Anchored Fuzzing for each of 17,232 snapshots
  (4,330 CPU-hours). `AE_SCALE=paper` runs those budgets.

* **Section VII (the mitigation)** — not an experiment of this evaluation.
  `optee_shm_patch/` contains the mitigation itself and nothing else:
  `optee_os.patch` is the 140-line change to OP-TEE that makes shared-memory
  parameters opt-in copy-on-invoke, `optee_examples.patch` is the example TA
  that opts in, and `qemu_v8.xml` is the repo manifest of the OP-TEE QEMU-v8
  tree they apply to. Measuring the overhead needs that tree built (~31 GB,
  hours of compiling), which is why the section is documented rather than run.
  The benchmark harness is not part of this artifact.

---

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
`AE_SCALE=quick AE_SUBSET=all ./ae.sh e1_automatic_df_detection` does what it
says.

### Worker pools

Deduplication, annotation and the plotting code fan out over python worker
*processes* in the controller container. Each worker holds its own copy of what
it is handed — a coverage worker peaks around a gigabyte on a long campaign —
so the pools size themselves from the cores, the **cgroup memory limit** and
`MemAvailable`, and print what they picked. Nothing has to be set.

| variable | default |
|---|---|
| `AE_POOL_WORKERS` | unset — overrides every pool below |
| `AE_GRAPH_WORKERS` | auto — coverage parsing for Figures 4 and 5 |
| `AE_ANNOTATE_WORKERS` | auto — overlapped-fetch annotation |
| `AE_GRAPH_WORKER_MB` | 1024 — assumed peak per coverage worker |
| `AE_ANNOTATE_WORKER_MB` | 256 — assumed peak per annotation worker |

The cgroup limit matters: inside a container `/proc/meminfo` reports the
*host*, so a `docker --memory` cap — or the memory ceiling of Docker Desktop's
and WSL2's VM, which is typically well below the host's RAM — is invisible
there. If the controller has 2 GB, this is what you want reported, not the
host's 16 GB.

If a worker is killed anyway, the pool does **not** abort the run: it reports

```
[-] a coverage worker was killed (almost certainly out of memory: 2048 MB
    available for 8 workers). Finishing the remaining TAs in this process -
    slower, but it completes. Set AE_GRAPH_WORKERS to pin the pool size.
```

and finishes the remaining work serially. A run that previously died with

```
concurrent.futures.process.BrokenProcessPool: A process in the process pool
was terminated abruptly while the future was running or pending
```

now completes. If you see the warning, raising the memory available to docker
(Docker Desktop: Settings → Resources; WSL2: `memory=` in `.wslconfig`) will
make it fast again.

### What `./ae.sh all` costs

`AE_JOBS` is the only thing that decides wall clock: the pipeline runs the
harnesses in waves of `AE_JOBS` emulator containers, one core each. A commodity
desktop (8 cores, 16 GB RAM) gets `AE_JOBS=6` — `min(8-2, (16 GB - 2 GB)/512
MB)` — which is what the estimates below assume. Twelve cores get 10, and
E1/E2 finish in roughly half the time.

```sh
cd ae && ./ae.sh setup
nohup ./ae.sh all > ae_full_run.log 2>&1 &
```

| experiment | work | ~wall clock at `AE_JOBS=6` |
|---|---|---|
| `e1_automatic_df_detection` | | **~8 h** |
| &nbsp;&nbsp;stage 1, exploration | 27 harnesses × 30 min, 5 waves + dedup | ~3 h |
| &nbsp;&nbsp;stage 2, FAF | 27 × 4 snapshots × 15 min, 18 waves | ~4.5 h |
| &nbsp;&nbsp;stage 3, distillation | every crash found above | minutes |
| &nbsp;&nbsp;stage 4, Table I | Table I of that campaign | seconds |
| &nbsp;&nbsp;stage 5, figures | CFGs + coverage replays (~1 s each) | ~30 min |
| `e2_vulns` | six PoCs raced against the emulator | ~15 min |
| `e3_rust` | 5 Rust TAs × 30 min | ~40 min |
| **total** | | **~9 h** |

Two smaller options:

```sh
./ae.sh setup && ./ae.sh e2_vulns      # kick the tires, ~25 min, Table II
AE_SCALE=quick ./ae.sh all             # five TAs, short budgets, ~1 h
```

### What the scaled-down run does and does not show

Preserved in full:

* the **dataset** of Table I (all 66 GlobalPlatform TAs, all 30 that operate on
  shared memory, verified against `ae/data/dataset.json`),
* all **five TEEs**, each fuzzed with the same emulator and harnesses as the
  paper,
* the **three stages** end to end on every one of those 30 TAs, producing
  Table I of the run and Figures 4 and 5,
* **Table II**: all six vulnerabilities, reproduced by racing each TA with its
  proof-of-concept client — this is independent of the fuzzing budget,
* **Table IV**: which Rust TAs contain double fetches,
* **Section VII**: the mitigation and its size.

Reduced: the paper explores each TA for 5 × 24 h and fuzzes each of its 17,232
snapshots for 15 min (4,330 CPU-hours). The default run spends 30 min per TA
and fuzzes 4 snapshots per TA, so the absolute counts in Table I (overlapped
fetches, snapshots, crashes) are correspondingly smaller; the columns are
reported next to the paper's numbers. Raising `AE_EXPLORE_TIME`,
`AE_EXPLORE_REPS` and `AE_FAF_MAX_SNAPSHOTS` scales the run continuously up to
`AE_SCALE=paper`.

---

## 8. Cleaning up

```sh
./ae.sh clean                                    # everything a run produced (§1.2)
docker compose -f ../docker-compose.redis.yml --profile ui down
docker rmi ta_emu_ae ta_emu_ae_ctl
```

`./ae.sh clean` deletes `ae/results/`, the `ae_e1_*` working harnesses and the
fuzzing state (`in/`, `out/`, `df_fuzz/`, `record_meta/`, `logs/`) of every
harness. All of that is produced by running the experiments, so a cleaned tree
is byte-for-byte the tree you checked out, and `./ae.sh all` recreates it.

---

## 9. Notes on reproduced numbers

The campaign behind the paper's Table I is 4,330 CPU-hours of fuzzing and is
**not** shipped: what you measure is what your own run produced. Two
consequences:

* Table I's measured columns (`# TAs with Overl. Fetches`, `# Overl. Fetches`,
  `# Overl. Fetches merged`, `# Crashes`, `# Crashes Distilled`) scale with the
  budget you give the run and are printed next to the paper's numbers rather
  than compared to them. The dataset columns (`# TAs`, `# TAs w/o Local Copy`)
  do not: they come from `ae/data/dataset.json` and are checked against the
  corpus and the harnesses on disk.
* `./ae.sh e2_vulns --replay` and `stage_table1.py --source campaign` read
  campaign data, so they only do something after you have produced a campaign
  yourself. The default paths — racing the PoCs, and `--source ae` — need
  nothing but a checkout.

---

## 10. License

Our code is MIT-licensed (`LICENSE`), which explicitly permits use as a
baseline for comparison in other work.

`NOTICE` lists what the MIT license does **not** cover, and why: the TA
binaries under `<tee>/tas/` and the loader stubs under `emulator/rootfs/` are
proprietary vendor firmware, redistributed here only as the research subject of
the paper; the OP-TEE Rust TAs under `optee/tas/` carry their own upstream
open-source licenses; and `emulator/qiling.diff`, `optee_shm_patch/*.patch`,
`unicornafl.py` and `appendix/IEEEtran.cls` are patches against, or copies of,
third-party projects. Read `NOTICE` before redistributing any of it.
