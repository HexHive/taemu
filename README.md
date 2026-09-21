# GP TA Emulator 

## Setup

```
./build-docker.sh
```

## Run

```
./run-docker.sh
```

to run the `0811...` beanpod TA:

```
./run.sh ../beanpod/tas/08110000000000000000000000000000.ta
```

to run the `0811...` beanpod TA with the gdb stub:

```
./gdb.sh ../beanpod/tas/08110000000000000000000000000000.ta
```

## Emulation setup

### Run POC against emulator

Start the emulator:
```
make build
make run
```

Compile and run your poc against the emulator:
```
cd template
make docker
```

### Run POC against emulator with gdb

Run emulator with gdb:
```
make gdb
```

(you need to run the poc so the emulator spawns the gdb server)
```
cd template
make docker
```

```
gdb-multiarch -ex "target remote localhost:9999"
```

*qiling's gdb server is a bit broken, stepping etc will break often* 
*blata24 gef works (normal gef doesn't)*

## Run against actual phone

compile for phone:
```
wget https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
unzip android-ndk-r27c-linux.zip
ANDROID_NDK=$(pwd)/android-ndk-r27c make phone
```

go to admin desk and ask for keyinstall phone

interact with phone:
```
#(1) install adb
adb push poc /data/local/tmp
adb shell /data/local/tmp/poc
```

## Fuzzing

setup a folder with the following file in  `<tee>/harness/`

`harness.py`: the callback to place fuzzing input, see `beanpod/harness/0811_test/harness.py` for an example.
`in`: (optional) the input seed directory
symbolic link to the target ta `ln -s ../../tas/<target-ta>.ta .`
symbolic link to the target ta json `ln -s ../../tas/<target-ta>.json .`

afterwards run the fuzzer with: 

`./fuzz.sh <tee>/harness/<harness-folder>`

(fuzz and generate a crash if an api is not implemented:)

`TAEMU_CRASH_NOTIMPL=1 ./fuzz.sh <tee>/harness/<harness-folder>`

replay seeds with:

`./fuzz.sh <tee>/harness/<harness-folder> <path-to-seed>`

for gdb:
`./fuzz.sh <tee>/harness/<harness-folder> <path-to-seed> -g`

# Double-Fetch Fuzzing (ScHMuzz)

Finding an attacker-triggerable double fetch runs in three stages, named as in
the paper: **Exploration**, **Fetch-Anchored Fuzzing**, and **Distillation**.
Every command below is run inside the emulator container (`./run-docker.sh`),
from `/srv/emulator`.

Exploration needs the Redis-backed recorder: it is what observes overlapped
fetches and writes the snapshots the later stages consume. `run-docker.sh`
offers to start the Redis container -- say yes. Setting `TAEMU_DISABLE_REDIS=1`
switches double-fetch detection off entirely, so leave it unset for Exploration.

## Stage 1: Exploration

Fuzz the TA with its harness. Alongside normal coverage-guided fuzzing, the
recorder watches reads of the input memref buffers and snapshots any seed whose
execution fetches the same shared-memory address more than once.

```
./fuzz.sh ../<tee>/harness/<harness-folder>
```

Seeds that produced an overlapped fetch land in:

```
<harness-folder>/in/suspicious_inputs/<seed>        # the seed itself
<harness-folder>/in/suspicious_inputs/<seed>.meta   # the recorded fetches
<harness-folder>/record_meta/                       # per-run recorder metadata
```

Each `.meta` holds a `records` list, one entry per fetch, with the faulting
`PC`, the shared-memory `addr`, and a `reg_hash` identifying that fetch site.
Every entry marked `"is_second_fetch": true` is an overlapped re-fetch, and
each one is a separate snapshot with its own `reg_hash` to anchor stage 2 on --
a single seed commonly yields several. Contiguous second-fetch accesses are
merged into one logical overlapped fetch before this point.

```
python3 -c 'import json,sys; print([(r["regs"]["reg_hash"], hex(r["addr"])) \
  for r in json.load(open(sys.argv[1]))["records"] if r["is_second_fetch"]])' \
  ../<tee>/harness/<h>/in/suspicious_inputs/<seed>.meta
```

The paper fuzzes each TA 5x24h here and merges the resulting snapshots before
moving on.

## Merging snapshots (deduplication)

Exploration rediscovers the same double fetch on many seeds, so the raw
snapshot set is heavily redundant -- the paper merges 913,249 overlapped
fetches down to 17,232 snapshots before stage 2. Deduplicate before spending
Fetch-Anchored Fuzzing time on copies.

Unlike the rest of the pipeline, `eval/deduplicate.py` runs on the **host**: it
starts and drives the containers itself.

```
python3 eval/deduplicate.py --mode control_flow                # report only
python3 eval/deduplicate.py --mode control_flow --enable-del   # actually prune
```

Two modes:

* `control_flow` (default) hashes each `.meta`'s `records`. Pure metadata, no
  emulation, fast. `--non-conservative` hashes only the `regs` of each record
  rather than the whole record, merging more aggressively.
* `coverage` replays every snapshot through `replay_sus.sh` across
  `--num-replay-containers` emulator containers (default 20), hashes the sorted
  basic-block set from the drcov output, and drops snapshots whose coverage is
  identical. Needs Redis and the emulator containers; the script offers to
  start them.

Without `--enable-del` nothing is removed, it only reports duplicate hashes.
`--tee <name>` restricts the sweep, `--per-harness-limit N` samples per
harness, and `harness_dev/` is always skipped. Deleting a duplicate removes
both the seed and its `.meta`.

Two things that will bite you:

* `deduplicate.py` imports `tqdm`, which is in neither
  `emulator/requirements.txt` nor the image, so it fails to import in the
  container. Install it into whatever environment you run the eval scripts
  from (`aiofiles` is already in `requirements.txt`).
* `fuzz.sh` writes `in/suspicious_inputs/` as root, but `deduplicate.py` runs
  on the host as you, so `--enable-del` aborts with `PermissionError`. Take
  ownership of the harness `in/` dir first:

```
docker compose run --rm -T --workdir /srv emulator \
    chown -R $(id -u):$(id -g) /srv/<tee>/harness/<h>/in
```

## Stage 2: Fetch-Anchored Fuzzing

Restore the snapshot and fuzz only the value returned by the second fetch,
leaving the rest of the input fixed. This is what turns a benign overlapped
fetch into a memory corruption.

```
./df_fuzz.sh ../<tee>/harness/<h> \
             ../<tee>/harness/<h>/in/suspicious_inputs/<seed> \
             <reg_hash>
```

Results go to `<harness-folder>/df_fuzz/<seed>_<reg_hash>/{in,out}`. Set
`FUZZTIME=<seconds>` to time-box the run; the paper uses 15 minutes per
snapshot, which is enough to either corrupt memory or saturate coverage.

Replay one of its crashes (append the crash file as a 4th argument):

```
./df_fuzz.sh ../<tee>/harness/<h> <seed> <reg_hash> \
             <harness>/df_fuzz/<seed>_<reg_hash>/out/default/crashes/<id>
```

`./df_replay_debug.sh` takes the same arguments and replays verbosely (`-v`),
which is what you want when triaging.

## Stage 3: Distillation

Decide whether a stage-2 crash is genuinely reachable by an attacker who only
controls shared memory, or is an artifact of the injected fetch value. The
crash is replayed from program start using the original Exploration seed, with
the stage-2 crashing input injected into the shared-memory region before
`TA_InvokeCommandEntryPoint`, and no further shared-memory modification.

```
./df_validate.sh ../<tee>/harness/<h> \
                 ../<tee>/harness/<h>/in/suspicious_inputs/<seed> \
                 <reg_hash> \
                 <harness>/df_fuzz/<seed>_<reg_hash>/out/default/crashes/<id>
```

If the crash reproduces under these conditions it is attacker-triggerable; if
not, it depended on a value the attacker cannot actually control.

## Sanity check

A known-good double fetch, useful for checking the pipeline end to end:

```
./fuzz.sh ../mitee/harness/377e_double_fetch_stackov/
# -> the .meta's second entry should be the relevant df

AFL_DEBUG=1 ./df_fuzz.sh ../mitee/harness/377e_double_fetch_stackov/ \
  ../mitee/harness/377e_double_fetch_stackov/in/suspicious_inputs/run\:id\:d3b07384d113edec49eaa6238ad5ff00 \
  205374383998289612021010690897642464208
# different sizes for memmove should be correct
```
