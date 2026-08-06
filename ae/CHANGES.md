# Changes made to the artifact while building the AE harness

Everything below is a fix to the *existing* code so that it runs outside the
authors' machine (`/root/TA_GP_emulator`, image `ta_emu`, run from the host as
root). No analysis logic was changed.

## Portability: repository path and image name

`TAEMU_ROOT` (repository path **on the docker host**) and `TAEMU_IMAGE` (emulator
image) are now honoured everywhere; both keep their old defaults.

* `eval/taemu_env.py` *(new)* — shared helper: repository root, image name,
  path translation for the emulator scripts, docker checks, container command.
* `eval/deduplicate.py`, `eval/annotate_fetches.py`, `eval/df_validate.py`,
  `eval/reshaping_cmp.py` — use it instead of the hard-coded
  `/root/TA_GP_emulator` prefix, the `.replace("/root/TA_GP_emulator/", "../")`
  path rewriting, and `docker run … -v .:/srv … ta_emu`.
* `swarm/src/config.rs` *(new)* + `swarm/src/main.rs`, `swarm/src/container.rs` —
  same for the orchestrator, which previously panicked
  (`expect("unexpected old_root for the path.")`) when the repository was not at
  `/root/TA_GP_emulator`. `--fuzz-script` now defaults to
  `<TAEMU_ROOT>/emulator/fuzz.sh`.

## Bugs

* `eval/deduplicate.py`, `eval/df_validate.py`, `eval/reshaping_cmp.py`:
  the check whether the `emu_N` worker containers are running searched the raw
  `docker ps` output for the substring `emu_`, which also matches the *image*
  names (`ta_emu`, `ta_emu_ae`). The workers were therefore never started and
  every replay failed with `No such container: emu_0` while the run still
  reported success. Now matches container names.
* `eval/deduplicate.py`: container start-up used `… &>/dev/null` through
  `/bin/sh` and swallowed all errors; failures are reported now.
* `eval/reshaping_cmp.py`: `docker rm -f $(docker ps -aq)` removed **every**
  container on the machine, not just the emulator workers. Restricted to
  `emu_*`.
* `eval/count_dfs.py`: iterated over the file *name* instead of the parsed
  metadata (`for entry in f["records"]`), so it crashed on every input; it also
  counted writes as overlapped fetches.
* `Dockerfile`: the gef installer (a debugging convenience) pulls a distro
  package that no longer exists, which broke the image build entirely. It is now
  best-effort.
* `.dockerignore` *(new)*: the build context was the whole repository (~3.5 GB)
  although the image only needs three files.

## Extensions

* `statistics.sh`: rewritten around the same data sources. It now
  * counts **unique TAs** instead of harness directories (several harnesses can
    target the same TA, e.g. `mitee/harness/377e_*`), which is what Table I
    reports,
  * fills in the `# Overl. Fetches` column that was `@TODO@`,
  * takes the repository root from `$TAEMU_ROOT`,
  * writes machine-readable output with `--json <file>`,
  * counts a harness' overlapped fetches over **both** recording directories
    (`in/suspicious_inputs` and `in/suspicious_inputs_replay`, deduplicated by
    seed) - counting only the first one under-reports every harness whose raw
    recordings were deleted by `deduplicate.py --enable-del`,
  * skips the `ae_*` scratch harnesses of an AE run unless `--include ae|all`
    is given, so an evaluation run cannot contaminate the campaign statistics,
  * runs in ~6 s instead of ~2 min (one `jq` invocation per directory).
* `eval/annotate_fetches.py`: new `--dirs {replay,raw,both}`. It only annotated
  `in/suspicious_inputs_replay/`, so the raw recordings in
  `in/suspicious_inputs/` kept `is_second_fetch: false` and could not be counted.
* `eval/deduplicate.py`: with `TAEMU_KEEP_REDIS=1` it no longer tears down the
  shared redis container when it exits (the AE driver owns it).

## The emulator's client-serving mode (used by the PoCs)

`emulator/run.sh` puts the emulator into interactive mode, where it serves the
GlobalPlatform client protocol on TCP 1337 so that a PoC built with `-DEMULATE`
can drive the TA. That path had rotted:

* `start_interactive()` called `breakpoint()` unconditionally, so the emulator
  stopped in pdb instead of serving anything (now behind `TAEMU_DEBUG=1`).
* After the TA returned, the output sync of `InvokeCommand()` advanced the read
  pointer by 8 bytes for a value parameter, while `setup_params()` writes 16 on
  64 bit (a `TEE_Param` is a union of `{a,b}` and `{buffer,size}`) - the
  condition was inverted. Every parameter after a value parameter was therefore
  read from the middle of the union, and any PoC with `VALUE + MEMREF` killed
  the emulator with `UC_ERR_READ_UNMAPPED` right after the invocation.
* The same loop unmapped whatever pointer the TA had left in
  `params[i].memref.buffer`; it now unmaps the mapping it created itself.
* When a client disconnected, the emulator shut down. It now waits for the next
  one, so a PoC can be retried without restarting the TA.

With those fixed, `ae/ae.sh e2_vulns` reproduces the Table II vulnerabilities by
racing the TA with the shipped PoCs - no campaign data involved.

## Data that was missing from the artifact

* `mitee/harness/377e_double_fetch_stackov/harness.py` — reconstructed from the
  `__pycache__` bytecode that was still present; without it neither the paper's
  "Double Fetch Sanity Check" nor the SoterApp vulnerability could be replayed.
* TA symlinks in `mitee/harness/377e_double_fetch_stackov/`,
  `optee/harness/1755_fuzz/` and `optee/harness/ff09_fuzz/`.
* Still missing (harness directories that contain campaign data but no
  `harness.py`/TA): `mitee/harness/{377e_stackov,377e_heapov,a374_param,f130_fuzz}`,
  `beanpod/harness/df1e_paramconf`. They are not needed for any experiment but
  make the statistics incomplete.

* `ae/tools/make_dataset_skeleton.py` *(new)* generates the candidate list for
  `ae/data/dataset.json`, the one piece of Table I that cannot be derived from
  the repository (which TA files are the 66 GlobalPlatform TAs). Everything else
  in Table I, including `# TAs w/o Local Copy`, is computed from the harnesses
  and the campaign state.

See `ae/README.md` §9 for the campaign-data gaps that affect Table I and Table V.

## Additions to the mitigation benchmark

The benchmark measured what the mitigation *costs* but never checked that it
*works*. It now does both:

* `optee_shm_patch/benchmark/bench_ta/bench_ta.c` gains two double-fetch probe
  commands (`TA_BENCH_CMD_DF_SHARED` = 3, opted into shared memory with
  `TEE_RegisterShm()`; `TA_BENCH_CMD_DF_COPIED` = 2, not opted in). Each reads
  the same word of `params[0]` twice per iteration, with a compute gap in
  between, and reports how often the two reads disagreed.
* `optee_shm_patch/benchmark/bench_host/df_main.c` *(new)* races that word from
  a second normal-world thread while the probe runs.
* `harness/driver.py --df` / `--df-only` runs the probe for the three
  configurations and writes `df_test.csv`; `write_results()` no longer
  truncates `results_v2.csv` when only the probe ran.
* `build.sh` derives its own paths instead of hardcoding the pre-rename
  repository location, and builds the probe host binary.

Measured (OP-TEE QEMU-v8, 100,000 double fetches per configuration): unpatched
37,369 raced successfully, opted-in 38,994, not opted-in **0**.

`ae/experiments/e5_mitigation.py` turns that into `double_fetch.{txt,csv,tex}`
and three checks; `--run-qemu` re-measures it instead of re-analysing
`optee_shm_patch/benchmark/results/df_test.csv`.

## Experiments

The three stages of Section III, Table I and the figures used to be five
separate experiments that only made sense run in one order, with the sequencing
(`--from exploration`, `--from faf`, `--source ae`) left to the caller. They are
now one experiment, `e1_automatic_df_detection`: one campaign, five stages, with
Table I and Figures 4 and 5 as its output.

Each stage is still its own script (`ae/experiments/stage_*.py`) and writes its
own tables, logs and `result.json` to
`ae/results/e1_automatic_df_detection/<n>_<stage>/`; `--only <stage>...` and
`--from <stage>` select which of them run, so a campaign can be continued or its
output re-rendered without refuzzing.

The remaining experiments shifted up: `e2_vulns`, `e3_rust`, `e4_reshaping`,
`e5_mitigation`. Claim IDs (C1-C9) are unchanged.

## Defaults

The scaled-down budgets were documented in the README but not the defaults, so
plain `./ae.sh all` ran five TAs for 5 minutes each and everything the artifact
appendix recommended had to be typed out by hand. The recommended settings are
now what you get with nothing set:

    AE_SUBSET=all (27 harnesses, the 30 TAs of Table I)
    AE_EXPLORE_TIME=1800   AE_EXPLORE_REPS=1
    AE_FAF_TIME=900        AE_FAF_MAX_SNAPSHOTS=4
    AE_DEDUP_LIMIT=0       AE_JOBS=auto

`AE_JOBS` already derived itself from the machine's cores and free memory at
every invocation; `./ae.sh list` now prints the whole resolved configuration,
so a reviewer can see what their machine picked before starting a run.

`AE_SCALE=quick` is the old default (five TAs, 5 min each, ~1 h in total) for
smoke-testing, and `AE_SCALE=paper` is unchanged. Both presets now yield to
anything set explicitly in the environment, so `AE_SCALE=quick AE_SUBSET=all`
does what it says instead of silently ignoring the subset.

## Output

Experiments no longer print `[!!]` advisories. An experiment's output is its
table and its checks; everything advisory — a TA whose campaign data is pruned,
a missing `$OPTEE_DIR`, harnesses excluded from a count, a column that differs
from the paper (which the table already shows) — is collected and written to
`ae/results/<experiment>/notes.log` and the `notes` field of `result.json`,
where it sits next to the numbers it qualifies instead of scrolling past.

Failures are unaffected: failed checks are still `[--]` on stdout, and
`./ae.sh all` still reports an experiment that exited non-zero.

## Run artifacts

A run used to dirty files that are tracked, so `git status` after an evaluation
was a mixture of the reviewer's own edits and output:

* `eval/graphs/main.py` wrote its figures to
  `eval/graphs/{org,df}_control_flow_graph.png` and their raw data to
  `eval/graphs/{rawinfo,df_rawinfo}/` — the paper's own figures and data, which
  a run therefore overwrote. It takes `--out_dir` now (default: unchanged, so a
  standalone run still writes in place) and the figures stage points it at
  `ae/results/e1_automatic_df_detection/5_figures/`.
* `.suspicious_inputs_cov_files.txt` (a list of absolute paths built by
  `eval/graphs/bk_suspicious_inputs_covs.sh`) and
  `emulator/emulate/files/*/*-,` (a secure-storage object a TA writes while it
  runs, named after a fuzzer-controlled object ID) were tracked. Both are now
  untracked and ignored.

With `ae/results/`, `*/harness/ae_e*_*` and the campaign state that was already
ignored, a full evaluation now leaves the working tree clean.

## Measuring the mitigation instead of reciting it

`e5_mitigation` used to need `optee_shm_patch/benchmark/build.sh` to have been
run by hand before `--run-qemu` would do anything, and `build.sh` in turn wanted
*two* full OP-TEE trees (~31 GB each) because the patched dev-kit was built from
a separate checkout. So in practice nobody ever re-measured anything.

The mitigation is entirely in libutee and the core image is unchanged, so one
tree is enough: `build.sh` now copies `$OPTEE_DIR/optee_os`, applies
`optee_os.patch` to the copy (always from a clean copy - re-applying a patch on
top of itself is how a half-patched libutee happens) and builds both dev-kits
from there. A dev-kit build takes 9 s.

`e5_mitigation` drives all of it and does so **by default whenever `$OPTEE_DIR`
is a built OP-TEE QEMU-v8 tree**: build both libutee variants, build the TAs and
the client binaries, boot OP-TEE under QEMU, run the double-fetch probe. 30 s
end to end. `--run-qemu` forces it and fails loudly if the tree is unusable;
`--no-run-qemu` forces the re-analysis; without a tree the shipped measurement
is re-analysed as before.

Two things had to move for this to run inside docker, as everything else does:

* `ae/ae.sh` bind-mounts `$OPTEE_DIR` into the controller at its own path. It
  never did, so the pre-existing `git apply --check` of the patch could not have
  worked from inside the container.
* the controller image gained `patch`, `pexpect` and the three shared libraries
  the OP-TEE tree's own `qemu-system-aarch64` links against (`libfdt1`,
  `libslirp0`, `libusb-1.0-0`). The aarch64 toolchain comes from the tree.

Also fixed: `git apply --check` ran in `$OPTEE_DIR` instead of
`$OPTEE_DIR/optee_os`, so the "patch applies" check failed on a tree the patch
applies to perfectly well.

Measured from a freshly patched tree, independent of the shipped CSV:
44,301 / 27,422 / **0** raced double fetches out of 100,000 for baseline /
opted-in / not-opted-in.
