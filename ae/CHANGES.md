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
