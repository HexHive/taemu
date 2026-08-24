# Campaign evaluation

Post-processing of a fuzzing campaign. These run in the **controller**
container (`ta_emu_ae_ctl`), which has matplotlib and the docker client; they
start emulator containers as siblings when they need to replay something.
`ae/experiments/stage_*.py` call them, so a reviewer never invokes them
directly.

| file | used by | what it does |
|---|---|---|
| `deduplicate.py` | Stage 1 | replays every recorded Exploration input (`emulator/replay_sus.sh`) and drops the ones whose coverage adds nothing. `--enable-del` also deletes the redundant recordings |
| `annotate_fetches.py` | Stage 1, Stage 4 | marks every read that revisits an already-read range of a memref buffer, i.e. turns recordings into *overlapped fetches*. Deterministic and idempotent |
| `df_validate.py` | Stage 3 | drives `emulator/df_validate.sh` over every crash, in parallel, and records the Distillation verdict |
| `taemu_env.py` | all of them | one place for "where is the repository, what is the emulator image called, is redis up" — driven by `TAEMU_ROOT` / `TAEMU_IMAGE` |
| `graphs/` | Stage 5 | Figures 4 and 5; see `graphs/README.md` |

Directories these produce (`bbs_out/`, `campaign_out/`, `fuzz_graphs/`) are not
in the repository and are listed in `.gitignore`.
