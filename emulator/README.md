# ScHMuzz — the emulator

Emulates a GlobalPlatform trusted application on top of Qiling/Unicorn, serves
the `TEEC_*` client protocol, and drives AFL++ through the three stages of
Section III. Everything here runs **inside the `ta_emu_ae` container** with the
repository bind-mounted at `/srv` and `/srv/emulator` as the working
directory — `ae/ae.sh` does that for you; `./ae.sh shell` gives you a prompt in
it. Paths passed to these scripts are relative to `/srv/emulator`, e.g.
`../mitee/harness/88ce_fuzz`.

## Entry points

| script | stage | what it does |
|---|---|---|
| `fuzz.sh <harness> [<seed>]` | Exploration (III-A) | fuzzes the TA with AFL++ while recording every access to the memref buffers. With a seed argument it replays that one input instead |
| `replay_sus.sh <harness> <seed>` | Exploration | replays one recorded input; `eval/deduplicate.py` uses it to tell redundant recordings apart |
| `df_fuzz.sh <harness> <seed> <reg_hash> [<crash>]` | Fetch-Anchored Fuzzing (III-B) | restores the snapshot taken at the second fetch identified by `<reg_hash>` and fuzzes the value read there. With a crash argument it replays that crash |
| `df_validate.sh <harness> <seed> <reg_hash> <crash>` | Distillation (III-C) | replays a crash with the crashing value already in the buffer. If it still crashes, the race was not needed and the finding is dropped |
| `run.sh <ta>` | Table II | runs the TA in interactive mode: the emulator serves the GlobalPlatform client protocol on TCP 1337 and backs every memref with real System V shared memory, so a PoC client can race it |

## The emulator itself

    emulate/__main__.py         entry point: picks the loader for the TA
    emulate/ta_mgr.py           session and command dispatch, shared memory,
                                the interactive TEEC_* server used by e2_vulns
    emulate/gp_api.py           the GlobalPlatform Internal Core API
    emulate/gp/                 crypto, persistent/transient objects, properties
    emulate/{beanpod,mitee,optee,qsee,teegris,tc}_api.py
                                the per-TEE API surfaces beyond GlobalPlatform
    emulate/custom/             per-TEE loaders (TEEGris 32-bit, MiTEE, …)
    emulate/fuzz_record.py      the Exploration recorder
    emulate/redis_queue.py      streams records to the redis container
    emulate/asan.py             the heap/stack sanitiser that turns a memory
                                violation into a crash
    emulate/params.py           memref parameter handling
    emulate/files/              seed secure-storage objects some TAs expect
    rootfs/                     loader stubs the TAs link against; fuzz.sh
                                copies the TA under test in here at run time
    tee.ql                      Qiling machine profile (memory map, stack, …)
    qiling.diff                 patch applied to Qiling 56dd77b at image build
    requirements.txt            python dependencies of the emulator image

## Writing a harness

A harness is a directory under `<tee>/harness/` containing

* `harness.py` — the callback that places the fuzzer's input into the memref
  parameters of the invocation; see `mitee/harness/88ce_fuzz/harness.py`,
* a symlink to the target TA and to its `.json` entry-point offsets:
  `ln -s ../../tas/<uuid>.ta .` and the same for `.json`,
* optionally `in/` with initial seeds.

`TAEMU_CRASH_NOTIMPL=1 ./fuzz.sh <harness>` makes an unimplemented API call
raise a crash, which is how missing API surface is found while a new harness is
brought up.
